$ErrorActionPreference = "Stop"
Set-StrictMode -Version 2
$scriptPath = split-path -parent $MyInvocation.MyCommand.Definition
$localResourcesDir = "$scriptPath\UnattendResources"

. "$scriptPath\Interop.ps1"

Import-Module dism

function CheckIsAdmin()
{
    $wid = [System.Security.Principal.WindowsIdentity]::GetCurrent()
    $prp = new-object System.Security.Principal.WindowsPrincipal($wid)
    $adm = [System.Security.Principal.WindowsBuiltInRole]::Administrator
    $isAdmin = $prp.IsInRole($adm)
    if(!$isAdmin)
    {
        throw "This cmdlet must be executed in an elevated administrative shell"
    }
}

function Get-WimFileImagesInfo
{
    [CmdletBinding()]
    param
    (
        [parameter(Mandatory=$true, ValueFromPipeline=$true)]
        [string]$WimFilePath = "D:\Sources\install.wim"
    )
    PROCESS
    {
        $w = new-object WIMInterop.WimFile -ArgumentList $WimFilePath
        return $w.Images
    }
}

function CreateImageVirtualDisk($vhdPath, $size, $diskLayout)
{
    $v = [WIMInterop.VirtualDisk]::CreateVirtualDisk($vhdPath, $size)
    try
    {
        $v.AttachVirtualDisk()
        Start-Sleep -s 10  # wait until the drive has been mounted. Bad solution with sleep, but it works for me.
        $path = $v.GetVirtualDiskPhysicalPath()

        $m = $path -match "\\\\.\\PHYSICALDRIVE(?<num>\d+)"
        $diskNum = $matches["num"]
        $volumeLabel = "OS"

        if($diskLayout -eq "UEFI")
        {
            Initialize-Disk -Number $diskNum -PartitionStyle GPT
            # EFI partition
            $systemPart = New-Partition -DiskNumber $diskNum -Size 200MB -GptType '{c12a7328-f81f-11d2-ba4b-00a0c93ec93b}' -AssignDriveLetter
            & format.com "$($systemPart.DriveLetter):" /FS:FAT32 /Q /Y | Out-Null
            if($LASTEXITCODE) { throw "format failed" }
            # MSR partition
            $reservedPart = New-Partition -DiskNumber $diskNum -Size 128MB -GptType '{e3c9e316-0b5c-4db8-817d-f92df00215ae}'
            # Windows partition
            $windowsPart = New-Partition -DiskNumber $diskNum -UseMaximumSize -GptType "{ebd0a0a2-b9e5-4433-87c0-68b6b72699c7}" -AssignDriveLetter
        }
        else # BIOS
        {
            Initialize-Disk -Number $diskNum -PartitionStyle MBR
            $windowsPart = New-Partition -DiskNumber $diskNum -UseMaximumSize -AssignDriveLetter -IsActive
            $systemPart = $windowsPart
        }

        $format = Format-Volume -DriveLetter $windowsPart.DriveLetter -FileSystem NTFS -NewFileSystemLabel $volumeLabel -Force -Confirm:$false
        return @("$($systemPart.DriveLetter):", "$($windowsPart.DriveLetter):")
    }
    finally
    {
        $v.Close()
    }
}

function ApplyImage($winImagePath, $wimFilePath, $imageIndex)
{
    Write-Output ('Applying Windows image "{0}" in "{1}"' -f $wimFilePath, $winImagePath)
    #Expand-WindowsImage -ImagePath $wimFilePath -Index $imageIndex -ApplyPath $winImagePath
    # Use Dism in place of the PowerShell equivalent for better progress update
    # and for ease of interruption with CTRL+C
    & Dism.exe /apply-image /imagefile:${wimFilePath} /index:${imageIndex} /ApplyDir:${winImagePath}
    if($LASTEXITCODE) { throw "Dism apply-image failed" }
}

function CreateBCDBootConfig($systemDrive, $windowsDrive, $diskLayout)
{
    $bcdbootPath = "${windowsDrive}\windows\system32\bcdboot.exe"
    if (!(Test-Path $bcdbootPath))
    {
        Write-Warning ('"{0}" not found, using online version' -f $bcdbootPath)
        $bcdbootPath = "bcdboot.exe"
    }

    # TODO: add support for UEFI boot
    # Note: older versions of bcdboot.exe don't have a /f argument
    & $bcdbootPath ${windowsDrive}\windows /s ${systemDrive} /v /f $diskLayout
    if($LASTEXITCODE) { throw "BCDBoot failed" }

    if($diskLayout -eq "BIOS")
    {
        $bcdeditPath = "${windowsDrive}\windows\system32\bcdedit.exe"
        if (!(Test-Path $bcdeditPath))
        {
            Write-Warning ('"{0}" not found, using online version' -f $bcdeditPath)
            $bcdeditPath = "bcdedit.exe"
        }

        & $bcdeditPath /store ${systemDrive}\boot\BCD /set `{bootmgr`} device locate
        if($LASTEXITCODE) { throw "BCDEdit failed" }

        & $bcdeditPath /store ${systemDrive}\boot\BCD /set `{default`} device locate
        if($LASTEXITCODE) { throw "BCDEdit failed" }

        & $bcdeditPath /store ${systemDrive}\boot\BCD /set `{default`} osdevice locate
        if($LASTEXITCODE) { throw "BCDEdit failed" }
    }
}

function TransformXml($xsltPath, $inXmlPath, $outXmlPath, $xsltArgs)
{
    $xslt = New-Object System.Xml.Xsl.XslCompiledTransform($false)
    $xsltSettings = New-Object System.Xml.Xsl.XsltSettings($false, $true)
    $xslt.Load($xsltPath, $xsltSettings, (New-Object System.Xml.XmlUrlResolver))
    $outXmlFile = New-Object System.IO.FileStream($outXmlPath, [System.IO.FileMode]::Create, [System.IO.FileAccess]::Write)
    $argList = new-object System.Xml.Xsl.XsltArgumentList

    foreach($k in $xsltArgs.Keys)
    {
        $argList.AddParam($k, "", $xsltArgs[$k])
    }

    $xslt.Transform($inXmlPath, $argList, $outXmlFile)
    $outXmlFile.Close()
}

function GenerateUnattendXml($inUnattendXmlPath, $outUnattendXmlPath, $image, $productKey, $administratorPassword)
{
    $xsltArgs = @{}

    $xsltArgs["processorArchitecture"] = ([string]$image.ImageArchitecture).ToLower()
    $xsltArgs["imageName"] = $image.ImageName
    $xsltArgs["versionMajor"] = $image.ImageVersion.Major
    $xsltArgs["versionMinor"] = $image.ImageVersion.Minor
    $xsltArgs["installationType"] = $image.ImageInstallationType
    $xsltArgs["administratorPassword"] = $administratorPassword

    if($productKey) {
        $xsltArgs["productKey"] = $productKey
    }

    TransformXml "$scriptPath\Unattend.xslt" $inUnattendXmlPath $outUnattendXmlPath $xsltArgs
}

function DetachVirtualDisk($vhdPath)
{
    try
    {
        $v = [WIMInterop.VirtualDisk]::OpenVirtualDisk($vhdPath)
        $v.DetachVirtualDisk()
    }
    finally
    {
        if($v) { $v.Close() }
    }
}

function GetDismVersion()
{
    return new-Object System.Version (gcm dism.exe).FileVersionInfo.ProductVersion
}

function CheckDismVersionForImage($image)
{
    $dismVersion = GetDismVersion
    if ($image.ImageVersion.CompareTo($dismVersion) -gt 0)
    {
        Write-Warning "The installed version of DISM is older than the Windows image"
    }
}

function ConvertVirtualDisk($vhdPath, $outPath, $format)
{
    Write-Output "Converting virtual disk image from $vhdPath to $outPath..."
    & $scriptPath\bin\qemu-img.exe convert -O $format.ToLower() $vhdPath $outPath
    if($LASTEXITCODE) { throw "qemu-img failed to convert the virtual disk" }
}

function CopyUnattendResources($resourcesDir, $imageInstallationType)
{
    # Workaround to recognize the $resourcesDir drive. This seems a PowerShell bug
    $drives = Get-PSDrive

    if(!(Test-Path "$resourcesDir")) { $d = mkdir "$resourcesDir" }
    copy -Recurse "$localResourcesDir\*" $resourcesDir

    if ($imageInstallationType -eq "Server Core")
    {
        # Skip the wallpaper on server core
        del -Force "$resourcesDir\Wallpaper.png"
        del -Force "$resourcesDir\GPO.zip"
    }
}

function DownloadCloudbaseInit($resourcesDir, $osArch)
{
    Write-Output "Downloading Cloudbase-Init..."

    if($osArch -eq "AMD64")
    {
        $CloudbaseInitMsi = "CloudbaseInitSetup_Stable_x64.msi"
    }
    else
    {
        $CloudbaseInitMsi = "CloudbaseInitSetup_Stable_x86.msi"
    }

    $CloudbaseInitMsiPath = "$resourcesDir\CloudbaseInit.msi"
    $CloudbaseInitMsiUrl = "https://www.cloudbase.it/downloads/$CloudbaseInitMsi"

    (new-object System.Net.WebClient).DownloadFile($CloudbaseInitMsiUrl, $CloudbaseInitMsiPath)
}

function GenerateConfigFile($resourcesDir, $installUpdates)
{
    $configIniPath = "$resourcesDir\config.ini"
    Import-Module "$localResourcesDir\ini.psm1"
    Set-IniFileValue -Path $configIniPath -Section "DEFAULT" -Key "InstallUpdates" -Value $installUpdates
}

function AddDriversToImage($winImagePath, $driversPath)
{
    Write-Output ('Adding drivers from "{0}" to image "{1}"' -f $driversPath, $winImagePath)
    Add-WindowsDriver -Path $winImagePath -Driver $driversPath -ForceUnsigned -Recurse
    #& Dism.exe /image:${winImagePath} /Add-Driver /driver:${driversPath} /ForceUnsigned /recurse
    #if ($LASTEXITCODE) { throw "Dism failed to add drivers from: $driversPath" }
}

function SetProductKeyInImage($winImagePath, $productKey)
{
    Set-WindowsProductKey -Path $winImagePath -ProductKey $productKey
}

function EnableFeaturesInImage($winImagePath, $featureNames)
{
    if($featureNames)
    {
        $featuresCmdStr = "& Dism.exe /image:${winImagePath} /Enable-Feature"
        foreach($featureName in $featureNames)
        {
            $featuresCmdStr += " /FeatureName:$featureName"
        }

        # Prefer Dism over Enable-WindowsOptionalFeature due to better error reporting
        Invoke-Expression $featuresCmdStr
        if ($LASTEXITCODE) { throw "Dism failed to enable features: $featureNames" }
    }
}

function CheckEnablePowerShellInImage($winImagePath, $image)
{
    # Windows 2008 R2 Server Core dows not enable powershell by default
    $v62 = new-Object System.Version 6, 2, 0, 0
    if($image.ImageVersion.CompareTo($v62) -lt 0 -and $image.ImageInstallationType -eq "Server Core")
    {
        Write-Output "Enabling PowerShell in the Windows image"
        $psFeatures = @("NetFx2-ServerCore", "MicrosoftWindowsPowerShell", `
                        "NetFx2-ServerCore-WOW64", "MicrosoftWindowsPowerShell-WOW64")
        EnableFeaturesInImage $winImagePath $psFeatures
    }
}

function AddVirtIODriversFromISO($vhdDriveLetter, $image, $isoPath)
{
    $v = [WIMInterop.VirtualDisk]::OpenVirtualDisk($isoPath)
    try
    {
        $v.AttachVirtualDisk()
        $devicePath = $v.GetVirtualDiskPhysicalPath()
        $isoDriveLetter = (Get-DiskImage -DevicePath $devicePath | Get-Volume).DriveLetter

        # For VirtIO ISO with drivers version lower than 1.8.x
        if($image.ImageVersion.Major -eq 6 -and $image.ImageVersion.Minor -eq 0)
        {
            $virtioVer = "VISTA"
        }
        elseif($image.ImageVersion.Major -eq 6 -and $image.ImageVersion.Minor -eq 1)
        {
            $virtioVer = "WIN7"
        }
        elseif(($image.ImageVersion.Major -eq 6 -and $image.ImageVersion.Minor -ge 2) -or $image.ImageVersion.Major -gt 6)
        {
            $virtioVer = "WIN8"
        }
        else
        {
            throw "Unsupported Windows version for VirtIO drivers: {0}" -f $image.ImageVersion
        }
        $virtioDir = "{0}:\{1}\{2}" -f $isoDriveLetter, $virtioVer, $image.ImageArchitecture
        if (Test-Path $virtioDir) {
            AddDriversToImage $vhdDriveLetter $virtioDir
            return
        }

        # For VirtIO ISO with drivers version higher than 1.8.x
        if($image.ImageVersion.Major -eq 6 -and $image.ImageVersion.Minor -eq 0)
        {
            $virtioVer = "2k12r2"
        }
        elseif($image.ImageVersion.Major -eq 6 -and $image.ImageVersion.Minor -eq 1)
        {
            $virtioVer = "w7"
        }
        elseif(($image.ImageVersion.Major -eq 6 -and $image.ImageVersion.Minor -ge 2) -or $image.ImageVersion.Major -gt 6)
        {
            $virtioVer = "w8.1"
        }
        else
        {
            throw "Unsupported Windows version for VirtIO drivers: {0}" -f $image.ImageVersion
        }

        $drivers = @("Balloon", "NetKVM", "viorng", "vioscsi", "vioserial", "viostor")
        foreach ($driver in $drivers) {
            $virtioDir = "{0}:\{1}\{2}\{3}" -f $isoDriveLetter, $driver, $virtioVer, $image.ImageArchitecture
            if (Test-Path $virtioDir) {
                AddDriversToImage $vhdDriveLetter $virtioDir
            }
        }

    }
    finally
    {
        $v.DetachVirtualDisk()
        $v.Close()
    }
}

function SetDotNetCWD()
{
    # Make sure the PowerShell and .Net CWD match
    [Environment]::CurrentDirectory = (Get-Location -PSProvider FileSystem).ProviderPath
}

function GetPathWithoutExtension($path)
{
    return Join-Path ([System.IO.Path]::GetDirectoryName($path)) `
                     ([System.IO.Path]::GetFileNameWithoutExtension($path))
}

function New-WindowsCloudImage()
{
    [CmdletBinding()]
    param
    (
        [parameter(Mandatory=$true, ValueFromPipeline=$true)]
        [string]$WimFilePath = "D:\Sources\install.wim",
        [parameter(Mandatory=$true)]
        [string]$ImageName,
        [parameter(Mandatory=$true)]
        [string]$VirtualDiskPath,
        [parameter(Mandatory=$true)]
        [Uint64]$SizeBytes,
        [parameter(Mandatory=$false)]
        [string]$ProductKey,
        [parameter(Mandatory=$false)]
        [ValidateSet("VHD", "VHDX", "QCow2", "VMDK", "RAW", ignorecase=$false)]
        [string]$VirtualDiskFormat = "VHDX",
        [ValidateSet("BIOS", "UEFI", ignorecase=$false)]
        [string]$DiskLayout = "BIOS",
        [parameter(Mandatory=$false)]
        [string]$VirtIOISOPath,
        [parameter(Mandatory=$false)]
        [switch]$InstallUpdates,
        [parameter(Mandatory=$false)]
        [string]$AdministratorPassword = "Pa`$`$w0rd",
        [parameter(Mandatory=$false)]
        [string]$UnattendXmlPath = "$scriptPath\UnattendTemplate.xml"
    )
    PROCESS
    {
        SetDotNetCWD
        CheckIsAdmin

        $image = Get-WimFileImagesInfo -WimFilePath $wimFilePath | where {$_.ImageName -eq $ImageName }
        if(!$image) { throw 'Image "$ImageName" not found in WIM file "$WimFilePath"'}
        CheckDismVersionForImage $image

        if (Test-Path $VirtualDiskPath) { Remove-Item -Force $VirtualDiskPath }

        if ($VirtualDiskFormat -in @("VHD", "VHDX"))
        {
            $VHDPath = $VirtualDiskPath
        }
        else
        {
            $VHDPath = "{0}.vhd" -f (GetPathWithoutExtension $VirtualDiskPath)
            if (Test-Path $VHDPath) { Remove-Item -Force $VHDPath }
        }

        try
        {
            $drives = CreateImageVirtualDisk $VHDPath $SizeBytes $DiskLayout
            $winImagePath = "$($drives[1])\"
            $resourcesDir = "${winImagePath}UnattendResources"
            $unattedXmlPath = "${winImagePath}Unattend.xml"

            GenerateUnattendXml $UnattendXmlPath $unattedXmlPath $image $ProductKey $AdministratorPassword
            CopyUnattendResources $resourcesDir $image.ImageInstallationType
            GenerateConfigFile $resourcesDir $installUpdates
            DownloadCloudbaseInit $resourcesDir ([string]$image.ImageArchitecture)
            ApplyImage $winImagePath $wimFilePath $image.ImageIndex
            CreateBCDBootConfig $drives[0] $drives[1] $DiskLayout
            CheckEnablePowerShellInImage $winImagePath $image

            # Product key is applied by the unattend.xml
            # Evaluate if it's the case to set the product key here as well
            # which in case requires Dism /Set-Edition
            #if($ProductKey)
            #{
            #    SetProductKeyInImage $winImagePath $ProductKey
            #}

            if($VirtIOISOPath)
            {
                AddVirtIODriversFromISO $winImagePath $image $VirtIOISOPath
            }
        }
        finally
        {
            if (Test-Path $VHDPath)
            {
                DetachVirtualDisk $VHDPath
            }
        }

        if ($VHDPath -ne $VirtualDiskPath)
        {
            ConvertVirtualDisk $VHDPath $VirtualDiskPath $VirtualDiskFormat
            del -Force $VHDPath
        }
    }
}

Export-ModuleMember New-WindowsCloudImage, Get-WimFileImagesInfo
