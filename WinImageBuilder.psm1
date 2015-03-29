$ErrorActionPreference = "Stop"
Set-StrictMode -Version 2
$scriptPath = split-path -parent $MyInvocation.MyCommand.Definition
$localResourcesDir = "$scriptPath\UnattendResources"
$rebootWarning = @"
In order to finish the MaaS image generation, we need to boot the image.
This operation requires that you have the Hyper-V role installed. We will now
install the Hyper-V role for you, create a virtual switch, and then
reboot your computer. After the reboot is done, please rerun this script.

If this is not what you want, please Ctrl-C now.
"@

$noSysprepWarning = @"
You have chosen not to sysprep the image now. This means that the resulting
image is not yet ready to deploy. The image is set to automatically sysprep
on first boot.

Please make sure you boot this image at least once before you use it.
"@

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

function CreateImageVirtualDisk($vhdPath, $size)
{
    $v = [WIMInterop.VirtualDisk]::CreateVirtualDisk($vhdPath, $size)
    try
    {
        $v.AttachVirtualDisk()
        $path = $v.GetVirtualDiskPhysicalPath()

        $m = $path -match "\\\\.\\PHYSICALDRIVE(?<num>\d+)"
        $diskNum = $matches["num"]
        $volumeLabel = "OS"

        Initialize-Disk -Number $diskNum -PartitionStyle MBR
        $part = New-Partition -DiskNumber $diskNum -UseMaximumSize -AssignDriveLetter -IsActive
        $driveLetter = $part.DriveLetter
        $format = Format-Volume -DriveLetter $driveLetter -FileSystem NTFS -NewFileSystemLabel $volumeLabel -Force -Confirm:$false
        return $driveLetter
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

function CreateBCDBootConfig($driveLetter)
{
    $bcdbootPath = "${driveLetter}:\windows\system32\bcdboot.exe"
    if (!(Test-Path $bcdbootPath))
    {
        Write-Warning ('"{0}" not found, using online version' -f $bcdbootPath)
        $bcdbootPath = "bcdboot.exe"
    }

    & $bcdbootPath ${driveLetter}:\windows /s ${driveLetter}: /v
    if($LASTEXITCODE) { throw "BCDBoot failed" }

    #& ${driveLetter}:\Windows\System32\bcdedit.exe /store ${driveLetter}:\boot\BCD
    #if($LASTEXITCODE) { throw "BCDEdit failed" }
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
        $v.Close()
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

function Convert-VirtualDisk($vhdPath, $outPath, $format)
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
        $CloudbaseInitMsi = "CloudbaseInitSetup_Beta_x64.msi"
    }
    else
    {
        $CloudbaseInitMsi = "CloudbaseInitSetup_Beta_x86.msi"
    }

    $CloudbaseInitMsiPath = "$resourcesDir\CloudbaseInit.msi"
    $CloudbaseInitMsiUrl = "https://www.cloudbase.it/downloads/$CloudbaseInitMsi"

    (new-object System.Net.WebClient).DownloadFile($CloudbaseInitMsiUrl, $CloudbaseInitMsiPath)
}

function GenerateConfigFile
{
    Param(
        [Parameter(Mandatory=$true)]
        [string]$resourcesDir,
        [Parameter(Mandatory=$true)]
        [hashtable]$values
    )

    $configIniPath = "$resourcesDir\config.ini"
    Import-Module "$localResourcesDir\ini.psm1"
    foreach ($i in $values.GetEnumerator()){
        Set-IniFileValue -Path $configIniPath -Section "DEFAULT" -Key $i.Name -Value $i.Value
    }
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
        AddDriversToImage $vhdDriveLetter $virtioDir
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

function Compress-Image($VirtualDiskPath, $ImagePath)
{
    if (!(Test-Path $VirtualDiskPath)){
        Throw "$VirtualDiskPath not found"
    }
    $name = $ImagePath + ".tgz"
    $tmpName = $name + "." + (Get-Random)

    $7zip = Join-Path $localResourcesDir 7za.exe

    Write-Host "Compressing $VirtualDiskPath to $name"
    & $7zip a -ttar $tmpName $VirtualDiskPath
    if($LASTEXITCODE){
        Throw "Failed to create tar"
    }
    Remove-Item -Force $VirtualDiskPath
    & $7zip a $name $tmpName
    if($LASTEXITCODE){
        Throw "Failed to compress image"
    }
    Remove-Item -Force $tmpName
    Move-Item $name $ImagePath
    Write-Host "MaaS image is ready and available at: $ImagePath"
}

function Create-VirtualSwitch
{
    Param(
        [Parameter(Mandatory=$false)]
        [string]$NetAdapterName,
        [Parameter(Mandatory=$false)]
        [string]$Name="br100"

    )
    if (!$NetAdapterName){
        $defRoute = Get-NetRoute | Where-Object {$_.DestinationPrefix -eq "0.0.0.0/0"}
        if (!$defRoute) {
            Throw "Could not determine default route"
        }
        $details = $defRoute[0]
        $netAdapter = Get-NetAdapter -ifIndex $details.ifIndex -Physical:$true
        if (!$netAdapter){
            Throw "Could not get physical interface for switch"
        }
        $NetAdapterName = $netAdapter.Name        
    }
    $sw = New-VMSwitch -Name $Name -NetAdapterName $NetAdapterName -AllowManagementOS $true
    return $sw
}

function Install-Prerequisites
{
    try {
        $needsHyperV = Get-WindowsOptionalFeature -Online -FeatureName Microsoft-Hyper-V
    }catch{
        Write-Error "Failed to get Hyper-V role status"
    }

    if ($needsHyperV.State -ne "Enabled"){
        $delay = 60
        Write-Warning $rebootWarning
        Write-Warning "Sleeping for $delay"
        Start-Sleep $delay

        $installHyperV = Enable-WindowsOptionalFeature -Online -FeatureName Microsoft-Hyper-V -All -NoRestart
        if ($installHyperV.RestartNeeded){
            shutdown -r -t 0
            exit 0
        }
    }
}

function GetOrCreateSwitch
{
    $vmSwitches = Get-VMSwitch -SwitchType external

    if ($vmSwitches){
        $vmswitch = $vmSwitches[0]
    }else{
        $vmswitch = Create-VirtualSwitch -Name "br100"
    }

    return $vmswitch
}

function Wait-ForVMShutdown
{
    Param(
        [Parameter(Mandatory=$true)]
        [string]$Name
    )
    Write-Host "Waiting for $Name to finish sysprep"
    $isOff = (Get-VM -Name $Name).State -eq "Off"
    while($isOff -eq $false){
        Start-Sleep 1
        $isOff = (Get-VM -Name $Name).State -eq "Off"
    }
}

function Run-Sysprep
{
    Param(
        [Parameter(Mandatory=$true)]
        [string]$Name,
        [Parameter(Mandatory=$true)]
        [string]$VHDPath,
        [Parameter(Mandatory=$true)]
        [Uint64]$Memory,
        [Parameter(Mandatory=$true)]
        [int]$CpuCores=1,
        [Parameter(Mandatory=$true)]
        [string]$VMSwitch
    )

    Write-Host "Creating VM $Name attached to $VMSwitch"
    New-VM -Name $Name -MemoryStartupBytes $Memory -SwitchName $VMSwitch -VHDPath $VHDPath
    Set-VMProcessor -VMname $Name -count $CpuCores 
    Write-Host "Starting $Name"
    Start-VM $Name
    Start-Sleep 5
    Wait-ForVMShutdown $Name
    Remove-VM $Name -Confirm:$false -Force
}

function New-MaaSImage()
{
    [CmdletBinding()]
    param
    (
        [parameter(Mandatory=$true, ValueFromPipeline=$true)]
        [string]$WimFilePath = "D:\Sources\install.wim",
        [parameter(Mandatory=$true)]
        [string]$ImageName,
        [parameter(Mandatory=$true)]
        [string]$MaaSImagePath,
        [parameter(Mandatory=$true)]
        [Uint64]$SizeBytes,
        [parameter(Mandatory=$false)]
        [string]$ProductKey,
        [parameter(Mandatory=$false)]
        [string]$VirtIOISOPath,
        [parameter(Mandatory=$false)]
        [switch]$InstallUpdates,
        [parameter(Mandatory=$false)]
        [string]$AdministratorPassword = "Pa`$`$w0rd",
        [parameter(Mandatory=$false)]
        [switch]$PersistDriverInstall = $false,
        [parameter(Mandatory=$false)]
        [Uint64]$Memory=2GB,
        [parameter(Mandatory=$false)]
        [int]$CpuCores=1,
        [parameter(Mandatory=$false)]
        [switch]$RunSysprep
    )
    PROCESS
    {
        CheckIsAdmin
        if ($RunSysprep){
            Install-Prerequisites
            $vmSwitch = GetOrCreateSwitch
            $coreCount = (gwmi win32_processor).NumberOfLogicalProcessors
            if ($CpuCores -gt $coreCount){
                Write-Warning "CpuCores larger then available (logical) CPU cores. Setting CpuCores to $coreCount"
                $CpuCores = $coreCount
            }
        }else{
            Write-Warning $noSysprepWarning
            Write-Host "Sleeping for 30 seconds"
            Start-Sleep 30
        }
        try {
            $VirtualDiskPath = $MaaSImagePath + ".vhd"
            $RawImagePath = $MaaSImagePath + ".img"
            New-WindowsCloudImage -WimFilePath $WimFilePath -ImageName $ImageName `
            -VirtualDiskPath $VirtualDiskPath -SizeBytes $SizeBytes -ProductKey $ProductKey `
            -VirtIOISOPath $VirtIOISOPath -InstallUpdates:$InstallUpdates `
            -AdministratorPassword $AdministratorPassword -PersistDriverInstall:$PersistDriverInstall

            if ($RunSysprep){
                $Name = "MaaS-Sysprep" + (Get-Random)
                Run-Sysprep -Name $Name -Memory $Memory -VHDPath $VirtualDiskPath -VMSwitch $vmSwitch.Name -CpuCores $CpuCores
            }
            Write-Host "Converting VHD to RAW"
            Convert-VirtualDisk $VirtualDiskPath $RawImagePath "RAW"
            del -Force $VirtualDiskPath
            Compress-Image $RawImagePath $MaaSImagePath
        }finally{
            Remove-Item -Force $MaaSImagePath* -ErrorAction SilentlyContinue
        }
    }
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
        [ValidateSet("VHD", "QCow2", "VMDK", "RAW", ignorecase=$false)]
        [string]$VirtualDiskFormat = "VHD",
        [parameter(Mandatory=$false)]
        [string]$VirtIOISOPath,
        [parameter(Mandatory=$false)]
        [switch]$InstallUpdates,
        [parameter(Mandatory=$false)]
        [string]$AdministratorPassword = "Pa`$`$w0rd",
        [parameter(Mandatory=$false)]
        [string]$UnattendXmlPath = "$scriptPath\UnattendTemplate.xml",
        [parameter(Mandatory=$false)]
        [switch]$PersistDriverInstall = $true
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
            $driveLetter = CreateImageVirtualDisk $VHDPath $SizeBytes
            $winImagePath = "${driveLetter}:\"
            $resourcesDir = "${winImagePath}UnattendResources"
            $unattedXmlPath = "${winImagePath}Unattend.xml"
            $configValues = @{
                "InstallUpdates"=$InstallUpdates;
                "PersistDriverInstall"=$PersistDriverInstall;
            }

            echo "$UnattendXmlPath $unattedXmlPath $image $ProductKey $AdministratorPassword"
            GenerateUnattendXml $UnattendXmlPath $unattedXmlPath $image $ProductKey $AdministratorPassword
            CopyUnattendResources $resourcesDir $image.ImageInstallationType
            GenerateConfigFile $resourcesDir $configValues
            DownloadCloudbaseInit $resourcesDir ([string]$image.ImageArchitecture)
            ApplyImage $winImagePath $wimFilePath $image.ImageIndex
            CreateBCDBootConfig $driveLetter
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
            Convert-VirtualDisk $VHDPath $VirtualDiskPath $VirtualDiskFormat
            del -Force $VHDPath
        }
    }
}

Export-ModuleMember New-WindowsCloudImage, Get-WimFileImagesInfo, New-MaaSImage
