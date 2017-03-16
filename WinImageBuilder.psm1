$ErrorActionPreference = "Stop"
Set-StrictMode -Version 2
Import-Module Dism

$scriptPath = Split-Path -Parent $MyInvocation.MyCommand.Definition
$localResourcesDir = "$scriptPath\UnattendResources"
Import-Module "$localResourcesDir\ini.psm1"

$noHypervWarning = @"
The Hyper-V role is missing from this machine. In order to be able to finish
generating the image, you need to install the Hyper-V role.

You can do so by running the following commands from an elevated powershell
command prompt:
Enable-WindowsOptionalFeature -Online -FeatureName Microsoft-Hyper-V -All -NoRestart
Enable-WindowsOptionalFeature -Online -FeatureName Microsoft-Hyper-V-Management-PowerShell -All -NoRestart

Don't forget to reboot after you install the Hyper-V role.
"@
$noSysprepWarning = @"
You have chosen not to sysprep the image now. If you want to run sysprep now,
use the -RunSysprep flag. If you do not run sysprep now, the resulting image
will not be ready to deploy.
The image is set to automatically sysprep on first boot.
Please make sure you boot this image at least once before you use it.
"@
$VirtIODrivers = @("balloon", "netkvm", "pvpanic", "qemupciserial", "qxl",
             "qxldod", "vioinput", "viorng", "vioscsi", "vioserial", "viostor")

$VirtIODriverMappings = @{
    "2k8" = @(60, 1);
    "2k8r2" = @(61, 1);
    "w7" = @(61, 0);
    "2k12" = @(62, 1);
    "w8" = @(62, 0);
    "2k12r2" = @(63, 1);
    "w8.1" = @(63, 0);
    "2k16" = @(100, 1);
    "w10" = @(100, 0);
}

. "$scriptPath\Interop.ps1"


function Get-AvailableConfigs {
    $availableConfigs = @()
    $availableConfigs += Get-ConfigFromTemplate -Name "wim_file_path" -DefaultValue "D:\Sources\install.wim"
    $availableConfigs += Get-ConfigFromTemplate -Name "image_name" 
    $availableConfigs += Get-ConfigFromTemplate -Name "image_path" 
    $availableConfigs += Get-ConfigFromTemplate -Name "virtual_disk_format" -DefaultValue "VHDX"
    $availableConfigs += Get-ConfigFromTemplate -Name "image_type" -DefaultValue "MAAS"
    $availableConfigs += Get-ConfigFromTemplate -Name "disk_layout" -DefaultValue "BIOS"
    $availableConfigs += Get-ConfigFromTemplate -Name "product_key" 
    $availableConfigs += Get-ConfigFromTemplate -Name "extra_features" 
    $availableConfigs += Get-ConfigFromTemplate -Name "force" -DefaultValue $false
    $availableConfigs += Get-ConfigFromTemplate -Name "install_maas_hooks" -DefaultValue $false
    $availableConfigs += Get-ConfigFromTemplate -Name "zip_password"
    $availableConfigs += Get-ConfigFromTemplate -Name "administrator_password" -DefaultValue "Pa`$`$w0rd" `
                                     -GroupName "vm"
    $availableConfigs += Get-ConfigFromTemplate -Name "external_switch" -GroupName "vm"
    $availableConfigs += Get-ConfigFromTemplate -Name "cpu_count" -DefaultValue "1" `
                                     -GroupName "vm"
    $availableConfigs += Get-ConfigFromTemplate -Name "ram_size" -DefaultValue "2048" `
                                     -GroupName "vm"
    $availableConfigs += Get-ConfigFromTemplate -Name "disk_size" -DefaultValue "40G" `
                                     -GroupName "vm"
    $availableConfigs += Get-ConfigFromTemplate -Name "virtio_iso_path" -GroupName "drivers"
    $availableConfigs += Get-ConfigFromTemplate -Name "virtio_base_path" -GroupName "drivers"
    $availableConfigs += Get-ConfigFromTemplate -Name "drivers_path" -GroupName "drivers"
    $availableConfigs += Get-ConfigFromTemplate -Name "install_updates" -DefaultValue $false `
                                     -GroupName "updates"
    $availableConfigs += Get-ConfigFromTemplate -Name "purge_updates" -DefaultValue $false `
                                     -GroupName "updates"
    $availableConfigs += Get-ConfigFromTemplate -Name "run_sysprep" -DefaultValue $true `
                                     -GroupName "sysprep"
    $availableConfigs += Get-ConfigFromTemplate -Name "unattend_xml_path" -DefaultValue "UnattendTemplate.xml" `
                                     -GroupName "sysprep"
    $availableConfigs += Get-ConfigFromTemplate -Name "disable_swap" -DefaultValue $false `
                                     -GroupName "sysprep"
    $availableConfigs += Get-ConfigFromTemplate -Name "persist_drivers_install" -DefaultValue $true `
                                     -GroupName "sysprep"

    return $availableConfigs
}

function Get-ConfigFromTemplate {
    param(
        [parameter(Mandatory=$true)]
        [string]$Name,
        [parameter(Mandatory=$false)]
        [string]$DefaultValue="",
        [parameter(Mandatory=$false)]
        [string]$GroupName="DEFAULT"
        )

    return @{'Name' = $Name;'GroupName' = $GroupName; 'DefaultValue'  = $DefaultValue}
}

function Get-GlobalConfigs {
    param($ConfigPath)
    $GlobalConfigs = @{}
    $availableConfigs = Get-AvailableConfigs
    foreach($availableConfig in $availableConfigs) {
        try {
            $value = Get-IniFileValue -Path $configPath -Section $availableConfig['GroupName'] -Key $availableConfig['Name'] -Default $availableConfig['Default']
        } catch {
            $value = $availableConfig['Default']
        }
        $GlobalConfigs += @{$availableConfig['Name'] = $value}
    }
    return $GlobalConfigs

}


function Execute-Retry {
    Param(
        [parameter(Mandatory=$true)]
        $command,
        [int]$maxRetryCount=4,
        [int]$retryInterval=4
    )

    $currErrorActionPreference = $ErrorActionPreference
    $ErrorActionPreference = "Continue"

    $retryCount = 0
    while ($true) {
        try {
            $res = Invoke-Command -ScriptBlock $command
            $ErrorActionPreference = $currErrorActionPreference
            return $res
        } catch [System.Exception] {
            $retryCount++
            if ($retryCount -ge $maxRetryCount) {
                $ErrorActionPreference = $currErrorActionPreference
                throw
            } else {
                if($_) {
                    Write-Warning $_
                }
                Start-Sleep $retryInterval
            }
        }
    }
}

function Is-Administrator {
    $wid = [System.Security.Principal.WindowsIdentity]::GetCurrent()
    $prp = New-Object System.Security.Principal.WindowsPrincipal($wid)
    $adm = [System.Security.Principal.WindowsBuiltInRole]::Administrator
    $isAdmin = $prp.IsInRole($adm)
    if (!$isAdmin) {
        throw "This cmdlet must be executed in an elevated administrative shell"
    }
}

function Get-WimInteropObject {
    Param(
        [parameter(Mandatory=$true)]
        [string]$WimFilePath
    )
    return (New-Object WIMInterop.WimFile -ArgumentList $WimFilePath)
}

function Get-WimFileImagesInfo {
    <#
    .SYNOPSIS
     This function retrieves a list of the Windows Editions from an ISO file.
    .DESCRIPTION
     This function reads the Images content of the WIM file that can be found
     on a mounted ISO and it returns an object for each Windows Edition, each
     object containing a list of properties.
    .PARAMETER WimFilePath
     Location of the install.wim file found on the mounted ISO image.
    #>
    [CmdletBinding()]
    Param(
        [parameter(Mandatory=$true)]
        [string]$WimFilePath = "D:\Sources\install.wim"
    )
    PROCESS
    {
        $w = Get-WimInteropObject $WimFilePath
        return $w.Images
    }
}

function Create-ImageVirtualDisk {
    [CmdletBinding()]
    Param(
        [parameter(Mandatory=$true)]
        [string]$VhdPath,
        [parameter(Mandatory=$true)]
        [long]$Size,
        [parameter(Mandatory=$true)]
        [string]$DiskLayout
    )

    $v = [WIMInterop.VirtualDisk]::CreateVirtualDisk($VhdPath, $Size)
    try {
        $v.AttachVirtualDisk()
        $path = $v.GetVirtualDiskPhysicalPath()

        $m = $path -match "\\\\.\\PHYSICALDRIVE(?<num>\d+)"
        $diskNum = $matches["num"]
        $volumeLabel = "OS"

        if ($DiskLayout -eq "UEFI") {
            Initialize-Disk -Number $diskNum -PartitionStyle GPT
            # EFI partition
            $systemPart = New-Partition -DiskNumber $diskNum -Size 200MB `
                -GptType '{c12a7328-f81f-11d2-ba4b-00a0c93ec93b}' `
                -AssignDriveLetter
            & format.com "$($systemPart.DriveLetter):" /FS:FAT32 /Q /Y | Out-Null
            if ($LASTEXITCODE) {
                throw "Format failed"
            }
            # MSR partition
            $reservedPart = New-Partition -DiskNumber $diskNum -Size 128MB `
                -GptType '{e3c9e316-0b5c-4db8-817d-f92df00215ae}'
            # Windows partition
            $windowsPart = New-Partition -DiskNumber $diskNum -UseMaximumSize `
                -GptType "{ebd0a0a2-b9e5-4433-87c0-68b6b72699c7}" `
                -AssignDriveLetter
        } else {
            # BIOS
            Initialize-Disk -Number $diskNum -PartitionStyle MBR
            $windowsPart = New-Partition -DiskNumber $diskNum -UseMaximumSize `
                -AssignDriveLetter -IsActive
            $systemPart = $windowsPart
        }

        $format = Format-Volume -DriveLetter $windowsPart.DriveLetter `
            -FileSystem NTFS -NewFileSystemLabel $volumeLabel `
            -Force -Confirm:$false
        return @("$($systemPart.DriveLetter):", "$($windowsPart.DriveLetter):")
    } finally {
        $v.Close()
    }
}

function Apply-Image {
    Param(
        [parameter(Mandatory=$true)]
        [string]$winImagePath,
        [parameter(Mandatory=$true)]
        [string]$wimFilePath,
        [parameter(Mandatory=$true)]
        [int]$imageIndex
    )
    Write-Output ('Applying Windows image "{0}" in "{1}"' -f $wimFilePath, $winImagePath)
    #Expand-WindowsImage -ImagePath $wimFilePath -Index $imageIndex -ApplyPath $winImagePath
    # Use Dism in place of the PowerShell equivalent for better progress update
    # and for ease of interruption with CTRL+C
    & Dism.exe /apply-image /imagefile:${wimFilePath} /index:${imageIndex} /ApplyDir:${winImagePath}
    if ($LASTEXITCODE) { throw "Dism apply-image failed" }
}

function Create-BCDBootConfig {
    Param(
        [parameter(Mandatory=$true)]
        [string]$systemDrive,
        [parameter(Mandatory=$true)]
        [string]$windowsDrive,
        [parameter(Mandatory=$true)]
        [string]$diskLayout,
        [parameter(Mandatory=$true)]
        [object]$image
    )

    $bcdbootPath = "${windowsDrive}\windows\system32\bcdboot.exe"
    if (!(Test-Path $bcdbootPath)) {
        Write-Warning ('"{0}" not found, using online version' -f $bcdbootPath)
        $bcdbootPath = "bcdboot.exe"
    }

    # Note: older versions of bcdboot.exe don't have a /f argument
    if ($image.ImageVersion.Major -eq 6 -and $image.ImageVersion.Minor -lt 2) {
        & $bcdbootPath ${windowsDrive}\windows /s ${systemDrive} /v
    } else {
        & $bcdbootPath ${windowsDrive}\windows /s ${systemDrive} /v /f $diskLayout
    }
    if ($LASTEXITCODE) { throw "BCDBoot failed" }

    if ($diskLayout -eq "BIOS") {
        $bcdeditPath = "${windowsDrive}\windows\system32\bcdedit.exe"
        if (!(Test-Path $bcdeditPath)) {
            Write-Warning ('"{0}" not found, using online version' -f $bcdeditPath)
            $bcdeditPath = "bcdedit.exe"
        }

        & $bcdeditPath /store ${systemDrive}\boot\BCD /set `{bootmgr`} device locate
        if ($LASTEXITCODE) { Write-Warning "BCDEdit failed: bootmgr device locate" }

        & $bcdeditPath /store ${systemDrive}\boot\BCD /set `{default`} device locate
        if ($LASTEXITCODE) { Write-Warning "BCDEdit failed: default device locate" }

        & $bcdeditPath /store ${systemDrive}\boot\BCD /set `{default`} osdevice locate
        if ($LASTEXITCODE) { Write-Warning "BCDEdit failed: default osdevice locate" }
    }
}

function Transform-Xml {
    Param(
        [parameter(Mandatory=$true)]
        [string]$xsltPath,
        [parameter(Mandatory=$true)]
        [string]$inXmlPath,
        [parameter(Mandatory=$true)]
        [string]$outXmlPath,
        [parameter(Mandatory=$true)]
        $xsltArgs
    )
    $xslt = New-Object System.Xml.Xsl.XslCompiledTransform($false)
    $xsltSettings = New-Object System.Xml.Xsl.XsltSettings($false, $true)
    $xslt.Load($xsltPath, $xsltSettings, (New-Object System.Xml.XmlUrlResolver))
    $outXmlFile = New-Object System.IO.FileStream($outXmlPath, `
        [System.IO.FileMode]::Create, [System.IO.FileAccess]::Write)
    $argList = New-Object System.Xml.Xsl.XsltArgumentList

    foreach ($k in $xsltArgs.Keys) {
        $argList.AddParam($k, "", $xsltArgs[$k])
    }
    $xslt.Transform($inXmlPath, $argList, $outXmlFile)
    $outXmlFile.Close()
}

function Generate-UnattendXml {
    Param(
        [parameter(Mandatory=$true)]
        [string]$inUnattendXmlPath,
        [parameter(Mandatory=$true)]
        [string]$outUnattendXmlPath,
        [parameter(Mandatory=$true)]
        [object]$image,
        [ValidatePattern("^$|^\S{5}-\S{5}-\S{5}-\S{5}-\S{5}")]
        [parameter(Mandatory=$false)]
        [string]$productKey,
        [parameter(Mandatory=$false)]
        $administratorPassword
    )
    $xsltArgs = @{}
    $xsltArgs["processorArchitecture"] = ([string]$image.ImageArchitecture).ToLower()
    $xsltArgs["imageName"] = $image.ImageName
    $xsltArgs["versionMajor"] = $image.ImageVersion.Major
    $xsltArgs["versionMinor"] = $image.ImageVersion.Minor
    $xsltArgs["installationType"] = $image.ImageInstallationType
    $xsltArgs["administratorPassword"] = $administratorPassword

    if ($productKey) {
        $xsltArgs["productKey"] = $productKey
    }

    Transform-Xml "$scriptPath\Unattend.xslt" $inUnattendXmlPath $outUnattendXmlPath $xsltArgs
}

function Detach-VirtualDisk {
    Param(
        [Parameter(Mandatory=$true)]
        [string]$VhdPath
    )
    try {
        $v = [WIMInterop.VirtualDisk]::OpenVirtualDisk($VhdPath)
        $v.DetachVirtualDisk()
    } finally {
        if ($v) { $v.Close() }
    }
}

function Check-DismVersionForImage {
    Param(
        [Parameter(Mandatory=$true)]
        [object]$image
    )
    $dismVersion = New-Object System.Version `
        (Get-Command dism.exe).FileVersionInfo.ProductVersion
    if ($image.ImageVersion.CompareTo($dismVersion) -gt 0) {
        Write-Warning "The installed version of DISM is older than the Windows image"
    }
}

function Convert-VirtualDisk {
    Param(
        [Parameter(Mandatory=$true)]
        [string]$vhdPath,
        [Parameter(Mandatory=$true)]
        [string]$outPath,
        [Parameter(Mandatory=$true)]
        [string]$format
    )
    Write-Host "Converting virtual disk image from $vhdPath to $outPath..."
    Execute-Retry {
        & "$scriptPath\bin\qemu-img.exe" convert -O $format.ToLower() $vhdPath $outPath
        if($LASTEXITCODE) { throw "qemu-img failed to convert the virtual disk" }
    }
}

function Copy-UnattendResources {
    Param(
        [Parameter(Mandatory=$true)]
        [string]$resourcesDir,
        [Parameter(Mandatory=$true)]
        [string]$imageInstallationType,
        [Parameter(Mandatory=$false)]
        [boolean]$InstallMaaSHooks
    )
    # Workaround to recognize the $resourcesDir drive. This seems a PowerShell bug
    Get-PSDrive | Out-Null

    if (!(Test-Path "$resourcesDir")) {
        $d = New-Item -Type Directory $resourcesDir
    }
    Write-Host "Copying: $localResourcesDir $resourcesDir"
    Copy-Item -Recurse "$localResourcesDir\*" $resourcesDir

    if ($imageInstallationType -eq "Server Core") {
        # Skip the wallpaper on server core
        Remove-Item -Force "$resourcesDir\Wallpaper.jpg"
        Remove-Item -Force "$resourcesDir\GPO.zip"
    }
    if ($InstallMaaSHooks) {
        $src = Join-Path $localResourcesDir "windows-curtin-hooks\curtin"
        if ((Test-Path $src)) {
            $dst = Split-Path $resourcesDir
            Copy-Item -Recurse $src $dst
        } else {
            throw "The Windows curtin hooks module is not present.
                Please run git submodule update --init " }
    }
}

function Download-CloudbaseInit {
    Param(
        [Parameter(Mandatory=$true)]
        [string]$resourcesDir,
        [Parameter(Mandatory=$true)]
        [string]$osArch
    )
    Write-Host "Downloading Cloudbase-Init..."

    if ($osArch -eq "AMD64") {
        $CloudbaseInitMsi = "CloudbaseInitSetup_Stable_x64.msi"
    } else {
        $CloudbaseInitMsi = "CloudbaseInitSetup_Stable_x86.msi"
    }

    $CloudbaseInitMsiPath = "$resourcesDir\CloudbaseInit.msi"
    $CloudbaseInitMsiUrl = "https://www.cloudbase.it/downloads/$CloudbaseInitMsi"

    Execute-Retry {
        (New-Object System.Net.WebClient).DownloadFile($CloudbaseInitMsiUrl, $CloudbaseInitMsiPath)
    }
}

function Generate-ConfigFile {
    Param(
        [Parameter(Mandatory=$true)]
        [string]$resourcesDir,
        [Parameter(Mandatory=$true)]
        [hashtable]$values
    )

    $configIniPath = "$resourcesDir\config.ini"
    Import-Module "$localResourcesDir\ini.psm1"
    foreach ($i in $values.GetEnumerator()) {
        Set-IniFileValue -Path $configIniPath -Section "DEFAULT" -Key $i.Key -Value $i.Value
    }
}

function Add-DriversToImage {
    Param(
        [Parameter(Mandatory=$true)]
        [string]$winImagePath,
        [Parameter(Mandatory=$true)]
        [string]$driversPath
    )
    Write-Output ('Adding drivers from "{0}" to image "{1}"' -f $driversPath, $winImagePath)
    & Dism.exe /image:${winImagePath} /Add-Driver /driver:${driversPath} /ForceUnsigned /recurse
    if ($LASTEXITCODE) {
        throw "Dism failed to add drivers from: $driversPath"
    }
}

function Enable-FeaturesInImage {
    Param(
        [Parameter(Mandatory=$true)]
        [string]$winImagePath,
        [Parameter(Mandatory=$true)]
        [array]$featureNames
    )
    if ($featureNames) {
        $cmd = @(
        "Dism.exe",
        ("/image:{0}" -f ${winImagePath}),
        "/Enable-Feature"
        )
        foreach ($featureName in $featureNames) {
            $cmd += ("/FeatureName:{0}" -f $featureName)
        }

        Execute-Retry {
            & $cmd[0] $cmd[1..$cmd.Length]
            if ($LASTEXITCODE) { throw "Dism failed to enable features: $featureNames" }
        }
    }
}

function Check-EnablePowerShellInImage {
    Param(
        [Parameter(Mandatory=$true)]
        [string]$winImagePath,
        [Parameter(Mandatory=$true)]
        [object]$image
    )
    # Windows 2008 R2 Server Core does not have powershell enabled by default
    $v62 = New-Object System.Version 6, 2, 0, 0
    if ($image.ImageVersion.CompareTo($v62) -lt 0 `
            -and $image.ImageInstallationType -eq "Server Core") {
        Write-Output "Enabling PowerShell in the Windows image"
        $psFeatures = @("NetFx2-ServerCore",
                        "MicrosoftWindowsPowerShell",
                        "NetFx2-ServerCore-WOW64",
                        "MicrosoftWindowsPowerShell-WOW64"
                        )
        Enable-FeaturesInImage $winImagePath $psFeatures
    }
}

function Is-IsoFile {
    Param(
        [parameter(Mandatory=$true)]
        [string]$FilePath
    )
    return ([System.IO.Path]::GetExtension($FilePath) -eq ".iso")
}

function Is-ServerInstallationType {
    Param(
        [parameter(Mandatory=$true)]
        [object]$image
    )
    return ($image.ImageInstallationType -in @("Server", "Server Core"))
}

function Get-VirtIODrivers {
    Param(
        [parameter(Mandatory=$true)]
        [int]$MajorMinorVersion,
        [parameter(Mandatory=$true)]
        [int]$IsServer,
        [parameter(Mandatory=$true)]
        [string]$BasePath,
        [parameter(Mandatory=$true)]
        [string]$Architecture,
        [parameter(Mandatory=$false)]
        [int]$RecursionDepth = 0
    )

    $driverPaths = @()
    foreach ($driver in $VirtioDrivers) {
        foreach ($osVersion in $VirtIODriverMappings.Keys) {
            $map = $VirtIODriverMappings[$osVersion]
            if (!(($map[0] -eq $MajorMinorVersion) -and ($map[1] -eq $isServer))) {
              continue
            }
            $driverPath = "{0}\{1}\{2}\{3}" -f @($basePath,
                                                 $driver,
                                                 $osVersion,
                                                 $architecture)
            if (Test-Path $driverPath) {
                $driverPaths += $driverPath
                break
            }
        }
    }
    if (!$driverPaths -and $RecursionDepth -lt 1) {
        # Note(avladu): Fallback to 2012r2/w8.1 if no drivers are found
        $driverPaths = Get-VirtIODrivers 63 $IsServer $BasePath $Architecture 1
    }
    return $driverPaths
}

function Add-VirtIODrivers {
    Param(
        [parameter(Mandatory=$true)]
        [string]$vhdDriveLetter,
        [parameter(Mandatory=$true)]
        [object]$image,
        [parameter(Mandatory=$true)]
        [string]$driversBasePath
    )
    # For VirtIO ISO with drivers version lower than 1.8.x
    if ($image.ImageVersion.Major -eq 6 -and $image.ImageVersion.Minor -eq 0) {
        $virtioVer = "VISTA"
    } elseif ($image.ImageVersion.Major -eq 6 -and $image.ImageVersion.Minor -eq 1) {
        $virtioVer = "WIN7"
    } elseif (($image.ImageVersion.Major -eq 6 -and $image.ImageVersion.Minor -ge 2) `
        -or $image.ImageVersion.Major -gt 6) {
        $virtioVer = "WIN8"
    } else {
        throw "Unsupported Windows version for VirtIO drivers: {0}" `
            -f $image.ImageVersion
    }
    $virtioDir = "{0}\{1}\{2}" -f $driversBasePath, $virtioVer, $image.ImageArchitecture
    if (Test-Path $virtioDir) {
        Add-DriversToImage $vhdDriveLetter $virtioDir
        return
    }

    # For VirtIO ISO with drivers version higher than 1.8.x
    $majorMinorVersion = [string]$image.ImageVersion.Major + [string]$image.ImageVersion.Minor
    $virtioDriversPaths = Get-VirtIODrivers -MajorMinorVersion $majorMinorVersion `
        -IsServer ([int](Is-ServerInstallationType $image)) -BasePath $driversBasePath `
        -Architecture $image.ImageArchitecture
    foreach ($virtioDriversPath in $virtioDriversPaths) {
        if (Test-Path $virtioDriversPath) {
            Add-DriversToImage $vhdDriveLetter $virtioDriversPath
        }
    }
}

function Add-VirtIODriversFromISO {
    <#
    .SYNOPSIS
     This function adds VirtIO drivers from a given ISO path to a mounted Windows VHD image.
     The VirtIO ISO contains all the synthetic drivers for the KVM hypervisor. 
    .DESCRIPTION
     This function takes the VirtIO drivers from a specified ISO file and installs them into the 
     given VHD, based on the characteristics given by the image parameter (which contains the
     image version, image architecture and installation type).
     More info can be found here: https://fedoraproject.org/wiki/Windows_Virtio_Drivers
    .PARAMETER VHDDriveLetter
     The drive letter of the mounted Windows VHD image.
    .PARAMETER Image
     The exact flavor of Windows installed on that image, so that the supported VirtIO drivers
     can be installed.
    .PARAMETER ISOPath
     The full path of the VirtIO ISO file containing the drivers.
    #>
    Param(
        [parameter(Mandatory=$true)]
        [string]$vhdDriveLetter,
        [parameter(Mandatory=$true)]
        [object]$image,
        [parameter(Mandatory=$true)]
        [string]$isoPath
    )
    $v = [WIMInterop.VirtualDisk]::OpenVirtualDisk($isoPath)
    try {
        if (Is-IsoFile $isoPath) {
            $v.AttachVirtualDisk()
            $devicePath = $v.GetVirtualDiskPhysicalPath()
            $driversBasePath = ((Get-DiskImage -DevicePath $devicePath `
                | Get-Volume).DriveLetter) + ":"
            Write-Host "Adding drivers from $driversBasePath"
            # We call Get-PSDrive to refresh the list of active drives.
            # Otherwise, "Test-Path $driversBasePath" will return $False
            # http://www.vistax64.com/powershell/2653-powershell-does-not-update-subst-mapped-drives.html
            Get-PSDrive | Out-Null
            Add-VirtIODrivers $vhdDriveLetter $image $driversBasePath
        } else {
            throw "The $isoPath is not a valid iso path."
        }
    } catch{
        Write-Host $_
    } finally {
        if ($v) {
            $v.DetachVirtualDisk()
            $v.Close()
        }
    }
}

function Set-DotNetCWD {
    # Make sure the PowerShell and .Net CWD match
    [Environment]::CurrentDirectory = (Get-Location -PSProvider FileSystem).ProviderPath
}

function Get-PathWithoutExtension {
    Param(
        [Parameter(Mandatory=$true)]
        [string]$Path
    )
    return Join-Path ([System.IO.Path]::GetDirectoryName($Path)) `
                     ([System.IO.Path]::GetFileNameWithoutExtension($Path))
}

function Compress-Image {
    Param(
        [Parameter(Mandatory=$true)]
        [string]$VirtualDiskPath,
        [Parameter(Mandatory=$true)]
        [string]$ImagePath
    )
    if (!(Test-Path $VirtualDiskPath)) {
        Throw "$VirtualDiskPath not found"
    }
    $tmpName = $ImagePath + "." + (Get-Random)

    $7zip = Get-7zipPath
    $pigz = Join-Path $localResourcesDir pigz.exe
    try {
        Write-Host "Archiving $VirtualDiskPath to tarfile $tmpName"
        pushd ([System.IO.Path]::GetDirectoryName((Resolve-path $VirtualDiskPath).Path))
        try {
            # Avoid storing the full path in the archive
            $imageFileName = (Get-Item $VirtualDiskPath).Name
            Write-Host "Creating tar archive..."
            & $7zip a -ttar $tmpName $imageFileName
            if ($LASTEXITCODE) {
                if ((Test-Path $imageFileName)) {
                    Remove-Item -Force $imageFileName
                }
                throw "7za.exe failed while creating tar file for image: $tmpName"
            }
        } finally {
            popd
        }

        Remove-Item -Force $VirtualDiskPath
        Write-Host "Compressing $tmpName to gzip"
        pushd ([System.IO.Path]::GetDirectoryName((Resolve-path $tmpName).Path))
        try {
            $tmpPathName = (Get-Item $tmpName).Name
            Write-Host "Creating gzip..."
            & $pigz -p12 $tmpPathName
            if ($LASTEXITCODE) {
                $gzipped = ($tmpPathName + ".gz")
                if ((Test-Path $gzipped)) {
                    Remove-Item -Force $gzipped
                }
                throw "pigz.exe failed while creating gzip file for : $tmpName"
            }
        } finally {
            popd
        }
    } catch {
        Remove-Item -Force $tmpName -ErrorAction SilentlyContinue
        Remove-Item -Force $VirtualDiskPath -ErrorAction SilentlyContinue
        throw
    }
    Move-Item ($tmpName + ".gz") $ImagePath
    Write-Output "MaaS image is ready and available at: $ImagePath"
}

function Start-Executable {
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory=$true)]
        [Alias("7za.exe")]
        [array]$Command
    )
    PROCESS {
        $cmdType = (Get-Command $Command[0]).CommandType
        if ($cmdType -eq "Application") {
            $ErrorActionPreference = "SilentlyContinue"
            $ret = & $Command[0] $Command[1..$Command.Length] 2>&1
            $ErrorActionPreference = "Stop"
        } else {
            $ret = & $Command[0] $Command[1..$Command.Length]
        }
        if ($cmdType -eq "Application" -and $LASTEXITCODE) {
            Throw ("Failed to run: " + ($Command -Join " "))
        }
        if ($ret -and $ret.Length -gt 0) {
            return $ret
        }
        return $false
    }
}

function Get-7zipPath {
    return Join-Path -Path "$localResourcesDir" -ChildPath "7za.exe"
}

function New-ProtectedZip {
    Param(
        [parameter(Mandatory=$true)]
        [string]$ZipPassword,
        [Parameter(Mandatory=$true)]
        [string]$VirtualDiskPath
    )
        $zipPath = (Get-PathWithoutExtension $VirtualDiskPath) + ".zip"
        $7zip = Get-7zip
        Write-Host "Creating protected zip"
        Start-Executable -Command @("$7zip", "a" , "-tzip", "$zipPath", `
                                    "$VirtualDiskPath", "-p$ZipPassword", "-mx1")
        Write-Host "The zip password is: $ZipPassword"
}
function Resize-VHDImage {
    <#
    .SYNOPSIS
     This function resizes the VHD image to a minimum VHD size plus a FreeSpace parameter value buffer.
    .DESCRIPTION
     This function mounts the VHD given as parameter and retrieves the drive letter. After that it computes
     the actual size and the minimum supported size.
    .PARAMETER VirtualDiskPath
     The path to the VHD image  to resize.
    .PARAMETER FreeSpace
     This is the extra buffer parameter.
    #>
    Param(
        [Parameter(Mandatory=$true)]
        [string]$VirtualDiskPath,
        [parameter(Mandatory=$false)]
        [Uint64]$FreeSpace=500MB
    )
    Write-Host "Shrinking VHD to minimum size"

    $vhdSize = (Get-VHD -Path $VirtualDiskPath).Size
    $vhdSizeGB = $vhdSize/1GB
    Write-Host "Initial VHD size is: $vhdSizeGB GB"

    $Drive = (Mount-VHD -Path $VirtualDiskPath -Passthru | Get-Disk | Get-Partition | Get-Volume).DriveLetter
    try
    {
        Optimize-Volume -DriveLetter $Drive -Defrag -ReTrim -SlabConsolidate

        $partitionInfo = Get-Partition -DriveLetter $Drive
        $MinSize = (Get-PartitionSupportedSize -DriveLetter $Drive).SizeMin
        $CurrSize = ((Get-Partition -DriveLetter $Drive).Size/1GB)
        Write-Host "Current partition size: $CurrSize GB"
        # Leave free space for making sure Sysprep finishes successfuly
        $newSizeGB = [int](($MinSize + $FreeSpace)/1GB) + 1
        $NewSize = $newSizeGB*1GB
        Write-Host "New partition size: $newSizeGB GB"

        if ($NewSize -gt $MinSize) {
            $global:i = 0
            $step = 100MB
            Execute-Retry {
                $sizeIncreased = ($NewSize + ($step * $global:i))
                Write-Host "Size increased: $sizeIncreased"
                $global:i = $global:i + 1
                Resize-Partition -DriveLetter $Drive -Size $sizeIncreased -ErrorAction "Stop"
            }
        }
    }
    finally
    {
        Dismount-VHD -Path $VirtualDiskPath
    }

    $vhdMinSize = (Get-VHD -Path $VirtualDiskPath).MinimumSize
    if ($vhdSize -gt $vhdMinSize) {
        Resize-VHD $VirtualDiskPath -ToMinimumSize
    }
    $FinalDiskSize = ((Get-VHD -Path $VirtualDiskPath).Size/1GB)
    Write-Host "Final disk size: $FinalDiskSize GB"
}

function Create-VirtualSwitch {
    Param(
        [Parameter(Mandatory=$false)]
        [string]$NetAdapterName,
        [Parameter(Mandatory=$false)]
        [string]$Name="br100"
    )

    if (!$NetAdapterName) {
        $defRoute = Get-NetRoute | Where-Object { $_.DestinationPrefix -eq "0.0.0.0/0" }
        if (!$defRoute) {
            Throw "Could not determine default route"
        }
        $details = $defRoute[0]
        $netAdapter = Get-NetAdapter -ifIndex $details.ifIndex -Physical:$true
        if (!$netAdapter) {
            Throw "Could not get physical interface for switch"
        }
        $NetAdapterName = $netAdapter.Name
    }
    $vSwitch = New-VMSwitch -Name $Name -NetAdapterName $NetAdapterName `
        -AllowManagementOS $true
    return $vSwitch
}

function Check-Prerequisites {
    $needsHyperV = Get-WindowsOptionalFeature -Online -FeatureName Microsoft-Hyper-V
    if ($needsHyperV.State -ne "Enabled") {
        throw $noHypervWarning
    }
}

function GetOrCreate-Switch {
    $vmSwitches = Get-VMSwitch -SwitchType external
    $vmswitch = $null
    if ($vmSwitches) {
        foreach ($i in $vmSwitches) {
            $name = $i.Name
            $netadapter = Get-NetAdapter -Name "vEthernet ($name)" -ErrorAction SilentlyContinue
            if (!$netadapter) { continue }
            if ($netadapter.Status -eq "Up") {
                $vmswitch = $i
                break
            }
        }
        if (!$vmswitch) {
            $vmswitch = Create-VirtualSwitch -Name "br100"
        }
    } else {
        $vmswitch = Create-VirtualSwitch -Name "br100"
    }
    if (!$vmswitch) {
        Throw "Count not retrieve VMSwitch"
    }
    return $vmswitch
}

function Wait-ForVMShutdown {
    Param(
        [Parameter(Mandatory=$true)]
        [string]$Name
    )
    Write-Output "Waiting for $Name to finish sysprep"
    $isOff = (Get-VM -Name $Name).State -eq "Off"
    while ($isOff -eq $false) {
        Start-Sleep 1
        $isOff = (Get-VM -Name $Name).State -eq "Off"
    }
}

function Run-Sysprep {
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
        [string]$VMSwitch,
        [ValidateSet("1", "2")]
        [string]$Generation = "1"
    )

    Write-Output "Creating VM $Name attached to $VMSwitch"
    New-VM -Name $Name -MemoryStartupBytes $Memory -SwitchName $VMSwitch `
        -VHDPath $VHDPath -Generation $Generation
    Set-VMProcessor -VMname $Name -count $CpuCores
    Write-Output "Starting $Name"
    Start-VM $Name
    Start-Sleep 5
    Wait-ForVMShutdown $Name
    Remove-VM $Name -Confirm:$false -Force
}

function New-WindowsOnlineImage {
    [CmdletBinding()]
    Param(
        [parameter(Mandatory=$false, ValueFromPipeline=$true)]
        [string]$ConfigFilePath =""
    )
    PROCESS
    {
        $CONFIG = Get-GlobalConfigs $ConfigFilePath
        Write-Host ("Windows online image generation started at: {0}" -f @(Get-Date))
        Is-Administrator
        if (!$CONFIG["run_sysprep"] -and !$CONFIG["force"]) {
            throw "You chose not to run sysprep.
                This will build an unusable MaaS image.
                If you really want to continue use the -Force:$true flag."
        }

        Check-Prerequisites
        if ($CONFIG["external_switch"]) {
            $switch = Get-VMSwitch -Name $CONFIG["external_switch"] -ErrorAction SilentlyContinue
            if (!$switch) {
                throw "Selected vmswitch {0} does not exist" -f $CONFIG["external_switch"]
            }
            if ($switch.SwitchType -ne "External" -and !$CONFIG["force"]) {
                throw "Selected switch {0}} is not an external
                    switch. If you really want to continue use the -Force:$true flag." -f $CONFIG["external_switch"]
            }
        } else {
            $switch = GetOrCreate-Switch
        }
        $cpuCount = 0
        $coreCount = (Get-WmiObject Win32_Processor).NumberOfLogicalProcessors
        foreach ($i in $coreCount) {
            $cpuCount += $i
        }
        if ($cpuCount -eq 0) {
            $cpuCount = 1
        }
        if ($CONFIG["cpu_count"] -gt $cpuCount) {
            Write-Warning "CpuCores larger then available (logical) CPU cores.
                Setting CpuCores to $coreCount"
            $CONFIG["cpu_count"] = $coreCount
        }

        try {
            $barePath = Get-PathWithoutExtension $CONFIG["image_path"]
            $VirtualDiskPath = $barePath + ".vhdx"
            $CONFIG["install_maas_hooks"] = $false
            if ($CONFIG["image_type"] -eq "MAAS") {
                $CONFIG["install_maas_hooks"] = $true
            }
            if ($CONFIG["image_type"] -eq "KVM") {
                $CONFIG["persist_drivers_install"] = $false
            }

            New-WindowsCloudImage -ConfigOptions $CONFIG
            if ($CONFIG["run_sysprep"]) {
                if($CONFIG["disk_layout"] -eq "UEFI") {
                    $generation = "2"
                } else {
                    $generation = "1"
                }

                $Name = "WindowsOnlineImage-Sysprep" + (Get-Random)
                Run-Sysprep -Name $Name -Memory $CONFIG["ram_size"] -VHDPath $VirtualDiskPath `
                    -VMSwitch $switch.Name -CpuCores $CONFIG["cpu_count"] `
                    -Generation $generation
            }

            Resize-VHDImage $VirtualDiskPath

            if ($CONFIG["image_type"] -eq "MAAS") {
                $RawImagePath = $barePath + ".img"
                Write-Host "Converting VHD to RAW"
                Convert-VirtualDisk $VirtualDiskPath $RawImagePath "RAW"
                Remove-Item -Force $VirtualDiskPath
                Compress-Image $RawImagePath $CONFIG['image_path']
            }

            if ($CONFIG["image_type"] -eq "KVM") {
                $Qcow2ImagePath = $barePath + ".qcow2"
                Write-Host "Converting VHD to QCow2"
                Convert-VirtualDisk $VirtualDiskPath $Qcow2ImagePath "qcow2"
                if ($ZipPassword) {
                    New-ProtectedZip -ZipPassword $ZipPassword -VirtualDiskPath $Qcow2ImagePath
                }
                Remove-Item -Force $VirtualDiskPath
            }
        } catch {
            Remove-Item -Force "$CONFIG['image_path']*" -ErrorAction SilentlyContinue
            Throw
        }
        Write-Host ("Windows online image generation finished at: {0}" -f @((Get-Date)))
    }

}

function New-WindowsCloudImage {
    [CmdletBinding()]
    param
    (
        [parameter(Mandatory=$false, ValueFromPipeline=$true)]
        [string]$ConfigOptions,
        [parameter(Mandatory=$false, ValueFromPipeline=$true)]
        [string]$ConfigFilePath    

    )
    PROCESS
    {
        if (!$ConfigOptions) {
            $ConfigOptions = Get-GlobalConfigs -ConfigFilePath $ConfigFilePath
        }
        Write-Host ("Image generation started at: {0}" -f @(Get-Date))
        Set-DotNetCWD
        Is-Administrator

        $image = Get-WimFileImagesInfo -WimFilePath $CONFIG["wim_file_path"] | `
            Where { $_.ImageName -eq $CONFIG["image_name"] }
        if (!$image) {
            throw 'Image "$CONFIG["image_name"]" not found in WIM file "$CONFIG["wim_file_path"]"'
        }
        Check-DismVersionForImage $image

        if (Test-Path $CONFIG["image_path"]) {
            Remove-Item -Force $CONFIG["image_path"]
        }

        if ($CONFIG["image_path"] -in @("VHD", "VHDX")) {
            $VHDPath = $CONFIG["image_path"]
        } else {
            $VHDPath = "{0}.vhd" -f (Get-PathWithoutExtension $CONFIG["image_path"])
            if (Test-Path $VHDPath) { Remove-Item -Force $VHDPath }
        }

        try {
            $drives = Create-ImageVirtualDisk $VHDPath $CONFIG["disk_size"] $CONFIG["disk_layout"]
            $winImagePath = "$($drives[1])\"
            $resourcesDir = "${winImagePath}UnattendResources"
            $outUnattendXmlPath = "${winImagePath}Unattend.xml"
            $configValues = @{
                "InstallUpdates"=$CONFIG["install_updates"];
                "PersistDriverInstall"=$CONFIG["persist_drivers_install"];
                "PurgeUpdates"=$CONFIG["purge_updates"];
                "DisableSwap"=$CONFIG["disable_swap"];
            }

            $xmlunattendPath = Join-Path $scriptPath $CONFIG['unattend_xml_path']
            $xmlParams = @{'InUnattendXmlPath' = $xmlunattendPath;
                           'OutUnattendXmlPath' = $outUnattendXmlPath;
                           'Image' = $image;
                           'AdministratorPassword' = $CONFIG["administrator_password"];
            }
            if ($CONFIG["product_key"]) {
                $xmlParams.Add('productKey', $CONFIG["product_key"]);
            }
            Generate-UnattendXml @xmlParams
            Copy-UnattendResources $resourcesDir $image.ImageInstallationType $CONFIG["install_maas_hooks"]
            Generate-ConfigFile $resourcesDir $configValues
            Download-CloudbaseInit $resourcesDir ([string]$image.ImageArchitecture)
            Apply-Image $winImagePath $CONFIG["wim_file_path"] $image.ImageIndex
            Create-BCDBootConfig $drives[0] $drives[1] $CONFIG["disk_layout"] $image
            Check-EnablePowerShellInImage $winImagePath $image

            if ($CONFIG["drivers_path"] -and (Test-Path $CONFIG["drivers_path"])) {
                Add-DriversToImage $winImagePath $CONFIG["drivers_path"]
            }
            if ($CONFIG["virtio_iso_path"]) {
                Add-VirtIODriversFromISO $winImagePath $image $CONFIG["virtio_iso_path"]
            }
            if ($CONFIG["virtio_base_path"]) {
                Add-VirtIODrivers $winImagePath $image $CONFIG["virtio_base_path"]
            }
            if ($CONFIG["extra_features"]) {
                Enable-FeaturesInImage $winImagePath $CONFIG["extra_features"]
            }
        } finally {
            if (Test-Path $VHDPath) {
                Detach-VirtualDisk $VHDPath
            }
        }

        if ($VHDPath -ne $CONFIG["image_path"]) {
            Convert-VirtualDisk $VHDPath $CONFIG["image_path"] $CONFIG["virtual_disk_format"]
            if ($ZipPassword) {
                New-ProtectedZip -ZipPassword $CONFIG["zip_password"] -VirtualDiskPath $CONFIG["image_path"]
            }
            Remove-Item -Force $VHDPath
        }
        Write-Host ("Image generation finished at: {0}" -f @(Get-Date))
    }
}

Export-ModuleMember New-WindowsCloudImage, Get-WimFileImagesInfo, New-MaaSImage, Resize-VHDImage,
    New-WindowsOnlineImage, Add-VirtIODriversFromISO, Get-GlobalConfigs
