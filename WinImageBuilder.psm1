# Copyright 2017 Cloudbase Solutions Srl
#
#    Licensed under the Apache License, Version 2.0 (the "License"); you may
#    not use this file except in compliance with the License. You may obtain
#    a copy of the License at
#
#         http://www.apache.org/licenses/LICENSE-2.0
#
#    Unless required by applicable law or agreed to in writing, software
#    distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
#    WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
#    License for the specific language governing permissions and limitations
#    under the License.
$ErrorActionPreference = "Stop"
Set-StrictMode -Version 2
Import-Module Dism
$scriptPath = Split-Path -Parent $MyInvocation.MyCommand.Definition
$localResourcesDir = "$scriptPath\UnattendResources"
Import-Module "$scriptPath\Config.psm1"
Import-Module "$scriptPath\UnattendResources\ini.psm1"

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

class PathShouldExistAttribute : System.Management.Automation.ValidateArgumentsAttribute {
    [void] Validate([object]$arguments, [System.Management.Automation.EngineIntrinsics]$engineIntrinsics) {
        if (!(Test-Path -Path $arguments)) {
            throw "Path ``$arguments`` not found."
        }
    }
}

function Write-Log($MessageToOut) {
    Write-Host $MessageToOut -ForegroundColor Blue -BackgroundColor Green (Get-Date)`n
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
        [string]$WimFilePath
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

Write-Log "Create Virtual Disk Image"
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

    Write-Log "Create BCDBoot Config"
    $bcdbootPath = "${windowsDrive}\windows\system32\bcdboot.exe"
    if (!(Test-Path $bcdbootPath)) {
        Write-Warning ('"{0}" not found, using online version' -f $bcdbootPath)
        $bcdbootPath = "bcdboot.exe"
    }

    # Note: older versions of bcdboot.exe don't have a /f argument
    if ($image.ImageVersion.Major -eq 6 -and $image.ImageVersion.Minor -lt 2) {
       $bcdbootOutput = & $bcdbootPath ${windowsDrive}\windows /s ${systemDrive} /v
    } else {
       $bcdbootOutput = & $bcdbootPath ${windowsDrive}\windows /s ${systemDrive} /v /f $diskLayout
    }
    if ($LASTEXITCODE) { throw "BCDBoot failed with error: $bcdbootOutput" }

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

    Write-Log "Generate Unattend Xml"
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
        [string]$format,
        [Parameter(Mandatory=$false)]
        [boolean]$CompressQcow2
    )

    Write-Log "Convert Virtual Disk"
    $compressParam = ""
    if ($format -eq "qcow2" -and $CompressQcow2) {
        Write-Host "Qcow2 compression has been enabled."
        $compressParam = "-c"
    }
    Write-Host "Converting virtual disk image from $vhdPath to $outPath..."
    Execute-Retry {
        & "$scriptPath\bin\qemu-img.exe" convert $compressParam -O $format.ToLower() $vhdPath $outPath
        if($LASTEXITCODE) { throw "qemu-img failed to convert the virtual disk" }
    }
}

function Copy-CustomResources {
    Param(
        [Parameter(Mandatory=$true)]
        [string]$ResourcesDir,
        [string]$CustomResources,
        [string]$CustomScripts
        )

    Write-Log "Copy Custom Resources"
    if (!(Test-Path "$resourcesDir")) {
        $d = New-Item -Type Directory $resourcesDir
    }
    if ($CustomResources) {
        if (!(Test-Path "$resourcesDir\CustomResources")) {
            $d = New-Item -Type Directory "$resourcesDir\CustomResources"
        }
        Write-Host "Copying: $CustomResources $resourcesDir"
        Copy-Item -Recurse "$CustomResources\*" "$resourcesDir\CustomResources"
    }
    if ($CustomScripts) {
        if (!(Test-Path "$resourcesDir\CustomScripts")) {
            $d = New-Item -Type Directory "$resourcesDir\CustomScripts"
        }
        Write-Host "Copying: $CustomScripts $resourcesDir"
        Copy-Item -Recurse "$CustomScripts\*" "$resourcesDir\CustomScripts"
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

    Write-Log "Copy Unattend Resources"
    # Workaround to recognize the $resourcesDir drive. This seems a PowerShell bug
    Get-PSDrive | Out-Null

    if (!(Test-Path "$resourcesDir")) {
        $d = New-Item -Type Directory $resourcesDir
    }
    Write-Host "Copying: $localResourcesDir $resourcesDir"
    Copy-Item -Recurse "$localResourcesDir\*" $resourcesDir

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
        [string]$osArch,
        [parameter(Mandatory=$false)]
        [switch]$BetaRelease,
        [parameter(Mandatory=$false)]
        [string]$MsiPath
    )
    $CloudbaseInitMsiPath = "$resourcesDir\CloudbaseInit.msi"
    if ($MsiPath) {
        if (!(Test-Path $MsiPath)) {
            throw "Cloudbase-Init installer could not be copied. $MsiPath does not exist."
        }
        Write-Host "Copying Cloudbase-Init..."
        Copy-Item $MsiPath $CloudbaseInitMsiPath
        return
    }
    Write-Host "Downloading Cloudbase-Init..."
    $msiBuildArchMap = @{
        "amd64" = "x64"
        "i386" = "x86"
        "x86" = "x86"
    }
    $msiBuildSuffix = ""
    if (-not $BetaRelease) {
        $msiBuildSuffix = "_Stable"
    }
    $CloudbaseInitMsi = "CloudbaseInitSetup{0}_{1}.msi" -f @($msiBuildSuffix, $msiBuildArchMap[$osArch])
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
    Write-Log "Generate config file"
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
    Write-Log "Getting Virtual IO Drivers"
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
    Write-Log "Adding Virtual IO Drivers"
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
    Write-Log "Adding Virtual IO Drivers from ISO"
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
    Write-Log "Compress Image"
    if (!(Test-Path $VirtualDiskPath)) {
        Throw "$VirtualDiskPath not found"
    }
    $tmpName = '{0}.tar' -f @((Get-PathWithoutExtension($ImagePath)))

    $7zip = Get-7zipPath
    $pigz = Get-PigzPath
    try {
        Write-Host "Archiving $VirtualDiskPath to tarfile $tmpName"
        Push-Location ([System.IO.Path]::GetDirectoryName((Resolve-path $VirtualDiskPath).Path))
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
            Pop-Location
        }

        Remove-Item -Force $VirtualDiskPath
        Write-Host "Compressing $tmpName to gzip"
        Push-Location ([System.IO.Path]::GetDirectoryName((Resolve-path $tmpName).Path))
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
            Pop-Location
        }
    } catch {
        Remove-Item -Force $tmpName -ErrorAction SilentlyContinue
        Remove-Item -Force $VirtualDiskPath -ErrorAction SilentlyContinue
        throw
    }
    if (Test-Path $ImagePath) {
        throw "File $ImagePath already exists. The image has been created at $tmpName."
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
    Write-Log "Star Executable"
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

function Get-PigzPath {
    return Join-Path -Path "$localResourcesDir" -ChildPath "pigz.exe"
}

function New-ProtectedZip {
    Param(
        [parameter(Mandatory=$true)]
        [string]$ZipPassword,
        [Parameter(Mandatory=$true)]
        [string]$VirtualDiskPath
    )
        $zipPath = (Get-PathWithoutExtension $VirtualDiskPath) + ".zip"
        $7zip = Get-7zipPath
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
    Write-Log "Create Virtual Switch"
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
        [string]$VhdPath,
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
        -VhdPath $VhdPath -Generation $Generation
    Set-VMProcessor -VMname $Name -count $CpuCores
    Write-Output "Starting $Name"
    Start-VM $Name
    Start-Sleep 5
    Wait-ForVMShutdown $Name
    Remove-VM $Name -Confirm:$false -Force
}

function Get-ImageInformation {
    Param(
        [Parameter(Mandatory=$true)]
        [string]$DriveLetter,
        [Parameter(Mandatory=$true)]
        [string]$ImageName
    )

    $ntDll = "$driveLetter\Windows\system32\ntdll.dll"
    if (Test-Path $ntDll) {
        $versionString = (Get-Item $ntDll).VersionInfo.ProductVersion
        $osVersion = $versionString.split('.')
        $imageVersion = @{
            "Major" = $osVersion[0];
            "Minor" = $osVersion[1];
        }
    } else {
        throw "Unable to determine OS Version"
    }

    if ((Get-Item $ntDll).Target -like "*amd64_microsoft-windows-ntdll*") {
        $imageArchitecture = "AMD64"
    } else {
        $imageArchitecture = "i386"
    }

    if ($imageName -like '*Core') {
        $imageInstallationType = "Server Core"
    } else {
        $imageInstallationType = "Server"
    }

    return $image = @{
        "imageVersion" = $imageVersion;
        "imageArchitecture" = $imageArchitecture;
        "imageInstallationType" = $imageInstallationType;
    }
}

function Set-WindowsWallpaper {
    Param(
        [Parameter(Mandatory=$true)][PathShouldExist()]
        [string]$winDrive,
        [Parameter(Mandatory=$false)]
        [string]$WallpaperPath
    )
    Write-Log "Set Wallpaper"
    if (!$WallpaperPath -or !(@('.jpg', '.jpeg') -contains `
            (Get-Item $windowsImageConfig.wallpaper_path -ErrorAction SilentlyContinue).Extension)) {
        $WallpaperPath = Join-Path $localResourcesDir "Wallpaper.jpg"
    }
    if (!(Test-Path $WallpaperPath)) {
        throw "Walpaper path ``$WallpaperPath`` does not exist."
    }
    $wallpaperDestinationFolder = Join-Path $winDrive "\Windows\web\Wallpaper\Cloud"
    if (!(Test-Path $wallpaperDestinationFolder)) {
       New-Item -Type Directory $wallpaperDestinationFolder | Out-Null
    }
    Copy-Item -Force $WallpaperPath "$wallpaperDestinationFolder\Wallpaper.jpg"
    Write-Host "Wallpaper copied to the image."

    $wallpaperGPOPath = Join-Path $localResourcesDir "GPO"
    $windowsLocalGPOPath = Join-Path $winDrive "\Windows\System32\GroupPolicy"
    if (!(Test-Path $windowsLocalGPOPath)) {
       New-Item -Type Directory $windowsLocalGPOPath | Out-Null
    }
    Copy-Item -Recurse -Force "$wallpaperGPOPath\*" "$windowsLocalGPOPath\"
    Write-Host "Wallpaper GPO copied to the image."

    # Note(avladu) if the image already has been booted and has a wallpaper, the
    # GPO will not be applied for the users who have already logged in.
    # The wallpaper can still be changed by replacing the cached one.
    $cachedWallpaperPartPath = "\Users\Administrator\AppData\Roaming\Microsoft\Windows\Themes\TranscodedWallpaper*"
    $cachedWallpaperPath = Join-Path -ErrorAction SilentlyContinue $winDrive $cachedWallpaperPartPath
    if (Test-Path $cachedWallpaperPath) {
        $wallpaperPathFullName = (Get-Item $cachedWallpaperPath).FullName
        Remove-Item -Recurse -Force ((Get-Item $cachedWallpaperPath).DirectoryName + "\*")
        Copy-Item -Force $WallpaperPath $wallpaperPathFullName
        Write-Host "Cached wallpaper for user Administrator has been replaced."
    }
}

function New-WindowsOnlineImage {
    <#
    .SYNOPSIS
     This function generates a Windows image using Hyper-V  to instantiate the image in
     order to apply the updates and install cloudbase-init.
    .DESCRIPTION
     This command requires Hyper-V to be enabled, a VMSwitch to be configured for external
     network connectivity if the updates are to be installed, which is highly recommended.
     This command uses internally the New-WindowsCloudImage to generate the base image and
     start a Hyper-V instance using the base image. After the Hyper-V instance shuts down,
     the resulting VHDX is shrunk to a minimum size and converted to the required format.

     The list of parameters can be found in the Config.psm1 file.
    #>
    Param(
        [parameter(Mandatory=$true, ValueFromPipeline=$true)]
        [string]$ConfigFilePath
    )
    $windowsImageConfig = Get-WindowsImageConfig -ConfigFilePath $ConfigFilePath

    if ($windowsImageConfig.gold_image) {
        if  (($windowsImageConfig.image_type -ne 'HYPER-V') -or `
            (!$windowsImageConfig.virtual_disk_format -in @("VHD","VHDX")) -or `
            (![System.IO.Path]::GetExtension($windowsImageConfig.image_path) -in @(".vhd",".vhdx"))) {
            throw "A golden image file should have a vhd(x) extension/disk`
                   format and the image_type should be HYPER-V."
        }
    }

    Write-Host ("Windows online image generation started at: {0}" -f @(Get-Date))
    Is-Administrator
    if (!$windowsImageConfig.run_sysprep -and !$windowsImageConfig.force) {
        throw "You chose not to run sysprep.
            This will build an unusable Windows image.
            If you really want to continue use the `force = true` config option."
    }

    Check-Prerequisites
    if ($windowsImageConfig.external_switch) {
        $switch = Get-VMSwitch -Name $windowsImageConfig.external_switch -ErrorAction SilentlyContinue
        if (!$switch) {
            throw "Selected vmswitch {0} does not exist" -f $windowsImageConfig.external_switch
        }
        if ($switch.SwitchType -ne "External" -and !$windowsImageConfig.force) {
            throw "Selected switch {0}} is not an external
                switch. If you really want to continue use the `force = true` flag." `
                -f $windowsImageConfig.external_switch
        }
    }
    if ($windowsImageConfig.cpu_count -gt `
        (Get-WmiObject Win32_Processor).NumberOfLogicalProcessors) {
        throw "CpuCores larger then available (logical) CPU cores."
    }

    if (Test-Path $windowsImageConfig.image_path) {
        Write-Host "Found already existing image file. Removing it..." -ForegroundColor Yellow
        Remove-Item -Force $windowsImageConfig.image_path
        Write-Host "Already existent image file has been removed." -ForegroundColor Yellow
    }

    try {
        $barePath = Get-PathWithoutExtension $windowsImageConfig.image_path
        $virtualDiskPath = $barePath + ".vhdx"

        # We need different config files for New-WindowsCloudImage and New-WindowsOnlineImage
        $offlineConfigFilePath = $ConfigFilePath + ".offline"
        Copy-Item -Path $ConfigFilePath -Destination $offlineConfigFilePath
        Set-IniFileValue -Path $offlineConfigFilePath -Section 'DEFAULT' -Key 'image_path' `
                -Value $virtualDiskPath
        Set-IniFileValue -Path $offlineConfigFilePath -Section 'DEFAULT' -Key 'virtual_disk_format' `
                -Value 'VHDX'
        if ($windowsImageConfig.zip_password) {
            Remove-IniFileValue -Path $offlineConfigFilePath `
                -Key 'zip_password' -Section 'DEFAULT'
        }
        New-WindowsCloudImage -ConfigFilePath $offlineConfigFilePath

        if ($windowsImageConfig.run_sysprep) {
            if($windowsImageConfig.disk_layout -eq "UEFI") {
                $generation = "2"
            } else {
                $generation = "1"
            }

            $Name = "WindowsOnlineImage-Sysprep" + (Get-Random)
            Run-Sysprep -Name $Name -Memory $windowsImageConfig.ram_size -vhdPath $virtualDiskPath `
                -VMSwitch $switch.Name -CpuCores $windowsImageConfig.cpu_count `
                -Generation $generation
        }
        Resize-VHDImage $virtualDiskPath

        if ($windowsImageConfig.image_type -eq "MAAS") {
            $rawImagePath = $barePath + ".img"
            Write-Host "Converting VHD to RAW"
            Convert-VirtualDisk $virtualDiskPath $rawImagePath "raw"
            Remove-Item -Force $virtualDiskPath
            Compress-Image $rawImagePath $windowsImageConfig['image_path']
        }

        if ($windowsImageConfig.image_type -eq "KVM") {
            $qcow2ImagePath = $barePath + ".qcow2"
            Write-Host "Converting VHD to Qcow2"
            Convert-VirtualDisk $virtualDiskPath $qcow2ImagePath "qcow2" $windowsImageConfig.compress_qcow2
            if ($windowsImageConfig.zip_password) {
                New-ProtectedZip -ZipPassword $windowsImageConfig.zip_password -VirtualDiskPath $qcow2ImagePath
            }
            Remove-Item -Force $virtualDiskPath
        }
    } catch {
        Write-host $_
        if ($windowsImageConfig.image_path -and (Test-Path $windowsImageConfig.image_path)) {
            Remove-Item -Force $windowsImageConfig.image_path -ErrorAction SilentlyContinue
        }
        Throw
    }
    Write-Host ("Windows online image generation finished at: {0}" -f @((Get-Date)))
}

function New-WindowsCloudImage {
    <#
    .SYNOPSIS
     This function creates a Windows Image, starting from an ISO file, without the need
     of Hyper-V to be enabled. The image, to become ready for cloud usage, needs to be
     started on a hypervisor and it will automatically shut down when it finishes all the
     operations needed to become cloud ready: cloudbase-init installation, updates and sysprep.
    .DESCRIPTION
     This script can generate a Windows Image in one of the following formats: VHD,
     VHDX, QCow2, VMDK or RAW. It takes the Windows flavor indicated by the ImageName
     from the WIM file and based on the parameters given, it will generate an image.
     This function does not require Hyper-V to be enabled, but the generated image
     is not ready to be deployed, as it needs to be started manually on another hypervisor.
     The image is ready to be used when it shuts down.

     The list of parameters can be found in the Config.psm1 file.
    #>
    param
    (
        [parameter(Mandatory=$true, ValueFromPipeline=$true)]
        [string]$ConfigFilePath
    )
    Write-Host ("Image generation started at: {0}" -f @(Get-Date))

    $windowsImageConfig = Get-WindowsImageConfig -ConfigFilePath $ConfigFilePath
    Set-DotNetCWD
    Is-Administrator
    $image = Get-WimFileImagesInfo -WimFilePath $windowsImageConfig.wim_file_path | `
        Where-Object { $_.ImageName -eq $windowsImageConfig.image_name }
    if (!$image) {
        throw ("Image {0} not found in WIM file {1}" -f @($windowsImageConfig.image_name, $windowsImageConfig.wim_file_path))
    }
    Check-DismVersionForImage $image

    if (Test-Path $windowsImageConfig.image_path) {
        Write-Host "Found already existing image file. Removing it..." -ForegroundColor Yellow
        Remove-Item -Force $windowsImageConfig.image_path
        Write-Host "Already existent image file has been removed." -ForegroundColor Yellow
    }

    $vhdPath = "{0}.vhdx" -f (Get-PathWithoutExtension $windowsImageConfig.image_path)
    if (Test-Path $vhdPath) {
        Remove-Item -Force $vhdPath
    }

    try {
        $drives = Create-ImageVirtualDisk $vhdPath $windowsImageConfig.disk_size $windowsImageConfig.disk_layout
        $winImagePath = "$($drives[1])\"
        $resourcesDir = "${winImagePath}UnattendResources"
        $outUnattendXmlPath = "${winImagePath}Unattend.xml"
        $xmlunattendPath = Join-Path $scriptPath $windowsImageConfig['unattend_xml_path']
        $xmlParams = @{'InUnattendXmlPath' = $xmlunattendPath;
                       'OutUnattendXmlPath' = $outUnattendXmlPath;
                       'Image' = $image;
                       'AdministratorPassword' = $windowsImageConfig.administrator_password;
        }
        if ($windowsImageConfig.product_key) {
            $xmlParams.Add('productKey', $windowsImageConfig.product_key);
        }
        Generate-UnattendXml @xmlParams
        Copy-UnattendResources $resourcesDir $image.ImageInstallationType $windowsImageConfig.install_maas_hooks
        Copy-CustomResources -ResourcesDir $resourcesDir -CustomResources $windowsImageConfig.custom_resources_path `
                             -CustomScripts $windowsImageConfig.custom_scripts_path
        Copy-Item $ConfigFilePath "$resourcesDir\config.ini"
        Set-WindowsWallpaper $winImagePath $windowsImageConfig.wallpaper_path
        Download-CloudbaseInit $resourcesDir ([string]$image.ImageArchitecture) -BetaRelease:$windowsImageConfig.beta_release `
                               $windowsImageConfig.msi_path
        Apply-Image $winImagePath $windowsImageConfig.wim_file_path $image.ImageIndex
        Create-BCDBootConfig $drives[0] $drives[1] $windowsImageConfig.disk_layout $image
        Check-EnablePowerShellInImage $winImagePath $image

        if ($windowsImageConfig.drivers_path -and (Test-Path $windowsImageConfig.drivers_path)) {
            Add-DriversToImage $winImagePath $windowsImageConfig.drivers_path
        }
        if ($windowsImageConfig.virtio_iso_path) {
            Add-VirtIODriversFromISO $winImagePath $image $windowsImageConfig.virtio_iso_path
        }
        if ($windowsImageConfig.virtio_base_path) {
            Add-VirtIODrivers $winImagePath $image $windowsImageConfig.virtio_base_path
        }
        if ($windowsImageConfig.extra_features) {
            Enable-FeaturesInImage $winImagePath $windowsImageConfig.extra_features
        }
    } finally {
        if (Test-Path $vhdPath) {
            Detach-VirtualDisk $vhdPath
        }
    }

    if (!($windowsImageConfig.virtual_disk_format -in @("VHD", "VHDX"))) {
        Convert-VirtualDisk $vhdPath $windowsImageConfig.image_path `
            $windowsImageConfig.virtual_disk_format
        Remove-Item -Force $vhdPath
    } elseif ($vhdPath -ne $windowsImageConfig.image_path) {
        Move-Item -Force $vhdPath $windowsImageConfig.image_path
    }

    if ($windowsImageConfig.zip_password) {
        New-ProtectedZip -ZipPassword $windowsImageConfig.zip_password `
            -virtualDiskPath $windowsImageConfig.image_path
    }
    Write-Host ("Image generation finished at: {0}" -f @(Get-Date))
}

function New-WindowsFromGoldenImage {
    <#
    .SYNOPSIS
     This function creates a functional Windows Image, starting from an already
     generated golden image. It will be started on Hyper-V and it will automatically
     shut down when it finishes all the operations needed to become cloud ready:
     cloudbase-init installation, updates and sysprep.
    .DESCRIPTION
     This function can generated a cloud ready Windows image starting from a golden
     image. The resulting image can have the following formats: VHD,VHDX, QCow2,
     VMDK or RAW.

     This command requires Hyper-V to be enabled, a VMSwitch to be configured for external
     network connectivity if the updates are to be installed, which is highly recommended.
     This command uses internally the New-WindowsOnlineImage to start a Hyper-V instance using
     the golden image provided as a parameter. After the Hyper-V instance shuts down,
     the resulting VHDX is shrunk to a minimum size and converted to the required format.
     #>
    [CmdletBinding()]
    Param(
        [parameter(Mandatory=$true, ValueFromPipeline=$true)]
        [string]$ConfigFilePath
    )

    $windowsImageConfig = Get-WindowsImageConfig -ConfigFilePath $ConfigFilePath
    Write-Host ("Windows online image generation started at: {0}" -f @(Get-Date))
    Is-Administrator
    if (!$windowsImageConfig.run_sysprep -and !$windowsImageConfig.force) {
        throw "You chose not to run sysprep.
            This will build an unusable Windows image.
            If you really want to continue use the `force = true` config option."
    }

    Check-Prerequisites
    if ($windowsImageConfig.external_switch) {
        $switch = Get-VMSwitch -Name $windowsImageConfig.external_switch -ErrorAction SilentlyContinue
        if (!$switch) {
            throw "Selected vmswitch {0} does not exist" -f $windowsImageConfig.external_switch
        }
        if ($switch.SwitchType -ne "External" -and !$windowsImageConfig.force) {
            throw "Selected switch {0} is not an external
                switch. If you really want to continue use the `force = true` flag." `
                -f $windowsImageConfig.external_switch
        }
    }
    if ($windowsImageConfig.cpu_count -gt `
        (Get-WmiObject Win32_Processor).NumberOfLogicalProcessors) {
        throw "CpuCores larger than available (logical) CPU cores."
    }

    try {
        Execute-Retry {
            Resize-VHD -Path $windowsImageConfig.gold_image_path -SizeBytes $windowsImageConfig.disk_size
        }

        Mount-VHD -Path $windowsImageConfig.gold_image_path -Passthru | Out-Null
        Get-PSDrive | Out-Null

        $driveLetterGold = (Get-DiskImage -ImagePath $windowsImageConfig.gold_image_path | Get-Disk | Get-Partition |`
            Get-Volume).DriveLetter + ":"

        $driveNumber = (Get-DiskImage -ImagePath $windowsImageConfig.gold_image_path | Get-Disk).Number
        $maxPartitionSize = (Get-PartitionSupportedSize -DiskNumber $driveNumber -PartitionNumber 1).SizeMax
        Resize-Partition -DiskNumber $driveNumber -PartitionNumber 1 -Size $maxPartitionSize

        $imageInfo = Get-ImageInformation $driveLetterGold -ImageName $windowsImageConfig.image_name
        if ($windowsImageConfig.virtio_iso_path) {
            Add-VirtIODriversFromISO $driveLetterGold $imageInfo $windowsImageConfig.virtio_iso_path
        }

        if ($windowsImageConfig.drivers_path -and (Get-ChildItem $windowsImageConfig.drivers_path)) {
            Dism.exe /Image:$driveLetterGold /Add-Driver /Driver:$windowsImageConfig.drivers_path `
                /ForceUnsigned /Recurse
            if ($LASTEXITCODE) {
                throw ("Failed to install drivers from {0}" -f @($windowsImageConfig.drivers_path))
            }
        }

        $resourcesDir = Join-Path -Path $driveLetterGold -ChildPath "UnattendResources"
        Copy-UnattendResources -resourcesDir $resourcesDir -imageInstallationType $windowsImageConfig.image_name
        Copy-CustomResources -ResourcesDir $resourcesDir -CustomResources $windowsImageConfig.custom_resources_path `
                             -CustomScripts $windowsImageConfig.custom_scripts_path
        Copy-Item $ConfigFilePath "$resourcesDir\config.ini"
        Set-WindowsWallpaper $driveLetterGold $windowsImageConfig.wallpaper_path
        Download-CloudbaseInit $resourcesDir $imageInfo.imageArchitecture -BetaRelease:$windowsImageConfig.beta_release `
                               $windowsImageConfig.msi_path
        Dismount-VHD -Path $windowsImageConfig.gold_image_path

        $Name = "WindowsGoldImage-Sysprep" + (Get-Random)

        New-VM -Name $Name -MemoryStartupBytes $windowsImageConfig.ram_size -SwitchName $switch.Name `
            -VHDPath $windowsImageConfig.gold_image_path
        Set-VMProcessor -VMname $Name -count $windowsImageConfig.cpu_count

        Start-VM $Name
        Start-Sleep 10
        Wait-ForVMShutdown $Name
        Remove-VM $Name -Confirm:$False -Force

        Resize-VHDImage $windowsImageConfig.gold_image_path

        $barePath = Get-PathWithoutExtension $windowsImageConfig.image_path

        if ($windowsImageConfig.image_type -eq "MAAS") {
            $RawImagePath = $barePath + ".img"
            Write-Output "Converting VHD to RAW"
            Convert-VirtualDisk $windowsImageConfig.gold_image_path $RawImagePath "RAW"
            Remove-Item -Force $windowsImageConfig.gold_image_path
            Compress-Image $RawImagePath $windowsImageConfig.image_path
        }
        if ($windowsImageConfig.image_type -eq "KVM") {
            $Qcow2ImagePath = $barePath + ".qcow2"
            Write-Output "Converting VHD to QCow2"
            Convert-VirtualDisk $windowsImageConfig.gold_image_path $Qcow2ImagePath "qcow2"
            Remove-Item -Force $windowsImageConfig.gold_image_path
        }
    } catch {
      Write-Host $_
      try {
        Get-VHD $windowsImageConfig.gold_image_path | Dismount-VHD
      } catch {
        Write-Host $_
      }
    }
}

Export-ModuleMember New-WindowsCloudImage, Get-WimFileImagesInfo, New-MaaSImage, Resize-VHDImage,
    New-WindowsOnlineImage, Add-VirtIODriversFromISO, New-WindowsFromGoldenImage
