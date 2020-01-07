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
$kmsProductKeysFile = "$scriptPath\kms_product_keys.json"
Import-Module "$scriptPath\Config.psm1"
Import-Module "$scriptPath\UnattendResources\ini.psm1"

# Enforce Tls1.2, as GitHub and more websites require it.
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

$noHypervWarning = @"
The Hyper-V role is missing from this machine. In order to be able to finish
generating the image, you need to install the Hyper-V role.

You can do so by running the following commands from an elevated powershell
command prompt:
Enable-WindowsOptionalFeature -Online -FeatureName Microsoft-Hyper-V -All -NoRestart
Enable-WindowsOptionalFeature -Online -FeatureName Microsoft-Hyper-V-Management-PowerShell -All -NoRestart

Don't forget to reboot after you install the Hyper-V role.
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

$AvailableCompressionFormats = @("tar","gz","zip")

. "$scriptPath\Interop.ps1"

class PathShouldExistAttribute : System.Management.Automation.ValidateArgumentsAttribute {
    [void] Validate([object]$arguments, [System.Management.Automation.EngineIntrinsics]$engineIntrinsics) {
        if (!(Test-Path -Path $arguments)) {
            throw "Path ``$arguments`` not found."
        }
    }
}

function Write-Log {
    Param($messageToOut)
    Write-Host ("{0} - {1}" -f @((Get-Date), $messageToOut))
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

    Write-Log "Creating Virtual Disk Image: $VhdPath..."
    $v = [WIMInterop.VirtualDisk]::CreateVirtualDisk($VhdPath, $Size)
    try {
        $v.AttachVirtualDisk()
        $path = $v.GetVirtualDiskPhysicalPath()
        # -match creates an env variable called $Matches
        $path -match "\\\\.\\PHYSICALDRIVE(?<num>\d+)" | Out-Null
        $diskNum = $Matches["num"]
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
            New-Partition -DiskNumber $diskNum -Size 128MB `
                -GptType '{e3c9e316-0b5c-4db8-817d-f92df00215ae}' | Out-Null
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

        Format-Volume -DriveLetter $windowsPart.DriveLetter `
            -FileSystem NTFS -NewFileSystemLabel $volumeLabel `
            -Force -Confirm:$false | Out-Null
        return @("$($systemPart.DriveLetter):", "$($windowsPart.DriveLetter):")
    } finally {
        Write-Log "Successfuly created disk: $VhdPath"
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
    Write-Log ('Applying Windows image "{0}" in "{1}"' -f $wimFilePath, $winImagePath)
    #Expand-WindowsImage -ImagePath $wimFilePath -Index $imageIndex -ApplyPath $winImagePath
    # Use Dism in place of the PowerShell equivalent for better progress update
    # and for ease of interruption with CTRL+C
    & Dism.exe /apply-image /imagefile:${wimFilePath} /index:${imageIndex} /ApplyDir:${winImagePath}
    if ($LASTEXITCODE) { throw "Dism apply-image failed" }
}

function Reset-BCDSearchOrder {
    Param(
        [parameter(Mandatory=$true)]
        [string]$systemDrive,
        [parameter(Mandatory=$true)]
        [string]$windowsDrive,
        [parameter(Mandatory=$true)]
        [string]$diskLayout
    )

    if ($diskLayout -eq "BIOS") {
        Write-Log "Resetting BCD boot border"
        $ErrorActionPreference = "SilentlyContinue"
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
        $ErrorActionPreference = "Stop"
    }
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

    Write-Log ("Create BCDBoot Config for {0}" -f @($image.ImageName))
    $bcdbootLocalPath = "bcdboot.exe"
    $bcdbootPath = "${windowsDrive}\windows\system32\bcdboot.exe"
    if (!(Test-Path $bcdbootPath)) {
        Write-Warning ('"{0}" not found, using online version' -f $bcdbootPath)
        $bcdbootPath = $bcdbootLocalPath
    }

    $ErrorActionPreference = "SilentlyContinue"
    # Note: older versions of bcdboot.exe don't have a /f argument
    if ($image.ImageVersion.Major -eq 6 -and $image.ImageVersion.Minor -lt 2) {
       $bcdbootOutput = & $bcdbootPath ${windowsDrive}\windows /s ${systemDrive} /v
       # Note(avladu): Retry using the local bcdboot path
       # when generating Win7 images on Win10 / Server 2k16 hosts
       if ($LASTEXITCODE) {
           Write-Log "Retrying with bcdboot.exe from host"
           $bcdbootOutput = & $bcdbootLocalPath ${windowsDrive}\windows /s ${systemDrive} /v /f $diskLayout
       }
    } else {
       $bcdbootOutput = & $bcdbootPath ${windowsDrive}\windows /s ${systemDrive} /v /f $diskLayout
    }
    if ($LASTEXITCODE) {
        $ErrorActionPreference = "Stop"
        throw "BCDBoot failed with error: $bcdbootOutput"
    }

    Reset-BCDSearchOrder -systemDrive $systemDrive -windowsDrive $windowsDrive `
        -diskLayout $diskLayout

    $ErrorActionPreference = "Stop"
    Write-Log "BCDBoot config has been created."
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

    Write-Log "Generate Unattend Xml :$outUnattendXmlPath..."
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

    Transform-Xml -xsltPath "$scriptPath\Unattend.xslt" -inXmlPath $inUnattendXmlPath `
        -outXmlPath $outUnattendXmlPath -xsltArgs $xsltArgs
    Write-Log "Xml was generated."
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

    Write-Log "Convert Virtual Disk: $vhdPath..."
    $format = $format.ToLower()
    $qemuParams = @("$scriptPath\bin\qemu-img.exe", "convert")
    if ($format -eq "qcow2" -and $CompressQcow2) {
        Write-Log "Qcow2 compression has been enabled."
        $qemuParams += @("-c", "-W", "-m16")
    }
    $qemuParams += @("-O", $format, $vhdPath, $outPath)
    Write-Log "Converting virtual disk image from $vhdPath to $outPath..."
    Execute-Retry {
        Start-Executable $qemuParams
    }
    Write-Log "Finish to convert virtual disk."
}

function Copy-CustomResources {
    Param(
        [Parameter(Mandatory=$true)]
        [string]$ResourcesDir,
        [string]$CustomResources,
        [string]$CustomScripts
        )

    Write-Log "Copy Custom Resources: $CustomResources..."
    if (!(Test-Path "$resourcesDir")) {
        New-Item -Type Directory $resourcesDir | Out-Null
    }
    if ($CustomResources) {
        if (!(Test-Path "$resourcesDir\CustomResources")) {
            New-Item -Type Directory "$resourcesDir\CustomResources" | Out-Null
        }
        Write-Log "Copying: $CustomResources $resourcesDir"
        # Custom resources can be multiple directories, split by ","
        $customResourcesSplit = $CustomResources.split(",")
        foreach ($customResource in $customResourcesSplit) {
            Copy-Item -Recurse "$customResource\*" "$resourcesDir\CustomResources"
        }
    }
    if ($CustomScripts) {
        if (!(Test-Path "$resourcesDir\CustomScripts")) {
            New-Item -Type Directory "$resourcesDir\CustomScripts" | Out-Null
        }
        Write-Log "Copying: $CustomScripts $resourcesDir"
        # Custom scripts can be multiple directories, split by ","
        $customScriptsSplit = $CustomScripts.split(",")
        foreach ($customScript in $customScriptsSplit) {
            Copy-Item -Recurse "$customScript\*" "$resourcesDir\CustomScripts"
        }
    }
    Write-Log "Custom Resources at: $ResourcesDir."
}


function Copy-UnattendResources {
    Param(
        [Parameter(Mandatory=$true)]
        [string]$resourcesDir,
        [Parameter(Mandatory=$true)]
        [string]$imageInstallationType,
        [Parameter(Mandatory=$false)]
        [boolean]$InstallMaaSHooks,
        [Parameter(Mandatory=$false)]
        [string]$VMwareToolsPath
    )

    Write-Log "Copy Unattend Resources: $imageInstallationType..."
    # Workaround to recognize the $resourcesDir drive. This seems a PowerShell bug
    Get-PSDrive | Out-Null

    if (!(Test-Path "$resourcesDir")) {
        New-Item -Type Directory $resourcesDir | Out-Null
    }
    Write-Log "Copying: $localResourcesDir $resourcesDir"
    Copy-Item -Recurse -Force "$localResourcesDir\*" $resourcesDir

    if ($InstallMaaSHooks) {
        $src = Join-Path $localResourcesDir "windows-curtin-hooks\curtin"
        if ((Test-Path $src)) {
            $dst = Split-Path $resourcesDir
            Copy-Item -Recurse $src $dst
        } else {
            throw "The Windows curtin hooks module is not present.
                Please run git submodule update --init " }
    }

    if ($VMwareToolsPath) {
        Write-Log "Copying VMwareTools..."
        $dst = Join-Path $resourcesDir "\VMware-tools.exe"
        Write-Log "VMware tools path is: $VMwareToolsPath"
        Copy-Item $VMwareToolsPath $dst
    }
    Write-Log "Resources have been copied."
}

function Validate-WindowsImageConfig {
    Param(
        [Parameter(Mandatory=$true)]
        [array]$ImageConfig
    )
    switch ($windowsImageConfig.image_type) {
            "VMware" {
                if (!$windowsImageConfig.vmware_tools_path) {
                    Write-Warning "VMware Tools path was not set.
                    The image that you create might not be usable on VMware hypervisor type."
                } elseif (!(Test-Path $windowsImageConfig.vmware_tools_path)) {
                    throw "VMware Tools path does not exist."
                }
            }
        }
    if ($windowsImageConfig.compression_format) {
        $compressionFormats = $windowsImageConfig.compression_format.split(".")
        $invalidCompressionFormat = $compressionFormats | Where-Object `
            {$AvailableCompressionFormats -notcontains $_}
        if ($invalidCompressionFormat) {
            throw "Compression format $invalidCompressionFormat not available."
        }
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
        [string]$MsiPath,
        [string]$CloudbaseInitConfigPath,
        [string]$CloudbaseInitUnattendedConfigPath
    )
    $CloudbaseInitMsiPath = "$resourcesDir\CloudbaseInit.msi"
    if ($CloudbaseInitConfigPath) {
        Write-Log "Copying Cloudbase-Init custom configuration file..."
        Copy-Item -Force $CloudbaseInitConfigPath "$resourcesDir\cloudbase-init.conf"
    }
    if ($CloudbaseInitUnattendedConfigPath) {
        Write-Log "Copying Cloudbase-Init custom unattended configuration file..."
        Copy-Item -Force $CloudbaseInitUnattendedConfigPath `
            "$resourcesDir\cloudbase-init-unattend.conf"
    }

    if ($MsiPath) {
        if (!(Test-Path $MsiPath)) {
            throw "Cloudbase-Init installer could not be copied. $MsiPath does not exist."
        }
        Write-Log "Copying Cloudbase-Init..."
        Copy-Item $MsiPath $CloudbaseInitMsiPath
        return
    }
    Write-Log "Downloading Cloudbase-Init..."
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

function Download-QemuGuestAgent {
    Param(
        [Parameter(Mandatory=$true)]
        [string]$QemuGuestAgentConfig,
        [Parameter(Mandatory=$true)]
        [string]$ResourcesDir,
        [Parameter(Mandatory=$true)]
        [string]$OsArch
    )

    $QemuGuestAgentUrl = $QemuGuestAgentConfig
    if ($QemuGuestAgentConfig -eq 'True') {
        $arch = "x86"
        if ($OsArch -eq "AMD64") {
            $arch = "x64"
        }
        $QemuGuestAgentUrl = "https://fedorapeople.org/groups/virt/virtio-win/direct-downloads" + `
                             "/archive-qemu-ga/qemu-ga-win-100.0.0.0-3.el7ev/qemu-ga-{0}.msi" -f $arch
    }

    Write-Log "Downloading QEMU guest agent installer from ${QemuGuestAgentUrl} ..."
    $dst = Join-Path $ResourcesDir "qemu-ga.msi"
    Execute-Retry {
        (New-Object System.Net.WebClient).DownloadFile($QemuGuestAgentUrl, $dst)
    }
    Write-Log "QEMU guest agent installer path is: $dst"
}

function Download-ZapFree {
    Param(
        [Parameter(Mandatory=$true)]
        [string]$resourcesDir,
        [Parameter(Mandatory=$true)]
        [string]$osArch
    )
    $ZapFreePath = "$resourcesDir\zapfree.exe"
    $ZapFree32Path = "$resourcesDir\zapfree32.exe"
    $ZapFreeZipPath = "$resourcesDir\ntfszapfree.zip"
    Write-Log "Downloading ntfszapfree..."

    $ZapFreeUrl = "https://github.com/felfert/ntfszapfree/releases/latest/download/ntfszapfree.zip"
    Execute-Retry {
        (New-Object System.Net.WebClient).DownloadFile($ZapFreeUrl, $ZapFreeZipPath)
    }
    Expand-Archive -LiteralPath $ZapFreeZipPath -DestinationPath $resourcesDir -Force
    Remove-Item -Force $ZapFreeZipPath
    if ($osArch.equals("amd64")) {
        Remove-Item -Force $ZapFree32Path
    } else {
        Move-Item -Force -Path $ZapFree32Path -Destination $ZapFreePath
    }
}

function Generate-ConfigFile {
    Param(
        [Parameter(Mandatory=$true)]
        [string]$resourcesDir,
        [Parameter(Mandatory=$true)]
        [hashtable]$values
    )

    Write-Log "Generate config file: $resourcesDir..."
    $configIniPath = "$resourcesDir\config.ini"
    Import-Module "$localResourcesDir\ini.psm1"
    foreach ($i in $values.GetEnumerator()) {
        Set-IniFileValue -Path $configIniPath -Section "DEFAULT" -Key $i.Key -Value $i.Value
    }
    Write-Log "Config file was generated."
}

function Add-DriversToImage {
    Param(
        [Parameter(Mandatory=$true)]
        [string]$winImagePath,
        [Parameter(Mandatory=$true)]
        [string]$driversPath
    )
    Write-Log ('Adding drivers from "{0}" to image "{1}"' -f $driversPath, $winImagePath)
    Execute-Retry {
        & Dism.exe /image:${winImagePath} /Add-Driver /driver:${driversPath} /ForceUnsigned /recurse
        if ($LASTEXITCODE) {
            throw "Dism failed to add drivers from: $driversPath"
        }
    } -retryInterval 1
}

function Add-PackageToImage {
    Param(
        [Parameter(Mandatory=$true)]
        [string]$winImagePath,
        [Parameter(Mandatory=$true)]
        [string]$packagePath,
        [Parameter(Mandatory=$false)]
        [boolean]$ignoreErrors
    )
    Write-Log ('Adding packages from "{0}" to image "{1}"' -f $packagePath, $winImagePath)
    & Dism.exe /image:${winImagePath} /Add-Package /Packagepath:${packagePath}
    if ($LASTEXITCODE -and !$ignoreErrors) {
        throw "Dism failed to add packages from: $packagePath"
    } elseif ($LASTEXITCODE) {
        Write-Log ("Dism failed to add packages from $packagePath. Skipping.")
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

function Add-CapabilitiesToImage {
    Param(
        [Parameter(Mandatory=$true)]
        [string]$winImagePath,
        [Parameter(Mandatory=$true)]
        [array]$capabilityNames
    )
    if ($capabilityNames) {
        $cmd = @(
        "Dism.exe",
        ("/image:{0}" -f ${winImagePath}),
        "/Add-Capability"
        )
        foreach ($capabilityName in $capabilityNames) {
            $cmd += ("/CapabilityName:{0}" -f $capabilityName)
        }

        Execute-Retry {
            & $cmd[0] $cmd[1..$cmd.Length]
            if ($LASTEXITCODE) { throw "Dism failed to add capabilities: $capabilityNames" }
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
        Write-Log "Enabling PowerShell in the Windows image"
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

    Write-Log "Getting Virtual IO Drivers: $BasePath..."
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
        $driverPaths = Get-VirtIODrivers -MajorMinorVersion 63 -IsServer $IsServer `
            -BasePath $BasePath -Architecture $Architecture -RecursionDepth 1
    }
    return $driverPaths
    Write-Log "Finished to get IO Drivers."
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

    Write-Log "Adding Virtual IO Drivers: $driversBasePath..."
    # For VirtIO ISO with drivers version lower than 1.8.x
    if ($image.ImageVersion.Major -eq 6 -and $image.ImageVersion.Minor -eq 0) {
        $virtioVer = "VISTA"
    } elseif ($image.ImageVersion.Major -eq 6 -and $image.ImageVersion.Minor -eq 1) {
        $virtioVer = "WIN7"
    } elseif ($image.ImageVersion.Major -eq 6 -and $image.ImageVersion.Minor -ge 2) {
        $virtioVer = "WIN8"
    } elseif (($image.ImageVersion.Major -eq 10 -and $image.ImageVersion.Minor -eq 0) `
        -or $image.ImageVersion.Major -gt 10) {
        $virtioVer = "w10"
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
    Write-Log "Virtual IO Drivers was added."
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
    Write-Log "Adding Virtual IO Drivers from ISO: $isoPath..."
    $isoPathBak = $isoPath + (Get-Random) + ".iso"
    Copy-Item $isoPath $isoPathBak -Force
    Write-Log "Using backed up ISO for safe dismount."
    $isoPath = $isoPathBak
    $v = [WIMInterop.VirtualDisk]::OpenVirtualDisk($isoPath)
    try {
        if (Is-IsoFile $isoPath) {
            $v.AttachVirtualDisk()
            # We call Get-PSDrive to refresh the list of active drives.
            # Otherwise, "Test-Path $driversBasePath" will return $False
            # http://www.vistax64.com/powershell/2653-powershell-does-not-update-subst-mapped-drives.html
            Get-PSDrive | Out-Null
            $devicePath = $v.GetVirtualDiskPhysicalPath()
            $driversBasePath = Execute-Retry {
                $res = (Get-DiskImage -DevicePath $devicePath `
                    | Get-Volume).DriveLetter
                if (!$res) {
                    throw "Failed to mount ISO ${isoPath}"
                }
                return $res
            }
            $driversBasePath += ":"
            Write-Log "Adding drivers from $driversBasePath"
            Add-VirtIODrivers -vhdDriveLetter $vhdDriveLetter -image $image `
                -driversBasePath $driversBasePath
        } else {
            throw "The $isoPath is not a valid iso path."
        }
    } catch{
        throw $_
    } finally {
        if ($v) {
            $v.DetachVirtualDisk()
            $v.Close()
        }
        Remove-Item -Force $isoPath
    }
    Write-Log "ISO Virtual Drivers have been adeed."
}

function Set-DotNetCWD {
    # Make sure the PowerShell and .Net CWD match
    [Environment]::CurrentDirectory = (Get-Location -PSProvider FileSystem).ProviderPath
}

function Get-PathWithoutExtension {
    Param(
        [Parameter(Mandatory=$true)]
        [string]$Path,
        [int]$Depth = 0
    )
    # NOTE(avladu): Cleanup all the extensions
    $fileName = [System.IO.Path]::GetFileNameWithoutExtension($Path)
    for($i = 0;$i -lt $Depth;$i++) {
        $fileName = [System.IO.Path]::GetFileNameWithoutExtension($fileName)
    }
    return Join-Path ([System.IO.Path]::GetDirectoryName($Path)) $fileName
}

function Compress-Image {
    Param(
        [Parameter(Mandatory=$true)]
        [string]$VirtualDiskPath,
        [Parameter(Mandatory=$true)]
        [string]$ImagePath,
        [Parameter(Mandatory=$true)]
        [string]$compressionFormats,
        [parameter(Mandatory=$false)]
        [string]$ZipPassword
    )
    Write-Log "Compressing image $VirtualDiskPath..."
    if (!(Test-Path $VirtualDiskPath)) {
        throw "$VirtualDiskPath not found"
    }
    $7zip = Get-7zipPath
    $pigz = Get-PigzPath
    $imageName = (Get-Item $VirtualDiskPath).Name
    $compressionFormatsArray = $compressionFormats.split(".")
    $virtualDiskPathRoot = [System.IO.Path]::GetDirectoryName((Resolve-Path $VirtualDiskPath).Path)
    $compressedImagePath = $VirtualDiskPath + "." + $compressionFormats
    if (Test-Path $compressedImagePath) {
        throw "Compressed $compressedImagePath already exists."
    }
    if (Test-Path $ImagePath) {
        throw "Target compression path $ImagePath already exists."
    }

    # Avoid storing the full path in the archive
    Push-Location $VirtualDiskPathRoot
    foreach ($compressionFormat in $compressionFormatsArray) {
        if ($compressionFormat -eq "tar") {
            $imageNameTar = "${imageName}.tar"
            Write-Log "Compressing ${imageName} to tar ${imageNameTar}"
            & $7zip a -aoa -ttar $imageNameTar $imageName
            if ($LASTEXITCODE) {
                throw "7za.exe failed to create tar ${imageNameTar}"
            }
            Remove-Item -Force $imageName
            $imageName = $imageNameTar
        }
        if ($compressionFormat -eq "gz") {
            $imageNameGz = "${imageName}.gz"
            Write-Log "Compressing ${imageName} to gzip ${imageNameGz}"
            & $pigz -3 -f -q $imageName
            if ($LASTEXITCODE) {
                throw "pigz.exe failed to create gzip ${imageNameGz}"
            }
            $imageName = $imageNameGz
        }
        if ($compressionFormat -eq "zip") {
            $imageNameZip = "${imageName}.zip"
            Write-Log "Compressing ${imageName} to zip ${imageNameZip}"
            $zipCommand = @($7zip, "a", "-aoa", "-tzip", $imageNameZip, `
                            $imageName, "-mx1")
            if ($ZipPassword) {
                Write-Log "The zip password is: $ZipPassword"
                $zipCommand += "-p$ZipPassword"
            }
            Start-Executable -Command $zipCommand
            Remove-Item -Force $imageName
            $imageName = $imageNameZip
        }
    }

    Pop-Location
    if (!(Test-Path $compressedImagePath)) {
        throw "Failed to compress image ${VirtualDiskPath} to ${compressedImagePath}"
    }
    if ($compressedImagePath -ne $imagePath) {
        Move-Item -Force $compressedImagePath $imagePath
    }
}

function Decompress-File {
    Param(
        [parameter(Mandatory=$true)]
        [string]$FilePath,
        [parameter(Mandatory=$true)]
        [string]$CompressionFormat,
        [string]$ZipPassword
    )

    Write-Log "Decompressing image $FilePath..."
    if (!(Test-Path $FilePath)) {
        throw "$FilePath not found"
    }
    $7zip = Get-7zipPath
    $pigz = Get-PigzPath
    $imageName = (Get-Item $FilePath).Name
    $virtualDiskPathRoot = [System.IO.Path]::GetDirectoryName((Resolve-Path $FilePath).Path)

    # Avoid storing the full path in the archive
    Push-Location $VirtualDiskPathRoot
    try {
        if ($CompressionFormat -eq "tar") {
            $imageNameTar = $imageName -replace ".tar", ""
            Write-Log "Decompressing tar ${imageName} to ${imageNameTar}"
            $tarCommand = @($7zip, "e", $imageName, "-y")
            Start-Executable -Command $tarCommand | Out-Null
            $imageName = $imageNameTar
        }
        if ($CompressionFormat -eq "gz") {
            $imageNameGz = $imageName -replace ".gz", ""
            Write-Log "Decompressing gzip ${imageName} to ${imageNameGz}"
            & $pigz -k -d -f $imageName | Out-Null
            if ($LASTEXITCODE) {
                throw "pigz.exe failed to decompress gzip ${imageName}"
            }
            $imageName = $imageNameGz
        }
        if ($CompressionFormat -eq "zip") {
            $imageNameZip = $imageName -replace ".zip", ""
            Write-Log "Decompressing zip ${imageName} to ${imageNameZip}"
            $zipCommand = @($7zip, "e", $imageName, "-y")
            if ($ZipPassword) {
                $zipCommand += "-p$ZipPassword"
            }
            Start-Executable -Command $zipCommand | Out-Null
            $imageName = $imageNameZip
        }
    } finally {
        Pop-Location
    }
    return (Join-Path $virtualDiskPathRoot $imageName)
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

function Get-PigzPath {
    return Join-Path -Path "$localResourcesDir" -ChildPath "pigz.exe"
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
    Write-Log "Shrinking VHD to minimum size"

    $vhdSize = (Get-VHD -Path $VirtualDiskPath).Size
    $vhdSizeGB = $vhdSize/1GB
    Write-Log "Initial VHD size is: $vhdSizeGB GB"

    $mountedVHD = Mount-VHD -Path $VirtualDiskPath -Passthru
    Get-PSDrive | Out-Null

    $Drive = ($mountedVHD | Get-Disk | Get-Partition | Get-Volume | `
        Sort-Object -Property Size -Descending | Select-Object -First 1).DriveLetter

    try {
        Optimize-Volume -DriveLetter $Drive -Defrag -ReTrim -SlabConsolidate

        $partitionInfo = Get-Partition -DriveLetter $Drive
        $partitionResizeInfo = Get-PartitionSupportedSize -DriveLetter $Drive
        $MinSize = $partitionResizeInfo.SizeMin
        $MaxSize = $partitionResizeInfo.SizeMax
        $CurrSize = $partitionInfo.Size/1GB
        Write-Log "Current partition size: $CurrSize GB"
        # Leave free space for making sure Sysprep finishes successfuly
        $newSizeGB = [int](($MinSize + $FreeSpace)/1GB) + 1
        $NewSize = $newSizeGB*1GB
        Write-Log "New partition size: $newSizeGB GB"

        if (($NewSize - $FreeSpace) -gt $MinSize) {
                $global:i = 0
                $global:sizeIncreased = 0
            try {
                $step = 100MB
                # Adding 10 retries means increasing the size to a max of 1.5GB,
                # which should be enough for the Resize-Partition to succeed.
                Execute-Retry {
                    $global:sizeIncreased = ($NewSize + ($step * $global:i))
                    Write-Log "Size increased: $sizeIncreased"
                    $global:i = $global:i + 1
                    Resize-Partition -DriveLetter $Drive -Size $global:sizeIncreased -ErrorAction "Stop"
                } -maxRetryCount 10
            } catch {
                Write-Log "Partition could not be resized using an incremental method"
                Write-Log "Trying to resize partition using a binary search method"
                $binaryTries = 0
                # For example, with 10 binary tries and a max min difference of 1TB space,
                # we will get 1024 / 1024 = 1 GB difference
                $binaryMaxTries = 10
                $MinSize = $global:sizeIncreased
                while (($MinSize -lt $MaxSize) -and ($binaryTries -lt $binaryMaxTries)) {
                    $desiredSize = $MinSize + ($MaxSize - $MinSize) / 2
                    Write-Log "Trying to decrease the partition to $desiredSize"
                    try {
                        Resize-Partition -DriveLetter $Drive -Size $desiredSize -ErrorAction "Stop"
                        Write-Log "Partition resized to $desiredSize. MaxSize becomes the desired size"
                        $MaxSize = $desiredSize
                    } catch {
                        Write-Log "Partition could not be resized to $desiredSize. MinSize becomes the desired size"
                        $MinSize = $desiredSize
                    }
                    $binaryTries ++
                }
            }
        }
    } finally {
        Dismount-VHD -Path $VirtualDiskPath
    }

    $vhdMinSize = (Get-VHD -Path $VirtualDiskPath).MinimumSize
    if ($vhdSize -gt $vhdMinSize) {
        Resize-VHD $VirtualDiskPath -ToMinimumSize
    }
    $FinalDiskSize = ((Get-VHD -Path $VirtualDiskPath).Size/1GB)
    Write-Log "Final disk size: $FinalDiskSize GB"
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
    Write-Log "Waiting for $Name to finish sysprep."
    $isOff = (Get-VM -Name $Name).State -eq "Off"
    $vmMessages = @{}
    while ($isOff -eq $false) {
        Start-Sleep 1
        $vmState = (Get-VM -Name $Name).State
        $isOff =  $vmState -eq "Off"
        try {
            if ($vmState -ne "Running" -or `
                !(Get-VMIntegrationService $Name -Name "Key-Value Pair Exchange").Enabled) {
                continue
            }
            $currentVMMessages = Get-KVPData -VMName $Name
            if (!$currentVMMessages) {continue}
            foreach ($stage in $currentVMMessages.keys) {
                if (!$vmMessages[$stage]) {
                    Write-Log ("- - {0}: {1}" -f @($stage, $currentVMMessages[$stage]))
                }
            }
            $vmMessages = $currentVMMessages
        } catch {
            Write-Log "Could not retrieve VM runtime logs"
        }
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
        [int]$CpuCores,
        [Parameter(Mandatory=$true)]
        [string]$VMSwitch,
        [ValidateSet("1", "2")]
        [string]$Generation = "1",
        [switch]$DisableSecureBoot,
        [switch]$NoWait,
        [string]$CustomIso
    )

    Write-Log "Creating VM $Name attached to $VMSwitch"
    New-VM -Name $Name -MemoryStartupBytes $Memory -SwitchName $VMSwitch `
        -VhdPath $VhdPath -Generation $Generation | Out-Null
    Set-VMProcessor -VMname $Name -count $CpuCores | Out-Null

    Set-VMMemory -VMname $Name -DynamicMemoryEnabled:$false | Out-Null
    $vmAutomaticCheckpointsEnabledWrapper = (Get-VM -Name $Name) | Select-Object 'AutomaticCheckpointsEnabled' `
        -ErrorAction SilentlyContinue
    $vmAutomaticCheckpointsEnabled = $false
    if ($vmAutomaticCheckpointsEnabledWrapper) {
       $vmAutomaticCheckpointsEnabled = $vmAutomaticCheckpointsEnabledWrapper.AutomaticCheckpointsEnabled
    }
    if ($vmAutomaticCheckpointsEnabled) {
       Set-VM -VMName $Name -AutomaticCheckpointsEnabled:$false
    }
    if ($DisableSecureBoot -and $Generation -eq "2") {
         Set-VMFirmware -VMName $Name -EnableSecureBoot Off
    }
    if ($CustomIso) {
        Add-VMDvdDrive -VMName $Name -Path $CustomIso
    }
    Write-Log "Starting $Name"
    Start-VM $Name | Out-Null
    Start-Sleep 5
    if (!$NoWait) {
        Wait-ForVMShutdown $Name
        Remove-VM $Name -Confirm:$false -Force
    }
}

function Convert-KvpData($xmlData) {
   $data = @{}

   foreach ($xmlItem in $xmlData) {
      $key = ""
      $value = ""
      $xmlData = [Xml]$xmlItem
      foreach ($i in $xmlData.INSTANCE.PROPERTY) {
         if ($i.Name -eq "Name") {
            $key = $i.Value
         }
         if ($i.Name -eq "Data") {
            $value = $i.Value
         }
      }
      if ($key -like "ImageGenerationLog-*") {
         $key = $key.replace("ImageGenerationLog-","")
         $data[$key] = $value
      }
   }

   return $data
}

function Get-KVPData {
   param($VMName)
   $wmiNamespace = "root\virtualization\v2"
   $vm = Get-WmiObject -Namespace $wmiNamespace `
      -Query "Select * From Msvm_ComputerSystem Where ElementName=`'$VMName`'"
   if (!$vm) {return}

   $kvp = Get-WmiObject -Namespace $wmiNamespace `
      -Query "Associators of {$vm} Where AssocClass=Msvm_SystemDevice ResultClass=Msvm_KvpExchangeComponent"
   if (!$kvp) {return}

   $kvpData = Convert-KvpData($kvp.GuestIntrinsicExchangeItems)
   return $kvpData
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

    if ($imageName -notlike "*server*") {
        $imageInstallationType = "Client"
    } elseif ($imageName -like '*Core') {
        $imageInstallationType = "Server Core"
    } else {
        $imageInstallationType = "Server"
    }

    return @{
        "imageVersion" = $imageVersion;
        "imageArchitecture" = $imageArchitecture;
        "imageInstallationType" = $imageInstallationType;
    }
}

function Set-WindowsWallpaper {
    Param(
        [Parameter(Mandatory=$true)][PathShouldExist()]
        [string]$WinDrive,
        [Parameter(Mandatory=$false)]
        [string]$WallpaperPath,
        [Parameter(Mandatory=$false)]
        [string]$WallpaperSolidColor
    )

    Write-Log "Setting wallpaper..."
    $useWallpaperImage = $false
    $wallpaperGPOPath = Join-Path $localResourcesDir "GPO"

    if ($WallpaperPath -and $WallpaperSolidColor) {
        throw "WallpaperPath and WallpaperSolidColor cannot be set at the same time."
    }
    if ($WallpaperPath -or !($WallpaperSolidColor)) {
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
        Write-Log "Wallpaper copied to the image."

        # Note(avladu) if the image already has been booted and has a wallpaper, the
        # GPO will not be applied for the users who have already logged in.
        # The wallpaper can still be changed by replacing the cached one.
        $cachedWallpaperPartPath = "\Users\Administrator\AppData\Roaming\Microsoft\Windows\Themes\TranscodedWallpaper*"
        $cachedWallpaperPath = Join-Path -ErrorAction SilentlyContinue $winDrive $cachedWallpaperPartPath
        if (Test-Path $cachedWallpaperPath) {
            $wallpaperPathFullName = (Get-Item $cachedWallpaperPath).FullName
            Remove-Item -Recurse -Force ((Get-Item $cachedWallpaperPath).DirectoryName + "\*")
            Copy-Item -Force $WallpaperPath $wallpaperPathFullName
            Write-Log "Cached wallpaper for user Administrator has been replaced."
        }
        $useWallpaperImage = $true
    }

    $windowsLocalGPOPath = Join-Path $winDrive "\Windows\System32\GroupPolicy"
    if (!(Test-Path $windowsLocalGPOPath)) {
       New-Item -Type Directory $windowsLocalGPOPath | Out-Null
    }
    Copy-Item -Recurse -Force "$wallpaperGPOPath\*" "$windowsLocalGPOPath\"
    $basePolicyRegistry = Join-Path $windowsLocalGPOPath "User/Registry.pol"
    $wallpaperPolicyRegistry = Join-Path $windowsLocalGPOPath "User/Registry-wallpaper.pol"
    $solidColorPolicyRegistry = Join-Path $windowsLocalGPOPath "User/Registry-solid-color.pol"

    if ($useWallpaperImage) {
        Move-Item -Force $wallpaperPolicyRegistry $basePolicyRegistry
        Remove-Item -Force $solidColorPolicyRegistry -ErrorAction SilentlyContinue
    } else {
        Move-Item -Force $solidColorPolicyRegistry $basePolicyRegistry
        Remove-Item -Force $wallpaperPolicyRegistry -ErrorAction SilentlyContinue
    }
    Write-Log "Wallpaper GPO copied to the image."

    Write-Log "Wallpaper was set."
}

function Reset-WindowsWallpaper {
    Param(
        [Parameter(Mandatory=$true)][PathShouldExist()]
        [string]$WinDrive
    )
    $wallpaperDestination = Join-Path $winDrive "\Windows\web\Wallpaper\Cloud\Wallpaper.jpg"
    Remove-Item -Force -ErrorAction SilentlyContinue $wallpaperDestination

    $cachedWallpaperPartPath = "\Users\Administrator\AppData\Roaming\Microsoft\Windows\Themes\TranscodedWallpaper*"
    $cachedWallpaperPath = Join-Path -ErrorAction SilentlyContinue $winDrive $cachedWallpaperPartPath
    Remove-Item -Force -ErrorAction SilentlyContinue $cachedWallpaperPath

    $windowsLocalGPOPath = Join-Path $winDrive "\Windows\System32\GroupPolicy\User\Registry.pol"
    Remove-Item -Force -ErrorAction SilentlyContinue $windowsLocalGPOPath
}

function Get-TotalLogicalProcessors {
    $count = 0
    $cpus = Get-WmiObject Win32_Processor
    foreach ($cpu in $cpus) {
        $count += $cpu.NumberOfLogicalProcessors
    }
    return $count
}

function Map-KMSProductKey {
    param($ImageName, $ImageVersion)

    $productKeysMap = Get-Content -Encoding ASCII $kmsProductKeysFile | ConvertFrom-Json
    try {
        $ImageVersionBuild = $ImageVersion.Build
        if ($ImageVersion.Major -eq "6") {
            $ImageVersionBuild = 0
        }
        return ($productKeysMap | Select-Object -ExpandProperty "KMS" | `
            Select-Object -ExpandProperty ([string]$ImageVersion.Major) | `
            Select-Object -ExpandProperty ([string]$ImageVersion.Minor) | `
            Select-Object -ExpandProperty ([string]$ImageVersionBuild) | `
            Select-Object -ExpandProperty $ImageName)
    } catch {
        Write-Log "No valid KMS key found for image ${ImageName}"
    }
}

function Clean-WindowsUpdates {
    Param(
        [Parameter(Mandatory=$true)]
        [string]$winImagePath,
        [Parameter(Mandatory=$false)]
        [boolean]$PurgeUpdates
    )
    Write-Log "Running offline dism Cleanup-Image..."
    if (([System.Environment]::OSVersion.Version.Major -gt 6) -or ([System.Environment]::OSVersion.Version.Minor -ge 2))
    {
        if (!$PurgeUpdates) {
            Dism.exe /image:${winImagePath} /Cleanup-Image /StartComponentCleanup
        } else {
            Dism.exe /image:${winImagePath} /Cleanup-Image /StartComponentCleanup /ResetBase
        }
        if ($LASTEXITCODE) {
            throw "Offline dism Cleanup-Image failed."
        } else {
            Write-Log "Offline dism Cleanup-Image completed."
        }
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

    Write-Log "Windows online image generation started."
    Is-Administrator
    if (!$windowsImageConfig.run_sysprep -and !$windowsImageConfig.force) {
        throw "You chose not to run sysprep.
            This will build an unusable Windows image.
            If you really want to continue use the ``force = true`` config option."
    }

    Check-Prerequisites
    if ($windowsImageConfig.external_switch) {
        $switch = Get-VMSwitch -Name $windowsImageConfig.external_switch -ErrorAction SilentlyContinue
        if (!$switch) {
            throw "Selected vmswitch {0} does not exist" -f $windowsImageConfig.external_switch
        }
        if ($switch.SwitchType -ne "External" -and !$windowsImageConfig.force) {
            throw ("Selected switch {0} is not an external switch. If you really want to continue use the ``force = true`` flag." -f $windowsImageConfig.external_switch)
        }
    }
    if ([int]$windowsImageConfig.cpu_count -gt [int](Get-TotalLogicalProcessors)) {
        throw "CpuCores larger then available (logical) CPU cores."
    }

    if (Test-Path $windowsImageConfig.image_path) {
        Write-Log "Found already existing image file. Removing it..." -ForegroundColor Yellow
        Remove-Item -Force $windowsImageConfig.image_path
        Write-Log "Already existent image file has been removed." -ForegroundColor Yellow
    }

    try {
        $barePath = Get-PathWithoutExtension $windowsImageConfig.image_path 3
        $virtualDiskPath = $barePath + ".vhdx"
        $imagePath = $virtualDiskPath

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
        if ($windowsImageConfig.compression_format) {
            Remove-IniFileValue -Path $offlineConfigFilePath `
                -Key 'compression_format' -Section 'DEFAULT'
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
                -Generation $generation -DisableSecureBoot:$windowsImageConfig.disable_secure_boot
        }

        if ($windowsImageConfig.shrink_image_to_minimum_size -eq $true) {
            Resize-VHDImage $virtualDiskPath
        }
        Optimize-VHD $VirtualDiskPath -Mode Full

        if ($windowsImageConfig.image_type -eq "MAAS") {
            $imagePath = $barePath + ".raw"
            Write-Log "Converting VHD to RAW"
            Convert-VirtualDisk -vhdPath $virtualDiskPath -outPath $imagePath -format "raw"
            Remove-Item -Force $virtualDiskPath
        }

        if ($windowsImageConfig.image_type -ceq "VMware") {
            $imagePath = $barePath + ".vmdk"
            Write-Log "Converting VHD to VMDK"
            Convert-VirtualDisk -vhdPath $virtualDiskPath -outPath $imagePath -format "vmdk"
            Remove-Item -Force $virtualDiskPath
        }

        if ($windowsImageConfig.image_type -eq "KVM") {
            $imagePath = $barePath + ".qcow2"
            Write-Log "Converting VHD to Qcow2"
            Convert-VirtualDisk -vhdPath $virtualDiskPath -outPath $imagePath -format "qcow2" `
                -CompressQcow2 $windowsImageConfig.compress_qcow2
            Remove-Item -Force $virtualDiskPath
        }

        if ($windowsImageConfig.compression_format) {
            Compress-Image -VirtualDiskPath $imagePath `
                -ImagePath $windowsImageConfig.image_path `
                -compressionFormats $windowsImageConfig.compression_format `
                -ZipPassword $windowsImageConfig.zip_password | Out-Null
        } elseif ($imagePath -ne $windowsImageConfig['image_path']) {
            Move-Item -Force $imagePath $windowsImageConfig['image_path']
        }
    } catch {
        Write-Log $_
        if ($windowsImageConfig.image_path -and (Test-Path $windowsImageConfig.image_path)) {
            Remove-Item -Force $windowsImageConfig.image_path -ErrorAction SilentlyContinue
        }
        Throw
    }
    Write-Log "Windows online image generation finished. Image path: $($windowsImageConfig.image_path)"
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
    Write-Log "Cloud image generation started."
    try {
        $windowsImageConfig = Get-WindowsImageConfig -ConfigFilePath $ConfigFilePath
        $mountedWindowsIso = $null
        if ($windowsImageConfig.wim_file_path.EndsWith('.iso')) {
            $windowsImageConfig.wim_file_path = get-command $windowsImageConfig.wim_file_path -erroraction ignore `
                | Select-Object -ExpandProperty Source
            if($windowsImageConfig.wim_file_path -eq $null){
                throw ("Unable to find source iso. Either specify the full path or add the folder containing the iso to the path variable")
            }
            $mountedWindowsIso = [WIMInterop.VirtualDisk]::OpenVirtualDisk($windowsImageConfig.wim_file_path)
            $mountedWindowsIso.AttachVirtualDisk()
            $devicePath = $mountedWindowsIso.GetVirtualDiskPhysicalPath()
            $basePath = ((Get-DiskImage -DevicePath $devicePath `
                    | Get-Volume).DriveLetter) + ":"
            $windowsImageConfig.wim_file_path = "$($basePath)\Sources\install.wim"
        }
        
        Validate-WindowsImageConfig $windowsImageConfig
        Set-DotNetCWD
        Is-Administrator
        $image = Get-WimFileImagesInfo -WimFilePath $windowsImageConfig.wim_file_path | `
            Where-Object { $_.ImageName -eq $windowsImageConfig.image_name }
        if (!$image) {
            throw ("Image {0} not found in WIM file {1}" -f @($windowsImageConfig.image_name, $windowsImageConfig.wim_file_path))
        }
        Check-DismVersionForImage $image

        if (Test-Path $windowsImageConfig.image_path) {
            Write-Log "Found already existing image file. Removing it..." -ForegroundColor Yellow
            Remove-Item -Force $windowsImageConfig.image_path
            Write-Log "Already existent image file has been removed." -ForegroundColor Yellow
        }

        $vhdPath = "{0}.vhdx" -f (Get-PathWithoutExtension $windowsImageConfig.image_path)
        if (Test-Path $vhdPath) {
            Remove-Item -Force $vhdPath
        }

        try {
            $drives = Create-ImageVirtualDisk -VhdPath $vhdPath -Size $windowsImageConfig.disk_size `
                -DiskLayout $windowsImageConfig.disk_layout
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
                $productKey = $windowsImageConfig.product_key
                if ($productKey -eq "default_kms_key") {
                    $productKey = Map-KMSProductKey $windowsImageConfig.image_name $image.ImageVersion
                }
                if ($productKey) {
                    $xmlParams.Add('productKey', $productKey)
                }
            }
            Generate-UnattendXml @xmlParams
            Copy-UnattendResources -resourcesDir $resourcesDir -imageInstallationType $image.ImageInstallationType `
                -InstallMaaSHooks $windowsImageConfig.install_maas_hooks `
                -VMwareToolsPath $windowsImageConfig.vmware_tools_path
            Copy-CustomResources -ResourcesDir $resourcesDir -CustomResources $windowsImageConfig.custom_resources_path `
                                 -CustomScripts $windowsImageConfig.custom_scripts_path
            Copy-Item $ConfigFilePath "$resourcesDir\config.ini"
            if ($windowsImageConfig.enable_custom_wallpaper) {
                Set-WindowsWallpaper -WinDrive $winImagePath -WallpaperPath $windowsImageConfig.wallpaper_path `
                    -WallpaperSolidColor $windowsImageConfig.wallpaper_solid_color
            }
            if ($windowsImageConfig.zero_unused_volume_sectors) {
                Download-ZapFree $resourcesDir ([string]$image.ImageArchitecture)
            }
            if ($windowsImageConfig.install_qemu_ga -and $windowsImageConfig.install_qemu_ga -ne 'False') {
                Download-QemuGuestAgent -QemuGuestAgentConfig $windowsImageConfig.install_qemu_ga `
                    -ResourcesDir $resourcesDir -OsArch ([string]$image.ImageArchitecture)
            }
            Download-CloudbaseInit -resourcesDir $resourcesDir -osArch ([string]$image.ImageArchitecture) `
                                   -BetaRelease:$windowsImageConfig.beta_release -MsiPath $windowsImageConfig.msi_path `
                                   -CloudbaseInitConfigPath $windowsImageConfig.cloudbase_init_config_path `
                                   -CloudbaseInitUnattendedConfigPath $windowsImageConfig.cloudbase_init_unattended_config_path
            Apply-Image -winImagePath $winImagePath -wimFilePath $windowsImageConfig.wim_file_path `
                -imageIndex $image.ImageIndex
            Create-BCDBootConfig -systemDrive $drives[0] -windowsDrive $drives[1] -diskLayout $windowsImageConfig.disk_layout `
                -image $image
            Check-EnablePowerShellInImage $winImagePath $image

            if ($windowsImageConfig.drivers_path -and (Test-Path $windowsImageConfig.drivers_path)) {
                Add-DriversToImage $winImagePath $windowsImageConfig.drivers_path
            }
            if ($windowsImageConfig.virtio_iso_path) {
                Add-VirtIODriversFromISO -vhdDriveLetter $winImagePath -image $image `
                    -isoPath $windowsImageConfig.virtio_iso_path
            }
            if ($windowsImageConfig.virtio_base_path) {
                Add-VirtIODrivers -vhdDriveLetter $winImagePath -image $image `
                    -driversBasePath $windowsImageConfig.virtio_base_path
            }
            if ($windowsImageConfig.extra_features) {
                Enable-FeaturesInImage $winImagePath $windowsImageConfig.extra_features
            }
            if ($windowsImageConfig.extra_packages) {
                foreach ($package in $windowsImageConfig.extra_packages.split(",")) {
                    Add-PackageToImage $winImagePath $package -ignoreErrors $windowsImageConfig.extra_packages_ignore_errors
                }
            }
            if ($windowsImageConfig.extra_capabilities) {
                Add-CapabilitiesToImage $winImagePath $windowsImageConfig.extra_capabilities
            }
            if ($windowsImageConfig.clean_updates_offline) {
                Clean-WindowsUpdates $winImagePath -PurgeUpdates $windowsImageConfig.purge_updates
            }

            Optimize-Volume -DriveLetter $drives[1].replace(":","") -Defrag -ReTrim -SlabConsolidate
        } finally {
            if (Test-Path $vhdPath) {
                Detach-VirtualDisk $vhdPath
            }
        }

        $barePath = Get-PathWithoutExtension $windowsImageConfig.image_path 3
        $imagePath = $barePath + "." + $windowsImageConfig.virtual_disk_format
        if (!($windowsImageConfig.virtual_disk_format -in @("VHD", "VHDX"))) {
            Convert-VirtualDisk -vhdPath $vhdPath -outPath $imagePath `
                -format $windowsImageConfig.virtual_disk_format
            Remove-Item -Force $vhdPath
        } elseif ($vhdPath -ne $imagePath) {
            Move-Item -Force $vhdPath $imagePath
        }
        if ($windowsImageConfig.compression_format) {
            Compress-Image -VirtualDiskPath $imagePath `
                -ImagePath $windowsImageConfig['image_path'] `
                -compressionFormats $windowsImageConfig.compression_format `
                -ZipPassword $windowsImageConfig.zip_password | Out-Null
        } elseif ($imagePath -ne $windowsImageConfig['image_path']) {
            Move-Item -Force $imagePath $windowsImageConfig['image_path']
        }
        Write-Log "Cloud image generation finished. Image path: $($windowsImageConfig.image_path)"
    } finally {
        if($mountedWindowsIso){
            $mountedWindowsIso.DetachVirtualDisk()
        }
    }
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

    Write-Log "Cloud image from golden image generation started."
    $windowsImageConfig = Get-WindowsImageConfig -ConfigFilePath $ConfigFilePath
    Is-Administrator
    if (!$windowsImageConfig.run_sysprep -and !$windowsImageConfig.force) {
        throw "You chose not to run sysprep.
            This will build an unusable Windows image.
            If you really want to continue use the ``force = true`` config option."
    }

    Check-Prerequisites
    if ($windowsImageConfig.external_switch) {
        $switch = Get-VMSwitch -Name $windowsImageConfig.external_switch -ErrorAction SilentlyContinue
        if (!$switch) {
            throw "Selected vmswitch {0} does not exist" -f $windowsImageConfig.external_switch
        }
        if ($switch.SwitchType -ne "External" -and !$windowsImageConfig.force) {
            throw ("Selected switch {0} is not an external switch. If you really want to continue use the ``force = true`` flag." -f $windowsImageConfig.external_switch)
        }
    }
    if ([int]$windowsImageConfig.cpu_count -gt [int](Get-TotalLogicalProcessors)) {
        throw "CpuCores larger than available (logical) CPU cores."
    }

    try {
        Execute-Retry {
            Resize-VHD -Path $windowsImageConfig.gold_image_path -SizeBytes $windowsImageConfig.disk_size
            Set-VHD -Path $windowsImageConfig.gold_image_path -ResetDiskIdentifier -Force
        } | Out-Null

        Mount-VHD -Path $windowsImageConfig.gold_image_path -Passthru | Out-Null
        $driveNumber = Execute-Retry {
            Get-PSDrive | Out-Null
            $driveNumber = (Get-DiskImage -ImagePath $windowsImageConfig.gold_image_path | Get-Disk).Number
            if ($driveNumber -eq $null) {
                throw "Could not retrieve drive number for mounted vhd"
            }
            return $driveNumber
        }
        $partition = Execute-Retry {
            Get-PSDrive | Out-Null
            Set-Disk -Number $driveNumber -IsOffline $False
            $partition = Get-Partition -DiskNumber $driveNumber | Where-Object {@("Basic", "IFS") -contains $_.Type}
            if (!$partition -or !$partition.DriveLetter) {
                throw "Partition not found for mounted $($windowsImageConfig.gold_image_path)"
            }
            return $partition
        }
        $driveLetterGold = $partition.DriveLetter + ":"
        Write-Log "The mount point for the gold image is: ${driveLetterGold}"
        try {
            $maxPartitionSize = (Get-PartitionSupportedSize -DiskNumber $driveNumber -PartitionNumber `
                                     $partition.PartitionNumber).SizeMax
            Resize-Partition -DiskNumber $driveNumber -PartitionNumber $partition.PartitionNumber `
                -Size $maxPartitionSize -ErrorAction SilentlyContinue
        } catch {
            Write-Log "Partition has already the desired size"
        }
        $imageInfo = Get-ImageInformation $driveLetterGold -ImageName $windowsImageConfig.image_name
        if ($windowsImageConfig.virtio_iso_path) {
            Add-VirtIODriversFromISO -vhdDriveLetter $driveLetterGold -image $imageInfo `
                -isoPath $windowsImageConfig.virtio_iso_path
        }

        if ($windowsImageConfig.drivers_path -and (Test-Path $windowsImageConfig.drivers_path)) {
            Add-DriversToImage $driveLetterGold $windowsImageConfig.drivers_path
        }

        $resourcesDir = Join-Path -Path $driveLetterGold -ChildPath "UnattendResources"
        Reset-BCDSearchOrder -systemDrive $driveLetterGold -windowsDrive $driveLetterGold `
            -diskLayout $windowsImageConfig.disk_layout
        Copy-UnattendResources -resourcesDir $resourcesDir -imageInstallationType $windowsImageConfig.image_name `
                               -InstallMaaSHooks $windowsImageConfig.install_maas_hooks `
                               -VMwareToolsPath $windowsImageConfig.vmware_tools_path
        Copy-CustomResources -ResourcesDir $resourcesDir -CustomResources $windowsImageConfig.custom_resources_path `
                             -CustomScripts $windowsImageConfig.custom_scripts_path
        Copy-Item $ConfigFilePath "$resourcesDir\config.ini"
        if ($windowsImageConfig.enable_custom_wallpaper) {
            Set-WindowsWallpaper -WinDrive $driveLetterGold -WallpaperPath $windowsImageConfig.wallpaper_path `
                -WallpaperSolidColor $windowsImageConfig.wallpaper_solid_color
        } else {
            Reset-WindowsWallpaper -WinDrive $driveLetterGold
        }
        if ($windowsImageConfig.zero_unused_volume_sectors) {
            Download-ZapFree $resourcesDir $imageInfo.imageArchitecture
        }
        if ($windowsImageConfig.install_qemu_ga -and $windowsImageConfig.install_qemu_ga -ne 'False') {
            Download-QemuGuestAgent -QemuGuestAgentConfig $windowsImageConfig.install_qemu_ga `
                -ResourcesDir $resourcesDir -OsArch $imageInfo.imageArchitecture
        }
        Download-CloudbaseInit -resourcesDir $resourcesDir -osArch $imageInfo.imageArchitecture `
                               -BetaRelease:$windowsImageConfig.beta_release -MsiPath $windowsImageConfig.msi_path `
                               -CloudbaseInitConfigPath $windowsImageConfig.cloudbase_init_config_path `
                               -CloudbaseInitUnattendedConfigPath $windowsImageConfig.cloudbase_init_unattended_config_path
        Dismount-VHD -Path $windowsImageConfig.gold_image_path | Out-Null

        if ($windowsImageConfig.run_sysprep) {
            if($windowsImageConfig.disk_layout -eq "UEFI") {
                $generation = "2"
            } else {
                $generation = "1"
            }

            $Name = "WindowsGoldImage-Sysprep" + (Get-Random)
            Run-Sysprep -Name $Name -Memory $windowsImageConfig.ram_size -vhdPath $windowsImageConfig.gold_image_path `
                -VMSwitch $switch.Name -CpuCores $windowsImageConfig.cpu_count `
                -Generation $generation -DisableSecureBoot:$windowsImageConfig.disable_secure_boot
        }

        if ($windowsImageConfig.shrink_image_to_minimum_size -eq $true) {
            Resize-VHDImage $windowsImageConfig.gold_image_path
        }
        Optimize-VHD $windowsImageConfig.gold_image_path -Mode Full

        $barePath = Get-PathWithoutExtension $windowsImageConfig.image_path 3
        $imagePath = $windowsImageConfig.gold_image_path

        if ($windowsImageConfig.image_type -eq "HYPER-V") {
            $imagePathVhdx = $barePath + ".vhdx"
            if ($imagePath -ne $imagePathVhdx) {
                Move-Item -Force $imagePath $imagePathVhdx
                $imagePath = $imagePathVhdx
            }
        }

        if ($windowsImageConfig.image_type -eq "MAAS") {
            $imagePathRaw = $barePath + ".raw"
            Write-Log "Converting VHD to RAW"
            Convert-VirtualDisk -vhdPath $imagePath -outPath $imagePathRaw `
                -format "RAW"
            Remove-Item -Force $imagePath
            $imagePath = $imagePathRaw
        }

        if ($windowsImageConfig.image_type -eq "KVM") {
            $imagePathQcow2 = $barePath + ".qcow2"
            Write-Log "Converting VHD to QCow2"
            Convert-VirtualDisk -vhdPath $imagePath -outPath $imagePathQcow2 `
                -format "qcow2" -CompressQcow2 $windowsImageConfig.compress_qcow2
            Remove-Item -Force $imagePath
            $imagePath = $imagePathQcow2
        }

        if ($windowsImageConfig.image_type -eq "VMware") {
            $imagePathVmdk = $barePath + ".vmdk"
            Write-Log "Converting VHD to VMDK"
            Convert-VirtualDisk -vhdPath $imagePath -outPath $imagePathVmdk `
                -format "vmdk"
            Remove-Item -Force $imagePath
            $imagePath = $imagePathVmdk
        }

        if ($windowsImageConfig.compression_format) {
            Compress-Image -VirtualDiskPath $imagePath `
                -ImagePath $windowsImageConfig['image_path'] `
                -compressionFormats $windowsImageConfig.compression_format `
                -ZipPassword $windowsImageConfig.zip_password | Out-Null
        } elseif ($imagePath -ne $windowsImageConfig['image_path']) {
            Move-Item -Force $imagePath $windowsImageConfig['image_path']
        }

        Write-Log "Cloud image from golden image generation finished. Image path: $($windowsImageConfig.image_path)"
    } catch {
        try {
            Get-VHD $windowsImageConfig.gold_image_path | Dismount-VHD
            Remove-Item -Force $windowsImageConfig.gold_image_path
        } catch {
            Write-Log $_
        }
        throw $_
    }
}

function Get-WinRMSession {
    param(
        [string]$VmName,
        [string]$Username,
        [string]$Password
    )

    $maxIpRetries = 30
    $ipRetries = 0
    $ip = ""
    $currentSession = ""
    while ($ipRetries -lt $maxIpRetries) {
        $ipAddresses = Get-VMNetworkAdapter -VMName $vmName | Where-Object `
            { $_.Status -and $_.IPAddresses } | `
            Select-Object -First 1 | Select-Object -Property IPAddresses
        if ($ipAddresses -and $ipAddresses.IPAddresses) {
            $ip = $ipAddresses.IPAddresses | Where-Object { ([ipaddress]$_).AddressFamily -eq "InterNetwork" }
            if ($ip) {
                $secureWinAdminPass = $Password | ConvertTo-SecureString -AsPlainText -Force
                $authCredentials = New-Object -TypeName `
                    System.Management.Automation.PSCredential -ArgumentList $Username, $secureWinAdminPass
                $sessionOptions = New-PSSessionOption -SkipCACheck -SkipCNCheck -SkipRevocationCheck
                $currentSession = ""
                try {
                    $currentSession = New-PSSession -ComputerName $ip -UseSSL `
                        -SessionOption $sessionOptions -Authentication Basic -Credential $authCredentials
                } catch {
                    Write-Log "Could not create WinRM HTTPS session to IP ${ip}"
                }
                if (!$currentSession) {
                    try {
                        $currentSession = New-PSSession -ComputerName $ip -Credential $authCredentials `
                            -Authentication Basic
                    } catch {
                        Write-Log "Could not create WinRM HTTP session to IP ${ip}"
                    }
                }
                if ($currentSession) {
                    break
                }
            }
        } else {
            Write-Log "Could not retrieve IPv4 IP for ${vmName}"
        }
        $ipRetries += 1
        Start-Sleep 30
    }
    return $currentSession
}

function Test-WindowsImage {
    <#
    .SYNOPSIS
     This function verifies if a Windows image has been properly generated according to
     the configuration file. The verification is performed offline, without instantiating
     the image.
    .DESCRIPTION
     This function first tests if the config.image_path exists, then uses the extension and the
     config.compression_format to detect the compression and qemu-img binary to detect
     the image format.
     If any compression is detected, a decompression is performed for each compression.
     If the image format is other than vhdx, "qemu-img convert -O vhdx" is performed.
     The vhdx is mounted and the following checks are performed:
       1. If Cloudbase-Init folder exists
       2. If curtin (for MAAS) folder exists
       3. If OEM drivers are installed
     Finally, the full chain of decompressed/converted files is removed.
     #>
    [CmdletBinding()]
    Param(
        [parameter(Mandatory=$true, ValueFromPipeline=$true)]
        [string]$ConfigFilePath,
        [switch]$Online,
        [string]$CustomIso
    )

    Write-Log "Offline Windows image validation started."
    $windowsImageConfig = Get-WindowsImageConfig -ConfigFilePath $ConfigFilePath
    Is-Administrator

    if (!(Test-Path $windowsImageConfig.image_path)) {
        throw "Image validation failed: $($windowsImageConfig.image_path) does not exist."
    }

    $imageChain = @()
    $vmName = "WindowsOnlineImage-Test" + (Get-Random)
    $imagePath = $windowsImageConfig.image_path

    try {
        if ($windowsImageConfig.compression_format) {
            $compressionFormats = $windowsImageConfig.compression_format.split(".")
            [array]::Reverse($compressionFormats)
            $invalidCompressionFormat = $compressionFormats | Where-Object `
                {$AvailableCompressionFormats -notcontains $_}
            if ($invalidCompressionFormat) {
                throw "Compression format $invalidCompressionFormat not available."
            } else {
                Write-Log "Compression format ${invalidCompressionFormat} is available."
            }
            foreach($compressionFormat in $compressionFormats) {
                $imageToDecompress = $imagePath
                $imagePath = Decompress-File -FilePath $imageToDecompress `
                    -CompressionFormat $compressionFormat `
                    -ZipPassword $windowsImageConfig.zip_password
                Write-Log "Image ${imageToDecompress} decompressed to ${imagePath}"
                $imageChain += $imagePath
            }
        }

        $imageFileExtension = [System.IO.Path]::GetExtension($imagePath)
        $fileExtension = '*'
        $diskFormat = '*'
        if ($windowsImageConfig.image_type -eq "HYPER-V") {
            $fileExtension = 'vhdx'
            $diskFormat = 'vhdx'
            if ($imageFileExtension -eq '.vhd') {
                $fileExtension = 'vhd'
                $diskFormat = 'vpc'
            }
        }
        if ($windowsImageConfig.image_type -eq "KVM") {
            $fileExtension = 'qcow2'
            $diskFormat = 'qcow2'
        }
        if ($windowsImageConfig.image_type -eq "MAAS") {
            $fileExtension = 'raw'
            $diskFormat = 'raw'
        }
        if ($windowsImageConfig.image_type -eq "VMware") {
            $fileExtension = 'vmdk'
            $diskFormat = 'vmdk'
        }

        if (!([System.IO.Path]::GetExtension($imagePath) -like ".${fileExtension}")) {
            throw "${imagePath} does not have ${fileExtension} extension."
        } else {
            Write-Log "${imagePath} has the correct ${fileExtension} extension."
        }

        $qemuInfoOutput = & "$scriptPath\bin\qemu-img.exe" info --output=json $imagePath
        $qemuInfoJson = ConvertFrom-Json ($qemuInfoOutput -join "")
        $qemuImgFormat = $qemuInfoJson | Select-Object "Format"
        if ($qemuImgFormat.Format -ne $diskFormat) {
            throw "${imagePath} does not have ${diskFormat} format."
        } else {
            Write-Log "${imagePath} has the correct ${diskFormat} format."
        }

        if (!(@("vhd", "vhdx").Contains($fileExtension))) {
            $barePath = Get-PathWithoutExtension $imagePath
            $tempImagePath = $barePath + ".vhdx"
            Convert-VirtualDisk -vhdPath $imagePath -outPath $tempImagePath `
                -format "vhdx"
            $imagePath = $tempImagePath
            $imageChain += $imagePath
        }

        $childImagePath = $imagePath -ireplace ".vhd", "_bak.vhd"
        New-VHD -ParentPath $imagePath -Path $childImagePath | Out-Null
        $imagePath = $childImagePath
        $imageChain += $imagePath
        Mount-VHD -Path $imagePath -Passthru | Out-Null

        try {
            Get-PSDrive | Out-Null
            $driveNumber = (Get-DiskImage -ImagePath $imagePath | Get-Disk).Number
            Set-Disk -Number $driveNumber -IsOffline $False
            Get-PSDrive | Out-Null
            $mountPoint = (Get-Partition -DiskNumber $driveNumber | `
                Where-Object {@("Basic", "IFS") -contains $_.Type}).DriveLetter + ":"

            # Test if Cloudbase-Init is installed
            $cloudbaseInitPath = "Program Files\Cloudbase Solutions\Cloudbase-Init"
            $cloudbaseInitPathX86 = "${cloudbaseInitPath} (x86)"
            if ((Test-Path (Join-Path $mountPoint $cloudbaseInitPath)) -or `
                (Test-Path (Join-Path $mountPoint $cloudbaseInitPathX86))) {
                Write-Log "Cloudbase-Init is installed."
            } else {
                throw "Cloudbase-Init is not installed on the image."
            }

            # Test if curtin modules are installed
            if ($windowsImageConfig.install_maas_hooks) {
                if (Test-Path (Join-Path $mountPoint "curtin")) {
                    Write-Log "Curtin hooks are installed."
                } else {
                    throw "Curtin hooks are not installed on the image."
                }
            }

            # Test if extra drivers are installed
            if ($windowsImageConfig.virtio_iso_path -or $windowsImageConfig.virtio_base_path `
                    -or $windowsImageConfig.drivers_path) {
                $dismDriversOutput = (& Dism.exe /image:$mountPoint /Get-Drivers /Format:Table)
                $allDrivers = (Select-String "oem" -InputObject $dismDriversOutput -AllMatches).Matches.Count
                $virtDrivers = (Select-String "Red Hat, Inc." -InputObject $dismDriversOutput -AllMatches).Matches.Count
                $virtDrivers += (Select-String "QEMU" -InputObject $dismDriversOutput `
                    -AllMatches -CaseSensitive).Matches.Count
                Write-Log "Found ${allDrivers} drivers, from which ${virtDrivers} are VirtIO drivers."
                $minDriversCount = 1
                if ($windowsImageConfig.virtio_iso_path -or $windowsImageConfig.virtio_base_path) {
                    $minDriversCount = $VirtIODrivers.Count - 1 + ($allDrivers - $virtDrivers)
                }
                if ($allDrivers -lt $minDriversCount) {
                    throw "Expected ${minDriversCount} ! >= ${allDrivers} drivers installed on the image."
                }
            }
        } finally {
            Dismount-VHD $imagePath
        }
        Write-Log "Offline Windows image validation finished."

        if (!$Online) {
            return
        }

        Write-Log "Online Windows image validation started."
        # Run the online testing
        # A vm will be created using the backing VHDX from the previous stage.
        # The VM will have a config drive attached and cloudbase-init will run automatically.
        # After the instance gets an IP, that IP will be retrieved and a WINRM session will be created
        # using a known username and password.
        # Afterwards, cloudbase-init logs will be checked, a report wil be created with the image details and
        # a custom test script will be run.
        # The VM will be removed after the testing process is finished.
        if($windowsImageConfig.disk_layout -eq "UEFI") {
            $generation = "2"
        } else {
            $generation = "1"
        }

        Run-Sysprep -Name $vmName -Memory $windowsImageConfig.ram_size -vhdPath $imagePath `
            -VMSwitch $windowsImageConfig.external_switch -CpuCores $windowsImageConfig.cpu_count `
            -Generation $generation -NoWait:$true -DisableSecureBoot:$windowsImageConfig.disable_secure_boot `
            -CustomIso $CustomIso

        $currentSession = Get-WinRMSession -VMName $vmName -Username "Administrator" `
            -Password $windowsImageConfig.administrator_password
        if (!$currentSession) {
            throw "Could not connect via WinRM to VM ${vmName}"
        } else {
            Write-Log "Connected via WinRM to VM ${vmName}"
        }

        $cloudbaseInitLogs = Invoke-Command -Session $currentSession {
            $cbsInitLogPath = 'C:\Program Files\Cloudbase Solutions\Cloudbase-Init\log\cloudbase-init.log'
            $logContent = Get-Content -Raw $cbsInitLogPath
            $afterLoading = $logContent.IndexOf("Config Drive found on")
            $logContent.substring($afterLoading)
        }
        Remove-PSSession $currentSession -ErrorAction SilentlyContinue
        if ($cloudbaseInitLogs -like "*error*" -or $cloudbaseInitLogs -like "*fail*") {
            Write-Log "Cloudbase-Init logs contain errors: ${cloudbaseInitLogs}"
        } else {
            Write-Log "Cloudbase-Init ran successfuly: ${cloudbaseInitLogs}"
        }
        Write-Log "Online Windows image validation finished."
    } finally {
        Stop-VM -Name $vmName -TurnOff -ErrorAction SilentlyContinue
        Remove-VM -Force -Confirm:$false -Name $vmName -ErrorAction SilentlyContinue
        [array]::Reverse($imageChain)
        foreach ($chainItem in $imageChain) {
            if ($chainItem -ne $windowsImageConfig.image_path) {
                Write-Log "Removing chain file item ${chainItem}"
                Remove-Item -Force $chainItem -ErrorAction SilentlyContinue
            }
        }
    }
}


Export-ModuleMember New-WindowsCloudImage, Get-WimFileImagesInfo, New-MaaSImage, Resize-VHDImage,
    New-WindowsOnlineImage, Add-VirtIODriversFromISO, New-WindowsFromGoldenImage, Get-WindowsImageConfig,
    New-WindowsImageConfig, Test-WindowsImage
