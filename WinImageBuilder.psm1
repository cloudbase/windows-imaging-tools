$ErrorActionPreference = "Stop"
Set-StrictMode -Version 2
Import-Module Dism

$scriptPath = Split-Path -Parent $MyInvocation.MyCommand.Definition
$localResourcesDir = "$scriptPath\UnattendResources"
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

. "$scriptPath\Interop.ps1"

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
        Remove-Item -Force "$resourcesDir\Wallpaper.png"
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
    if ($image.ImageVersion.Major -eq 6 -and $image.ImageVersion.Minor -eq 0) {
        $virtioVer = "2k8"
    } elseif ($image.ImageVersion.Major -eq 6 -and $image.ImageVersion.Minor -eq 1) {
        if (Is-ServerInstallationType $image) {
            $virtioVer = "2k8r2"
        } else {
            $virtioVer = "w7"
        }
    } elseif ($image.ImageVersion.Major -eq 6 -and $image.ImageVersion.Minor -eq 2) {
        if (Is-ServerInstallationType $image) {
            $virtioVer = "2k12"
        } else {
            $virtioVer = "w8"
        }
    } elseif (($image.ImageVersion.Major -eq 6 -and $image.ImageVersion.Minor -ge 3) `
        -or $image.ImageVersion.Major -gt 6) {
        if (Is-ServerInstallationType $image) {
            $virtioVer = "2k12R2"
        } else {
            $virtioVer = "w8.1"
        }
    } else {
        throw "Unsupported Windows version for VirtIO drivers: {0}" `
            -f $image.ImageVersion
    }

    $drivers = @("Balloon", "NetKVM", "viorng", "vioscsi", "vioserial", "viostor")
    foreach ($driver in $drivers) {
        $virtioDir = "{0}\{1}\{2}\{3}" -f $driversBasePath, $driver, $virtioVer, $image.ImageArchitecture
        if (Test-Path $virtioDir) {
            Add-DriversToImage $vhdDriveLetter $virtioDir
        }
    }
}

function Add-VirtIODriversFromISO {
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

    $7zip = Join-Path $localResourcesDir 7za.exe
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

function Resize-VHDImage {
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
            $local:i = 0
            $step = 100MB
            Execute-Retry {
                $sizeIncreased = ($NewSize + ($step * $i))
                Write-Host "Size increased: $sizeIncreased"
                $i = $i + 1
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

function New-MaaSImage {
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
        [ValidateSet("BIOS", "UEFI", ignorecase=$false)]
        [string]$DiskLayout = "BIOS",
        [ValidatePattern("^\S{5}-\S{5}-\S{5}-\S{5}-\S{5}")]
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
        [array]$ExtraFeatures = @(),
        [parameter(Mandatory=$false)]
        [string]$ExtraDriversPath,
        [parameter(Mandatory=$false)]
        [Uint64]$Memory=2GB,
        [parameter(Mandatory=$false)]
        [int]$CpuCores=1,
        [parameter(Mandatory=$false)]
        [switch]$RunSysprep=$true,
        [parameter(Mandatory=$false)]
        [string]$SwitchName,
        [parameter(Mandatory=$false)]
        [switch]$Force=$false,
        [parameter(Mandatory=$false)]
        [switch]$PurgeUpdates,
        [parameter(Mandatory=$false)]
        [switch]$DisableSwap
    )
    
    PROCESS
    {
        New-WindowsOnlineImage -Type "MAAS" -WimFilePath $WimFilePath -ImageName $ImageName `
            -WindowsImagePath $MaaSImagePath -SizeBytes $SizeBytes -DiskLayout $DiskLayout `
            -ProductKey $ProductKey -VirtIOISOPath $VirtIOISOPath -InstallUpdates:$InstallUpdates `
            -AdministratorPassword $AdministratorPassword -PersistDriverInstall:$PersistDriverInstall `
            -ExtraDriversPath $ExtraDriversPath -Memory $Memory -CpuCores $CpuCores `
            -RunSysprep:$RunSysprep -SwitchName $SwitchName -Force:$Force -PurgeUpdates:$PurgeUpdates `
            -DisableSwap:$DisableSwap
    }
}

function New-WindowsOnlineImage {
    [CmdletBinding()]
    param
    (
        [parameter(Mandatory=$true, ValueFromPipeline=$true)]
        [string]$WimFilePath = "D:\Sources\install.wim",
        [parameter(Mandatory=$true)]
        [string]$ImageName,
        [parameter(Mandatory=$true)]
        [string]$WindowsImagePath,
        [parameter(Mandatory=$true)]
        [Uint64]$SizeBytes,
        [ValidateSet("BIOS", "UEFI", ignorecase=$false)]
        [string]$DiskLayout = "BIOS",
        [parameter(Mandatory=$false)]
        [string]$ProductKey,
        [parameter(Mandatory=$false)]
        [string]$VirtIOISOPath,
        [parameter(Mandatory=$false)]
        [switch]$InstallUpdates,
        [parameter(Mandatory=$false)]
        [string]$AdministratorPassword = "Pa`$`$w0rd",
        [array]$ExtraFeatures = @(),
        [parameter(Mandatory=$false)]
        [string]$ExtraDriversPath,
        [parameter(Mandatory=$false)]
        [switch]$PersistDriverInstall = $true,
        [parameter(Mandatory=$false)]
        [Uint64]$Memory=2GB,
        [parameter(Mandatory=$false)]
        [int]$CpuCores=1,
        [parameter(Mandatory=$false)]
        [switch]$RunSysprep=$true,
        [parameter(Mandatory=$false)]
        [string]$SwitchName,
        [parameter(Mandatory=$false)]
        [switch]$Force=$false,
        [ValidateSet("MAAS", "KVM", "HYPER-V", ignorecase=$false)]
        [string]$Type = "MAAS",
        [parameter(Mandatory=$false)]
        [switch]$PurgeUpdates,
        [parameter(Mandatory=$false)]
        [switch]$DisableSwap
    )
    PROCESS
    {
        Write-Host ("Windows online image generation started at: {0}" -f @(Get-Date))
        Is-Administrator
        if (!$RunSysprep -and !$Force) {
            throw "You chose not to run sysprep.
                This will build an unusable MaaS image.
                If you really want to continue use the -Force:$true flag."
        }

        Check-Prerequisites
        if ($SwitchName) {
            $switch = Get-VMSwitch -Name $SwitchName -ErrorAction SilentlyContinue
            if (!$switch) {
                throw "Selected vmswitch ($SwitchName) does not exist"
            }
            if ($switch.SwitchType -ne "External" -and !$Force) {
                throw "Selected switch ($SwitchName) is not an external
                    switch. If you really want to continue use the -Force:$true flag."
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
        if ($CpuCores -gt $cpuCount) {
            Write-Warning "CpuCores larger then available (logical) CPU cores.
                Setting CpuCores to $coreCount"
            $CpuCores = $coreCount
        }

        try {
            $barePath = Get-PathWithoutExtension $WindowsImagePath
            $VirtualDiskPath = $barePath + ".vhdx"
            $InstallMaaSHooks = $false
            if ($Type -eq "MAAS") {
                $InstallMaaSHooks = $true
            }
            if ($Type -eq "KVM") {
                $PersistDriverInstall = $false
            }
            New-WindowsCloudImage -WimFilePath $WimFilePath -ImageName $ImageName `
                -VirtualDiskPath $VirtualDiskPath -SizeBytes $SizeBytes -ProductKey $ProductKey `
                -VirtIOISOPath $VirtIOISOPath -InstallUpdates:$InstallUpdates `
                -AdministratorPassword $AdministratorPassword -PersistDriverInstall:$PersistDriverInstall `
                -InstallMaaSHooks:$InstallMaaSHooks -ExtraFeatures $ExtraFeatures -ExtraDriversPath $ExtraDriversPath `
                -DiskLayout $DiskLayout -PurgeUpdates:$PurgeUpdates -DisableSwap:$DisableSwap

            if ($RunSysprep) {
                if($DiskLayout -eq "UEFI") {
                    $generation = "2"
                } else {
                    $generation = "1"
                }

                $Name = "WindowsOnlineImage-Sysprep" + (Get-Random)
                Run-Sysprep -Name $Name -Memory $Memory -VHDPath $VirtualDiskPath `
                    -VMSwitch $switch.Name -CpuCores $CpuCores `
                    -Generation $generation
            }

            Resize-VHDImage $VirtualDiskPath

            if ($Type -eq "MAAS") {
                $RawImagePath = $barePath + ".img"
                Write-Host "Converting VHD to RAW"
                Convert-VirtualDisk $VirtualDiskPath $RawImagePath "RAW"
                Remove-Item -Force $VirtualDiskPath
                Compress-Image $RawImagePath $WindowsImagePath
            }

            if ($Type -eq "KVM") {
                $Qcow2ImagePath = $barePath + ".qcow2"
                Write-Host "Converting VHD to QCow2"
                Convert-VirtualDisk $VirtualDiskPath $Qcow2ImagePath "qcow2"
                Remove-Item -Force $VirtualDiskPath
            }
        } catch {
            Remove-Item -Force $WindowsImagePath* -ErrorAction SilentlyContinue
            Throw
        }
        Write-Host ("Windows online image generation finished at: {0}" -f @((Get-Date)))
    }

}

function New-WindowsCloudImage {
    [CmdletBinding()]
    Param(
        [parameter(Mandatory=$true, ValueFromPipeline=$true)]
        [string]$WimFilePath = "D:\Sources\install.wim",
        [parameter(Mandatory=$true)]
        [string]$ImageName,
        [parameter(Mandatory=$true)]
        [string]$VirtualDiskPath,
        [parameter(Mandatory=$true)]
        [Uint64]$SizeBytes,
        [ValidatePattern("^$|^\S{5}-\S{5}-\S{5}-\S{5}-\S{5}")]
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
        [array]$ExtraFeatures = @(),
        [parameter(Mandatory=$false)]
        [string]$ExtraDriversPath,
        [parameter(Mandatory=$false)]
        [switch]$InstallUpdates,
        [parameter(Mandatory=$false)]
        [string]$AdministratorPassword = "Pa`$`$w0rd",
        [parameter(Mandatory=$false)]
        [string]$UnattendXmlPath = "$scriptPath\UnattendTemplate.xml",
        [parameter(Mandatory=$false)]
        [switch]$PersistDriverInstall = $true,
        [parameter(Mandatory=$false)]
        [switch]$InstallMaaSHooks,
        [parameter(Mandatory=$false)]
        [string]$VirtIOBasePath,
        [parameter(Mandatory=$false)]
        [switch]$PurgeUpdates,
        [parameter(Mandatory=$false)]
        [switch]$DisableSwap
    )

    PROCESS
    {
        Write-Host ("Image generation started at: {0}" -f @(Get-Date))
        Set-DotNetCWD
        Is-Administrator

        $image = Get-WimFileImagesInfo -WimFilePath $wimFilePath | `
            Where { $_.ImageName -eq $ImageName }
        if (!$image) {
            throw 'Image "$ImageName" not found in WIM file "$WimFilePath"'
        }
        Check-DismVersionForImage $image

        if (Test-Path $VirtualDiskPath) {
            Remove-Item -Force $VirtualDiskPath
        }

        if ($VirtualDiskFormat -in @("VHD", "VHDX")) {
            $VHDPath = $VirtualDiskPath
        } else {
            $VHDPath = "{0}.vhd" -f (Get-PathWithoutExtension $VirtualDiskPath)
            if (Test-Path $VHDPath) { Remove-Item -Force $VHDPath }
        }

        try {
            $drives = Create-ImageVirtualDisk $VHDPath $SizeBytes $DiskLayout
            $winImagePath = "$($drives[1])\"
            $resourcesDir = "${winImagePath}UnattendResources"
            $unattedXmlPath = "${winImagePath}Unattend.xml"
            $configValues = @{
                "InstallUpdates"=$InstallUpdates;
                "PersistDriverInstall"=$PersistDriverInstall;
                "PurgeUpdates"=$PurgeUpdates;
                "DisableSwap"=$DisableSwap;
            }

            Generate-UnattendXml $UnattendXmlPath $unattedXmlPath $image $ProductKey $AdministratorPassword
            Copy-UnattendResources $resourcesDir $image.ImageInstallationType $InstallMaaSHooks
            Generate-ConfigFile $resourcesDir $configValues
            Download-CloudbaseInit $resourcesDir ([string]$image.ImageArchitecture)
            Apply-Image $winImagePath $wimFilePath $image.ImageIndex
            Create-BCDBootConfig $drives[0] $drives[1] $DiskLayout $image
            Check-EnablePowerShellInImage $winImagePath $image

            if ($ExtraDriversPath -and (Test-Path $ExtraDriversPath)) {
                Add-DriversToImage $winImagePath $ExtraDriversPath
            }
            if ($VirtIOISOPath) {
                Add-VirtIODriversFromISO $winImagePath $image $VirtIOISOPath
            }
            if ($VirtIOBasePath) {
                Add-VirtIODrivers $winImagePath $image $VirtIOBasePath
            }
            if ($ExtraFeatures) {
                Enable-FeaturesInImage $winImagePath $ExtraFeatures
            }
        } finally {
            if (Test-Path $VHDPath) {
                Detach-VirtualDisk $VHDPath
            }
        }

        if ($VHDPath -ne $VirtualDiskPath) {
            Convert-VirtualDisk $VHDPath $VirtualDiskPath $VirtualDiskFormat
            Remove-Item -Force $VHDPath
        }
        Write-Host ("Image generation finished at: {0}" -f @(Get-Date))
    }
}

Export-ModuleMember New-WindowsCloudImage, Get-WimFileImagesInfo, New-MaaSImage, Resize-VHDImage,
    New-WindowsOnlineImage

