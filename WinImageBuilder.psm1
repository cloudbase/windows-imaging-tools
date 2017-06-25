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

$MaaSWindowsSeriesMap = @{
    "Hyper-V Server 2012 R2" = "win2012hvr2";
    "Hyper-V Server 2012" = "win2012hv";
    "Windows Server 2008 R2" = "win2008r2";
    "Windows Server 2012 R2" = "win2012r2";
    "Windows Server 2012" = "win2012";
    "Hyper-V Server 2016" = "win2016hv";
    "Windows Server 2016" = "win2016";
    "Windows Storage Server 2012 R2" = "win2012r2";
    "Windows Storage Server 2012" = "win2012";
    "Windows Storage Server 2016" = "win2016";
    "Windows 7" = "win7";
    "Windows 8.1" = "win81";
    "Windows 8" = "win8";
    "Windows 10"= "win10";
}

$WindowsClients = @(
    "win7", "win81", "win8",
    "win10"
)

$WindowsServers = @(
    "win2012hvr2", "win2012hv", "win2008r2",
    "win2012r2", "win2012", "win2016hv",
    "win2016"
)

$ImageArchitectureMap = @{
    "amd64" = "amd64";
    "x86_64" = "amd64";
    "x64" = "amd64";
    "x86" = "i386";
    "i386" = "i386";
}

. "$scriptPath\Interop.ps1"


function Confirm-GPGKey {
    [CmdletBinding()]
    Param(
        [parameter(Mandatory=$true)]
        [string]$KeyID
    )
    BEGIN {
        $gpgBin = (Get-Command -CommandType Application "gpg.exe").Source
    }
    PROCESS {
        $cmdArgs = @(
            "--list-keys",
            $KeyID
        )
        $output = & $gpgBin $cmdArgs 2>$null
        if ($LASTEXITCODE) {
            Throw ("Failed to validate KeyID: {0}" -f $KeyID)
        }
    }
}

function Export-GPGKey {
    [CmdletBinding()]
    Param(
        [parameter(Mandatory=$true)]
        [string]$KeyID,
        [parameter(Mandatory=$true)]
        [string]$OutFile
    )
    BEGIN {
        $gpgBin = (Get-Command -CommandType Application "gpg.exe").Source
    }
    PROCESS {
        Confirm-GPGKey -KeyID $KeyID
        $cmdArgs = @(
            "--output",
            $OutFile,
            "--export",
            "--batch",
            "--yes",
            $KeyID
        )
        & $gpgBin $cmdArgs | Out-Null
        if ($LASTEXITCODE) {
            Throw "gpg export failed with exit code: $LASTEXITCODE"
        }
    }
}

function Invoke-GPGClearSign {
    [CmdletBinding()]
    Param(
        [parameter(Mandatory=$true)]
        [string]$KeyID,
        [parameter(Mandatory=$false)]
        [string]$Passphrase,
        [parameter(Mandatory=$true)]
        [string]$FilePath,
        [parameter(Mandatory=$true)]
        [string]$OutFile
    )
    BEGIN {
        $gpgBin = (Get-Command -CommandType Application "gpg.exe").Source
    }
    PROCESS {
        Confirm-GPGKey -KeyID $KeyID
        if (!(Test-Path $FilePath)) {
            Throw "Could not find $FilePath"
        }

        $parentDir = Split-Path -Parent $OutFile
        if (!(Test-Path $parentDir)) {
            mkdir $parentDir | Out-Null
        }
        $cmdArgs = @(
            "--clearsign",
            "--yes",
            "--batch",
            "--default-key",
            $KeyID,
            "--output",
            $OutFile
        )
        if (![string]::IsNullOrEmpty($Passphrase)){
            $cmdArgs += "--passphrase=$Passphrase"
        }
        & $gpgBin $cmdArgs $FilePath
        if ($LASTEXITCODE) {
            Throw "GPG returned error code $LASTEXITCODE"
        }
        if (!(Test-Path $outFile)) {
            Throw "Failed to generate signed file for $FilePath"
        }
        return $outFile
    }
}

function New-SimpleStreamsFolderLayout {
    [CmdletBinding()]
    Param(
        [parameter(Mandatory=$true)]
        [string]$Series,
        [parameter(Mandatory=$true)]
        [ValidateSet("i386", "amd64")]
        [string]$Architecture,
        [parameter(Mandatory=$true)]
        [string]$Location
    )
    PROCESS {
        $date = Get-Date -Format yyyyMMdd
        if (!(Test-Path $Location)) {
            mkdir $Location | Out-Null
        }
        $streamsLocation = "{0}/streams/v1" -f $Location
        if(!(Test-Path $streamsLocation)) {
            mkdir $streamsLocation | Out-Null
        }
        $imgLocation = "{0}\{1}\{2}\{3}" -f @($Location, $series, $Architecture, $date)
        $imgLocation = [System.IO.Path]::GetFullPath($imgLocation)
        if (!(Test-Path $imgLocation)) {
            mkdir $imgLocation | Out-Null
        }
        return $imgLocation
    }
}

function Get-Series {
    [CmdletBinding()]
    Param(
        [parameter(Mandatory=$true)]
        [string]$VersionName
    )
    PROCESS {
        foreach($ver in $MaaSWindowsSeriesMap.GetEnumerator()){
            if($VersionName.StartsWith($ver.Key)) {
                return $ver.Value
            }
        }
        Throw "Could not determine series fir version $VersionName"
    }
}

function Invoke-GenerateSimplestreams {
    [CmdletBinding()]
    Param(
        [parameter(Mandatory=$true)]
        [string]$Location
    )
    PROCESS{
        $streams = Join-Path $Location "streams/v1"
        if(!(Test-Path $streams)) {
            mkdir $streams
        }
        $indexPath = Join-Path $streams "index.json"
        $productIndexPath = Join-Path $streams "it.cloudbase.maas-release-windows-images-download.json"
        $indexName = "it.cloudbase.maas:release:windows-images-download"
        $index = @{
            "index" = @{
                $indexName = @{
                    "datatype" = "image-ids";
                    "path" =  "streams/v1/it.cloudbase.maas-release-windows-images-download.json"
                    "updated" = (Get-Date -Format r).ToString();
                    "format" = "products:1.0";
                }
            }
        }
        $downloadSource = @{
            "content_id" = "it.cloudbase.maas:release:windows-images-download";
            "datatype" = "image-ids";
            "format" = "products:1.0";
        }
        $productNames = @()
        $products = @{}
        $folders = Get-ChildItem -Directory -Path $Location
        foreach($folder in $folders) {
            if($folder.Name -in $MaaSWindowsSeriesMap.Values){
                $architectures = Get-ChildItem -Directory -Path $folder.FullName
                if(!$architectures) {
                    continue
                }
                foreach($arch in $architectures) {
                    $versions = Get-ChildItem -Directory -Path $arch.FullName

                    if (!$versions) {
                        continue
                    }
                    $productType = "windows-client"
                    if ($folder.Name -in $WindowsServers) {
                        $productType = "windows-server"
                    }
                    $productName = "it.cloudbase.maas:release:{0}:{1}:{2}" -f @(
                            $productType, $folder.Name, $arch.Name
                        )
                    $productNames += $productName
                    $products[$productName] = @{
                        "arch" = $arch.Name.ToLower();
                        "label" = "release";
                        "os" = "windows";
                        "release" = $folder.Name;
                        "subarch" = "generic";
                        "subarches" = "generic";
                        "version" = $folder.Name;
                        "versions" = @{};
                    }
                    foreach($version in $versions) {
                        $rootDisk = Join-Path $version.FullName "root-dd"
                        if(!(Test-Path $rootDisk)) {
                            continue
                        }
                        $rootDiskDetails = Get-Item $rootDisk
                        $diskHash = (Get-FileHash -Path $rootDisk -Algorithm SHA256).Hash.ToLower()
                        $diskPath = "{0}/{1}/{2}/root-dd" -f @($folder.Name, $arch.Name, $version.Name)

                        $ver = @{
                            "items" = @{
                                "root-image.gz" = @{
                                    "ftype" = "root-dd";
                                    "path" = $diskPath;
                                    "sha256" = $diskHash;
                                    "size" = $rootDiskDetails.Length;
                                }
                            }
                        }
                        $products[$productName]["versions"][$version.Name] = $ver
                    }
                }
            }
        }
        $downloadSource["products"] = $products
        $index["index"][$indexName]["products"] = $productNames
        Set-Content -NoNewline -Encoding String `
                    -Path $productIndexPath `
                    -Value ((ConvertTo-Json -Compress -Depth 100 $downloadSource) -replace "`r`n","`n")
        Set-Content -NoNewline -Encoding String `
                    -Path $indexPath `
                    -Value ((ConvertTo-Json -Compress -Depth 100 $index) -replace "`r`n","`n")
    }
}

function Invoke-SignSimpleStreams {
    [CmdletBinding()]
    Param(
        [parameter(Mandatory=$true)]
        [string]$Location,
        [parameter(Mandatory=$true)]
        [string]$GPGKey,
        [parameter(Mandatory=$false)]
        [string]$GPGKeyPassPhrase
    )
    PROCESS {
        $streams = Join-Path $Location "streams/v1"
        $files = Get-ChildItem -Path $streams -Filter "*.json"
        $index = $null
        $indexPath = $null
        $signMap = @{}
        if ($files.Length -gt 0) {
            foreach($i in $files.FullName) {
                if ($i.EndsWith("index.json")) {
                    $index = ConvertFrom-Json (Get-Content -Raw $i)
                    $indexPath = $i
                    continue
                }
                $signedPath = (Get-PathWithoutExtension $i) + ".sjson"
                $gpgKeychain = (Get-PathWithoutExtension $i) + ".gpg"

                $relativeUnsignedPath = ($i.Replace($Location,"")).TrimStart("\").Replace("\","/")
                $relativeSignedPath = ($signedPath.Replace($Location,"")).TrimStart("\").Replace("\","/")
                $signMap[$relativeUnsignedPath] = $relativeSignedPath
                Invoke-GPGClearSign -KeyID $GPGKey `
                                    -Passphrase $GPGKeyPassPhrase `
                                    -FilePath $i `
                                    -OutFile $signedPath | Out-Null
                Export-GPGKey -KeyID $GPGKey `
                              -OutFile $gpgKeychain
            }
        }
        if($index -and $indexPath) {
            foreach ($i in ($index.index| Get-Member -MemberType "*Property").Name) {
                $product = $($index.index.$i)
                if ($signMap[$product.path]) {
                    $product.Path = $signMap[$product.path]
                }
            }
            $tmpIndex = [System.IO.Path]::GetTempFileName()
            $signedPath = (Get-PathWithoutExtension $indexPath) + ".sjson"
            $gpgKeychain = (Get-PathWithoutExtension $indexPath) + ".gpg"
            Set-Content -NoNewline -Encoding String `
                        -Path $tmpIndex `
                        -Value ((ConvertTo-Json -Compress -Depth 100 $index) -replace "`r`n","`n")
            Invoke-GPGClearSign -KeyID $GPGKey `
                                -Passphrase $GPGKeyPassPhrase `
                                -FilePath $tmpIndex `
                                -OutFile $signedPath | Out-Null
            Export-GPGKey -KeyID $GPGKey `
                          -OutFile $gpgKeychain
        }
    }
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
                Please run git submodule update --init "
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
        [switch]$BetaRelease
    )
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

        $image = Get-WimImage -Config $windowsImageConfig
        if ($windowsImageConfig.image_type -eq "MAAS") {
            $rawImagePath = $barePath + ".img"
            Write-Host "Converting VHD to RAW"
            Convert-VirtualDisk $virtualDiskPath $rawImagePath "raw"
            Remove-Item -Force $virtualDiskPath
            Compress-Image $rawImagePath $windowsImageConfig['image_path']
            $parentDir = Split-Path -Parent $windowsImageConfig['image_path']
            if($windowsImageConfig.generate_simplestreams) {
                $arch = $ImageArchitectureMap[$image.ImageArchitecture.ToString()]
                $series = Get-Series -VersionName $windowsImageConfig.image_name
                $imgLocation = New-SimpleStreamsFolderLayout -Series $series `
                                                             -Architecture $arch `
                                                             -Location $parentDir
                $dstFileName = Join-Path $imgLocation "root-dd"
                Write-Host $windowsImageConfig.image_path $dstFileName
                Move-Item -Force $windowsImageConfig.image_path $dstFileName
                Invoke-GenerateSimplestreams -Location $parentDir
                if($windowsImageConfig.sign_simplestreams) {
                    Invoke-SignSimpleStreams -Location $parentDir `
                                             -GPGKey $windowsImageConfig.gpg_signing_key `
                                             -GPGKeyPassPhrase $windowsImageConfig.gpg_passphrase
                }
            }
        }

        if ($windowsImageConfig.image_type -eq "KVM") {
            $qcow2ImagePath = $barePath + ".qcow2"
            Write-Host "Converting VHD to QCow2"
            Convert-VirtualDisk $virtualDiskPath $qcow2ImagePath "qcow2"
            if ($windowsImageConfig.zip_password) {
                New-ProtectedZip -ZipPassword $windowsImageConfig.zip_password -VirtualDiskPath $qcow2ImagePath
            }
            Remove-Item -Force $virtualDiskPath
        }
    } catch {
        if ($windowsImageConfig -and $windowsImageConfig.image_path -and (Test-Path $windowsImageConfig.image_path)) {
            Remove-Item -Force ${windowsImageConfig.image_path} -ErrorAction SilentlyContinue
        }
        Throw
    }
    Write-Host ("Windows online image generation finished at: {0}" -f @((Get-Date)))
}

function Get-WimImage {
    [CmdletBinding()]
    Param(
        [parameter(Mandatory=$true, ValueFromPipeline=$true)]
        [object]$Config
    )
    PROCESS {
        $image = Get-WimFileImagesInfo -WimFilePath $Config.wim_file_path | `
            Where-Object { $_.ImageName -eq $Config.image_name }
        if (!$image) {
            throw ("Image {0} not found in WIM file {1}" -f @($Config.image_name, $Config.wim_file_path))
        }
        return $image
    }
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
    $image = Get-WimImage -Config $windowsImageConfig

    Check-DismVersionForImage $image

    Write-Host $windowsImageConfig.image_path
    if (Test-Path $windowsImageConfig.image_path) {
        Write-Host ("Removing {0}" -f $windowsImageConfig.image_path)
        Remove-Item -Force $windowsImageConfig.image_path
    }

    if ($windowsImageConfig.virtual_disk_format -in @("VHD", "VHDX")) {
        $vhdPath = $windowsImageConfig.image_path
    } else {
        $vhdPath = "{0}.vhd" -f (Get-PathWithoutExtension $windowsImageConfig.image_path)
        if (Test-Path $vhdPath) { Remove-Item -Force $vhdPath }
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
        Copy-Item $ConfigFilePath "$resourcesDir\config.ini"
        Download-CloudbaseInit $resourcesDir ([string]$image.ImageArchitecture) -BetaRelease:$windowsImageConfig.beta_release
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

    if ($vhdPath -ne $windowsImageConfig.image_path) {
        Convert-VirtualDisk $vhdPath $windowsImageConfig.image_path $windowsImageConfig.virtual_disk_format
        if ($windowsImageConfig.zip_password) {
            New-ProtectedZip -ZipPassword $windowsImageConfig.zip_password -virtualDiskPath $windowsImageConfig.image_path
        }
        Remove-Item -Force $vhdPath
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

        if ($windowsImageConfig.drivers_path) {
            Dism /Image:$driveLetterGold /Add-Driver /Driver:$windowsImageConfig.drivers_path `
                /ForceUnsigned /Recurse
        }

        $resourcesDir = Join-Path -Path $driveLetterGold -ChildPath "UnattendResources"
        Copy-UnattendResources -resourcesDir $resourcesDir -imageInstallationType $windowsImageConfig.image_name
        Copy-Item $ConfigFilePath "$resourcesDir\config.ini"
        Download-CloudbaseInit $resourcesDir $imageInfo.imageArchitecture -BetaRelease:$windowsImageConfig.beta_release
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
