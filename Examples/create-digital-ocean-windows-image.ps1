# Copyright 2018 Cloudbase Solutions Srl
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
param(
    [parameter(Mandatory=$true)]
    [string] $WinIsoPath,
    [string] $BaseImageDir = $env:TEMP,
    [string] $HyperVSwitchName = "external"
)

$ErrorActionPreference = "Stop"
$scriptPath = Split-Path -Parent $MyInvocation.MyCommand.Definition | Split-Path

if (!(Test-Path $WinIsoPath)) {
    throw "Windows ISO path ${WinIsoPath} does not exist."
}
if (!(Get-VMSwitch $HyperVSwitchName -ErrorAction SilentlyContinue)) {
    throw "HyperV switch ${HyperVSwitchName} could not be found.`nPlease enable HyperV module and create ${HyperVSwitchName} switch."
}

git -C $scriptPath submodule update --init
if ($LASTEXITCODE) {
    throw "Failed to update git modules."
}

try {
    Join-Path -Path $scriptPath -ChildPath "\WinImageBuilder.psm1" | Remove-Module -ErrorAction SilentlyContinue
    Join-Path -Path $scriptPath -ChildPath "\Config.psm1" | Remove-Module -ErrorAction SilentlyContinue
    Join-Path -Path $scriptPath -ChildPath "\UnattendResources\ini.psm1" | Remove-Module -ErrorAction SilentlyContinue
} finally {
    Join-Path -Path $scriptPath -ChildPath "\WinImageBuilder.psm1" | Import-Module
    Join-Path -Path $scriptPath -ChildPath "\Config.psm1" | Import-Module
    Join-Path -Path $scriptPath -ChildPath "\UnattendResources\ini.psm1" | Import-Module
}

# Make sure the BaseDir exists
New-Item -Type Directory $BaseImageDir -ErrorAction SilentlyContinue

if (!(Test-Path $BaseImageDir)) {
    throw "Failed to create ${BaseImageDir}."
}

# The Windows image file path that will be generated
$windowsImagePath = Join-Path $BaseImageDir "digital-ocean-image"

# The wim file path is the installation image on the Windows ISO
$isoDriveLetter = (Mount-DiskImage $WinIsoPath -PassThru | Get-Volume).DriveLetter
$wimFilePath = Join-Path "${isoDriveLetter}:" "Sources\install.wim"
Get-PSDrive | Out-Null

if (!(Test-Path $wimFilePath)) {
    throw "Windows wim path ${wimFilePath} does not exist."
}

# VirtIO ISO contains all the synthetic drivers for the KVM hypervisor
$virtIOISOPath = Join-Path $BaseImageDir "virtio.iso"
$virtIODownloadLink = "https://fedorapeople.org/groups/virt/virtio-win/direct-downloads/archive-virtio/virtio-win-0.1.160-1/virtio-win-0.1.160.iso"

# Download the VirtIO drivers ISO from Fedora
Write-Host "Downloading ${virtIODownloadLink} to ${virtIOISOPath}"
(New-Object System.Net.WebClient).DownloadFile($virtIODownloadLink, $virtIOISOPath)

# Every Windows ISO can contain multiple Windows flavors like Core, Standard, Datacenter
# Usually, the first image version is the Core or Home one
$image = (Get-WimFileImagesInfo -WimFilePath $wimFilePath)[0]
Write-Host "Generating image name: $($image.ImageName)"

# The path were you want to create the config fille
$configFilePath = Join-Path $scriptPath "Examples\config.ini"
New-WindowsImageConfig -ConfigFilePath $configFilePath

# This is an example how to automate the image configuration file according to your needs
Set-IniFileValue -Path $configFilePath -Section "Default" -Key "wim_file_path" -Value $wimFilePath
Set-IniFileValue -Path $configFilePath -Section "Default" -Key "image_name" -Value $image.ImageName
Set-IniFileValue -Path $configFilePath -Section "Default" -Key "image_path" -Value $windowsImagePath
Set-IniFileValue -Path $configFilePath -Section "Default" -Key "image_type" -Value "HYPERV"
Set-IniFileValue -Path $configFilePath -Section "Default" -Key "compression_format" -Value "gz"
Set-IniFileValue -Path $configFilePath -Section "drivers" -Key "virtio_iso_path" -Value $virtIOISOPath
Set-IniFileValue -Path $configFilePath -Section "updates" -Key "install_updates" -Value "True"
Set-IniFileValue -Path $configFilePath -Section "updates" -Key "purge_updates" -Value "True"
Set-IniFileValue -Path $configFilePath -Section "sysprep" -Key "disable_swap" -Value "True"
Set-IniFileValue -Path $configFilePath -Section "cloudbase_init" -Key "beta_release" -Value "True"
Set-IniFileValue -Path $configFilePath -Section "vm" -Key "cpu_count" -Value 4
Set-IniFileValue -Path $configFilePath -Section "vm" -Key "ram_size" -Value (4GB)
Set-IniFileValue -Path $configFilePath -Section "vm" -Key "disk_size" -Value (30GB)
Set-IniFileValue -Path $configFilePath -Section "vm" -Key "external_switch" -Value $HyperVSwitchName

# This scripts generates a vhdx gziped image file, that can be used with Digital Ocean
New-WindowsOnlineImage -ConfigFilePath $configFilePath

Write-Host "The image has been successfully generated."
Write-Host "Image path: ${windowsImagePath}.vhdx.gz"
