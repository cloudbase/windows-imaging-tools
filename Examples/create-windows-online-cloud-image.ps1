# Copyright 2016 Cloudbase Solutions Srl
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

$scriptPath =Split-Path -Parent $MyInvocation.MyCommand.Definition | Split-Path

git submodule update --init
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

# The Windows image file path that will be generated
$windowsImagePath = "C:\images\my-windows-image.raw.tgz"

# The wim file path is the installation image on the Windows ISO
$wimFilePath = "D:\Sources\install.wim"

# VirtIO ISO contains all the synthetic drivers for the KVM hypervisor
$virtIOISOPath = "C:\images\virtio.iso"
# Note(avladu): Do not use stable 0.1.126 version because of this bug https://github.com/crobinso/virtio-win-pkg-scripts/issues/10
# Note (atira): Here https://fedorapeople.org/groups/virt/virtio-win/CHANGELOG you can see the changelog for the VirtIO drivers
$virtIODownloadLink = "https://fedorapeople.org/groups/virt/virtio-win/direct-downloads/archive-virtio/virtio-win-0.1.141-1/virtio-win-0.1.141.iso"

# Download the VirtIO drivers ISO from Fedora
(New-Object System.Net.WebClient).DownloadFile($virtIODownloadLink, $virtIOISOPath)

# Extra drivers path contains the drivers for the baremetal nodes
# Examples: Chelsio NIC Drivers, Mellanox NIC drivers, LSI SAS drivers, etc.
# The cmdlet will recursively install all the drivers from the folder and subfolders
$extraDriversPath = "C:\drivers\"

# Every Windows ISO can contain multiple Windows flavors like Core, Standard, Datacenter
# Usually, the second image version is the Standard one
$image = (Get-WimFileImagesInfo -WimFilePath $wimFilePath)[1]

# Make sure the switch exists and it allows Internet access if updates
# are to be installed
$switchName = 'external'

# The path were you want to create the config fille
$configFilePath = Join-Path $scriptPath "Examples\config.ini"
New-WindowsImageConfig -ConfigFilePath $configFilePath
$fCfgPath = Resolve-Path $configFilePath

#This is an example how to automate the image configuration file according to your needs
Set-IniFileValue -Path $fCfgPath -Section "Default" -Key "wim_file_path" -Value $wimFilePath
Set-IniFileValue -Path $fCfgPath -Section "Default" -Key "image_name" -Value $image.ImageName
Set-IniFileValue -Path $fCfgPath -Section "Default" -Key "image_path" -Value $windowsImagePath
Set-IniFileValue -Path $fCfgPath -Section "Default" -Key "image_type" -Value "MAAS"
Set-IniFileValue -Path $fCfgPath -Section "Default" -Key "install_maas_hooks" -Value "True"
Set-IniFileValue -Path $fCfgPath -Section "vm" -Key "cpu_count" -Value 4
Set-IniFileValue -Path $fCfgPath -Section "vm" -Key "ram_size" -Value (4GB)
Set-IniFileValue -Path $fCfgPath -Section "vm" -Key "disk_size" -Value (30GB)
Set-IniFileValue -Path $fCfgPath -Section "vm" -Key "external_switch" -Value $switchName
Set-IniFileValue -Path $fCfgPath -Section "drivers" -Key "virtio_iso_path" -Value $virtIOISOPath
Set-IniFileValue -Path $fCfgPath -Section "drivers" -Key "drivers_path" -Value $extraDriversPath
Set-IniFileValue -Path $fCfgPath -Section "updates" -Key "install_updates" -Value "True"
Set-IniFileValue -Path $fCfgPath -Section "updates" -Key "purge_updates" -Value "True"
Set-IniFileValue -Path $fCfgPath -Section "sysprep" -Key "disable_swap" -Value "True"

# This scripts generates a raw tar.gz-ed image file, that can be used with MAAS
New-WindowsOnlineImage -ConfigFilePath $configFilePath
