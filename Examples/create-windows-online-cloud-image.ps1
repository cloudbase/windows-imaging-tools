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

git clone https://github.com/cloudbase/windows-openstack-imaging-tools.git
pushd windows-openstack-imaging-tools
git submodule update --init
Import-Module .\WinImageBuilder.psm1

# The Windows image file path that will be generated
$virtualDiskPath = "C:\images\my-windows-image.raw"

# The wim file path is the installation image on the Windows ISO
$wimFilePath = "D:\Sources\install.wim"

# VirtIO ISO contains all the synthetic drivers for the KVM hypervisor
$VirtIOISOPath = "C:\images\virtio.iso"
$virtIODownloadLink = "https://fedorapeople.org/groups/virt/virtio-win/direct-downloads/archive-virtio/virtio-win-0.1.126-2/virtio-win.iso"

# Download the VirtIO drivers ISO from Fedora
(New-Object System.Net.WebClient).DownloadFile($virtIODownloadLink, $VirtIOISOPath)

# Extra drivers path contains the drivers for the baremetal nodes
# Examples: Chelsio NIC Drivers, Mellanox NIC drivers, LSI SAS drivers, etc.
# The cmdlet will recursively install all the drivers from the folder and subfolders
$extraDriversPath = "C:\drivers\"

# Every Windows ISO can contain multiple Windows flavors like Core, Standard, Datacenter
# Usually, the second image version is the Standard one
$image = (Get-WimFileImagesInfo -WimFilePath $wimFilePath)[1]

# This scripts generates a raw image file that can be directly used with Ironic or KVM hypervisor in OpenStack.
New-WindowsOnlineImage -WimFilePath $wimFilePath -ImageName $image.Name `
    -WindowsImagePath $windowsImagePath -Type 'MAAS' -ExtraFeatures @() `
    -SizeBytes 30GB -CpuCores 4 -Memory 4GB -SwitchName 'external'
    -ProductKey $productKey -DiskLayout 'BIOS' -VirtioISOPath $virtIOISOPath `
    -ExtraFeatures @("Hyper-V") -ExtraDriversPath $extraDriversPath `
    -InstallUpdates:$true -AdministratorPassword 'Pa$$w0rd' `
    -PurgeUpdates:$true -DisableSwap:$true

popd

