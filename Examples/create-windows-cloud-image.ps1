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

git submodule update --init
Import-Module ..\WinImageBuilder.psm1

# The Windows image file path that will be generated
$virtualDiskPath = "C:\images\my-windows-image.raw"

# The wim file path is the installation image on the Windows ISO
$wimFilePath = "D:\Sources\install.wim"

# VirtIO ISO contains all the synthetic drivers for the KVM hypervisor
$VirtIOISOPath = "C:\images\virtio.iso"
# Note(avladu): Do not use stable 0.1.126 version because of this bug https://github.com/crobinso/virtio-win-pkg-scripts/issues/10
$virtIODownloadLink = "https://fedorapeople.org/groups/virt/virtio-win/direct-downloads/stable-virtio/virtio-win.iso"

# Download the VirtIO drivers ISO from Fedora
(New-Object System.Net.WebClient).DownloadFile($virtIODownloadLink, $VirtIOISOPath)

# Extra drivers path contains the drivers for the baremetal nodes
# Examples: Chelsio NIC Drivers, Mellanox NIC drivers, LSI SAS drivers, etc.
# The cmdlet will recursively install all the drivers from the folder and subfolders
$extraDriversPath = "C:\drivers\"

# Every Windows ISO can contain multiple Windows flavors like Core, Standard, Datacenter
# Usually, the second image version is the Standard one
$image = (Get-WimFileImagesInfo -WimFilePath $wimFilePath)[1]

# This scripts generates a raw image file that, after being started as an instance and
# after it shuts down, it can be used with Ironic or KVM hypervisor in OpenStack.
New-WindowsCloudImage -WimFilePath $wimFilePath -ImageName $image.ImageName `
    -VirtualDiskPath $virtualDiskPath -SizeBytes 30GB -ProductKey $productKey `
    -VirtualDiskFormat 'RAW' -DiskLayout 'BIOS' -VirtioISOPath $virtIOISOPath `
    -ExtraDriversPath $extraDriversPath -InstallUpdates:$true `
    -AdministratorPassword 'Pa$$w0rd' -InstallMAASHooks:$false `
    -PurgeUpdates:$true -DisableSwap:$true

