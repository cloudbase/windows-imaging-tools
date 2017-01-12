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
$WindowsImageTargetPath = "C:\images\my-windows-image.raw.tgz"

# The VHDX file path is the golden image already generated
$WindowsImageVHDXPath = "D:\Golden\golden_image.vhdx"

# Extra drivers path contains the drivers for the baremetal nodes
# Examples: Chelsio NIC Drivers, Mellanox NIC drivers, LSI SAS drivers, etc.
# The cmdlet will recursively install all the drivers from the folder and subfolders
$extraDriversPath = "C:\drivers\"

# Make sure the switch exists and it allows Internet access if updates
# are to be installed
$switchName = 'external'

# This scripts generates a raw tar.gz-ed image file, that can be used with MAAS
New-WindowsFromGoldenImage -WindowsImageVHDXPath $WindowsImageVHDXPath `
-WindowsImageTargetPath $WindowsImageTargetPath -SizeBytes 30GB -CpuCores 4 `
-Memory 4GB -SwitchName $switchName -PurgeUpdates:$true -DisableSwap:$true `
-InstallUpdates:$true -$ExtraFeatures = @() -Type 'MAAS' `
-ExtraDriversPath $extraDriversPath
