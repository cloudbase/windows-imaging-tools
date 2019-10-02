# Copyright 2019 Cloudbase Solutions Srl
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
#
# Module manifest for module 'WindowsImageBuilder'
#
# Generated by: Adrian Vladu
#
# Generated on: 19/08/2019
#

@{

# Script module or binary module file associated with this manifest.
RootModule = 'UnattendResources\PSModules\WinImageBuilder.psm1'

# Version number of this module.
ModuleVersion = '0.2'

# ID used to uniquely identify this module
GUID = '6a64b662-7f53-425a-9777-ee61284407da'

# Author of this module
Author = 'Alessandro Pilotti', 'Adrian Vladu'

# Company or vendor of this module
CompanyName = 'Cloudbase Solutions SRL'

# Copyright statement for this module
Copyright = '(c) 2019 Cloudbase Solutions SRL. All rights reserved.'

# Description of the functionality provided by this module
Description = 'Powershell module to automate Windows image generation for OpenStack, MAAS, KVM, HyperV, ESXi and more.'

# Minimum version of the Windows PowerShell engine required by this module
PowerShellVersion = '4.0'

# Functions to export from this module
FunctionsToExport = "New-WindowsCloudImage", "New-WindowsOnlineImage", "New-WindowsFromGoldenImage",
     "Get-WindowsImageConfig", "New-WindowsImageConfig", "Test-OfflineWindowsImage",
     "Resize-VHDImage", "Set-IniFileValue", "Get-IniFileValue", "Remove-IniFileValue"

AliasesToExport = ""
}