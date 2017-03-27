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

$scriptPath = Split-Path -Parent $MyInvocation.MyCommand.Definition
$localResourcesDir = "$scriptPath\UnattendResources"
Import-Module "$localResourcesDir\ini.psm1"

function Get-availableConfigOptionOptions {
    return @(
        @{"Name" = "wim_file_path"; "DefaultValue" = "D:\Sources\install.wim";
          "Description" = "Wim file path."},
        @{"Name" = "image_name"; "DefaultValue" = "Windows Server 2012 R2 SERVERSTANDARD";
          "Description" = "Wim image name"},
        @{"Name" = "image_path"; "DefaultValue" = "${ENV:TEMP}\win-image.vhdx";
          "Description" = "Image path"},
        @{"Name" = "virtual_disk_format"; "DefaultValue" = "VHDX";
          "Description" = "Virtual disk format"},
        @{"Name" = "image_type"; "DefaultValue" = "HYPER-V";
          "Description" = ""},
        @{"Name" = "disk_layout"; "DefaultValue" = "BIOS";
          "Description" = ""},
        @{"Name" = "product_key";
          "Description" = ""},
        @{"Name" = "extra_features";
          "Description" = ""},
        @{"Name" = "force"; "DefaultValue" = $false; "AsBoolean" = $true;
          "Description" = ""},
        @{"Name" = "install_maas_hooks"; "DefaultValue" = $false; "AsBoolean" = $true;
          "Description" = ""},
        @{"Name" = "zip_password";
          "Description" = ""},
        @{"Name" = "administrator_password"; "GroupName" = "vm"; "DefaultValue" = "Pa`$`$w0rd";
          "Description" = ""},
        @{"Name" = "external_switch"; "GroupName" = "vm"; "DefaultValue" = "external";
          "Description" = ""},
        @{"Name" = "cpu_count"; "GroupName" = "vm"; "DefaultValue" = "1";
          "Description" = ""},
        @{"Name" = "ram_size"; "GroupName" = "vm"; "DefaultValue" = "2147483648";
          "Description" = ""},
        @{"Name" = "disk_size"; "GroupName" = "vm"; "DefaultValue" = "42949672960";
          "Description" = ""},
        @{"Name" = "virtio_iso_path"; "GroupName" = "drivers";
          "Description" = ""},
        @{"Name" = "virtio_base_path"; "GroupName" = "drivers";
          "Description" = ""},
        @{"Name" = "drivers_path"; "GroupName" = "drivers";
          "Description" = ""},
        @{"Name" = "install_updates"; "GroupName" = "updates"; "DefaultValue" = $false; "AsBoolean" = $true;
          "Description" = ""},
        @{"Name" = "purge_updates"; "GroupName" = "updates"; "DefaultValue" = $false; "AsBoolean" = $true;
          "Description" = ""},
        @{"Name" = "run_sysprep"; "GroupName" = "sysprep"; "DefaultValue" = $true; "AsBoolean" = $true;
          "Description" = ""},
        @{"Name" = "unattend_xml_path"; "GroupName" = "sysprep"; "DefaultValue" = "UnattendTemplate.xml";
          "Description" = ""},
        @{"Name" = "disable_swap"; "GroupName" = "sysprep"; "DefaultValue" = $false; "AsBoolean" = $true;
          "Description" = ""},
        @{"Name" = "persist_drivers_install"; "GroupName" = "sysprep"; "DefaultValue" = $true; "AsBoolean" = $true;
          "Description" = ""},
        @{"Name" = "beta_release"; "GroupName" = "cloudbase_init"; "DefaultValue" = $false; "AsBoolean" = $true;
          "Description" = ""}
    )
}

function Get-WindowsImageConfig {
    param([parameter(Mandatory=$true)]
        [string]$ConfigFilePath
    )
    $fullConfigFilePath = Resolve-Path $ConfigFilePath -ErrorAction SilentlyContinue
    if (!$fullConfigFilePath -or (-not (Test-Path $fullConfigFilePath))) {
        Write-Warning ("Config file {0} does not exist." -f $configFilePath)
    }
    $winImageConfig = @{}
    $availableConfigOptionOptions = Get-availableConfigOptionOptions
    foreach($availableConfigOption in $availableConfigOptionOptions) {
        try {
            $groupName = "DEFAULT"
            $asBoolean = $false
            if ($availableConfigOption['GroupName']) {
                $groupName = $availableConfigOption['GroupName']
            }
            if ($availableConfigOption['AsBoolean']) {
                $asBoolean = $availableConfigOption['AsBoolean']
            }
            $value = Get-IniFileValue -Path $fullConfigFilePath -Section $groupName `
                                      -Key $availableConfigOption['Name'] `
                                      -Default $availableConfigOption['DefaultValue'] `
                                      -AsBoolean:$asBoolean
        } catch {
            $value = $availableConfigOption['DefaultValue']
        }
        $winImageConfig += @{$availableConfigOption['Name'] = $value}
    }
    return $winImageConfig
}
function Set-IniComment {
    param
    (
        [parameter(Mandatory=$true, ValueFromPipeline=$true)]
        [string]$Key,
        [parameter()]
        [string]$Section = "DEFAULT",
        [parameter(Mandatory=$false)]
        [string]$Description,
        [parameter(Mandatory=$true)]
        [string]$Path
    )

    $content = Get-Content $Path
    $index = 0
    $descriptionContent = "# $Description"
    foreach ($line in $content) {
        if ($Description -and $line.StartsWith($Key) -and ($content[$index -1] -ne $descriptionContent)) {
            $content = $content[0..($index -1)], $descriptionContent, $content[$index..($content.Length -1)]
            break
        }
        $index += 1
    }
    Set-Content -Value $content -Path $ConfigFilePath -Encoding ASCII
}

function New-WindowsImageConfig {
    param([parameter(Mandatory=$true)]
        [string]$ConfigFilePath
    )
    if (Test-Path $ConfigFilePath) {
        Write-Warning "$ConfigFilePath exists and it will be rewritten."
    } else {
        New-Item -ItemType File -Path $ConfigFilePath
    }

    $fullConfigFilePath = Resolve-Path $ConfigFilePath -ErrorAction SilentlyContinue
    $availableConfigOptionOptions = Get-AvailableConfigOptionOptions
    foreach($availableConfigOption in $availableConfigOptionOptions) {
        try {
            $groupName = "DEFAULT"
            $asBoolean = $false
            if ($availableConfigOption['GroupName']) {
                $groupName = $availableConfigOption['GroupName']
            }
            if ($availableConfigOption['AsBoolean']) {
                $asBoolean = $availableConfigOption['AsBoolean']
            }
            $value = Set-IniFileValue -Path $fullConfigFilePath -Section $groupName `
                                      -Key $availableConfigOption['Name'] `
                                      -Value $availableConfigOption['DefaultValue']
            Set-IniComment -Path $fullConfigFilePath -Key $availableConfigOption['Name'] `
                           -Description $availableConfigOption['Description']
        } catch {
            Write-Warning ("Config option {0} could not be written." -f @($availableConfigOption['Name']))
        }
        $winImageConfig += @{$availableConfigOption['Name'] = $value}
    }
}

Export-ModuleMember Get-WindowsImageConfig, New-WindowsImageConfig
