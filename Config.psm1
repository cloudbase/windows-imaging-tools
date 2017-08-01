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

function Get-AvailableConfigOptions {
    return @(
        @{"Name" = "wim_file_path"; "DefaultValue" = "D:\Sources\install.wim";
          "Description" = "The location of the WIM file from the mounted Windows ISO."},
        @{"Name" = "image_name"; "DefaultValue" = "Windows Server 2012 R2 SERVERSTANDARD";
          "Description" = "This is the complete name of the Windows version that will be generated.
                           In order to find the possible options, use the Get-WimFileImagesInfo command
                           and look for the Name property."},
        @{"Name" = "image_path"; "DefaultValue" = "${ENV:TEMP}\win-image.vhdx";
          "Description" = "The destination of the generated image."},
        @{"Name" = "virtual_disk_format"; "DefaultValue" = "VHDX";
          "Description" = "Select between VHD, VHDX, QCOW2, VMDK or RAW formats."},
        @{"Name" = "image_type"; "DefaultValue" = "HYPER-V";
          "Description" = "This parameter allows to choose between MAAS, KVM and Hyper-V specific images.
                           For HYPER-V, cloudbase-init will be installed and the generated image should be in vhd or vhdx format.
                           For MAAS, in addition to cloudbase-init, the curtin tools are installed
                           and the generated image should be in raw.tgz format.
                           For KVM, in addition to cloudbase-init, the VirtIO drivers are installed
                           and the generated image should be in qcow2 format."},
        @{"Name" = "disk_layout"; "DefaultValue" = "BIOS";
          "Description" = "This parameter can be set to either BIOS or UEFI."},
        @{"Name" = "product_key";
          "Description" = "The product key for the selected OS."},
        @{"Name" = "extra_features";
          "Description" = "A comma separated array of extra features that will be enabled on the resulting image.
                           These features need to be present in the ISO file."},
        @{"Name" = "force"; "DefaultValue" = $false; "AsBoolean" = $true;
          "Description" = "It will force the image generation when RunSysprep is False or the selected SwitchName
                           is not an external one. Use this parameter with caution because it can easily generate
                           unstable images."},
        @{"Name" = "install_maas_hooks"; "DefaultValue" = $false; "AsBoolean" = $true;
          "Description" = "If set to true, MAAS Windows curtin hooks will be copied to the image root directory."},
        @{"Name" = "zip_password";
          "Description" = "If this parameter is set, after the image is generated,
                           a password protected zip archive with the image will be created."},
        @{"Name" = "gold_image"; "DefaultValue" = $false; "AsBoolean" = $true;
          "Description" = "It will stop the image generation after the updates are installed and cleaned."},
        @{"Name" = "gold_image_path";
          "Description" = "This is the full path of the already generated golden image.
                           It should be a valid VHDX path."},
        @{"Name" = "administrator_password"; "GroupName" = "vm"; "DefaultValue" = "Pa`$`$w0rd";
          "Description" = "This will be the Administrator user's, so that AutoLogin can be performed on the instance,
                           in order to install the required products,
                           updates and perform the generation tasks like sysprep."},
        @{"Name" = "external_switch"; "GroupName" = "vm"; "DefaultValue" = "external";
          "Description" = "Used to specify the virtual switch the VM will be using.
                           If it is specified but it is not external or if the switch does not exist,
                           you will get an error message."},
        @{"Name" = "cpu_count"; "GroupName" = "vm"; "DefaultValue" = "1";
          "Description" = "The number of CPU cores assigned to the VM used to generate the image."},
        @{"Name" = "ram_size"; "GroupName" = "vm"; "DefaultValue" = "2147483648";
          "Description" = "RAM (in bytes) assigned to the VM used to generate the image."},
        @{"Name" = "disk_size"; "GroupName" = "vm"; "DefaultValue" = "42949672960";
          "Description" = "Disk space (in bytes) assigned to the VM used to generate the image."},
        @{"Name" = "virtio_iso_path"; "GroupName" = "drivers";
          "Description" = "The path to the ISO file containing the VirtIO drivers."},
        @{"Name" = "virtio_base_path"; "GroupName" = "drivers";
          "Description" = "The location where the VirtIO drivers are found.
                           For example, the location of a mounted VirtIO ISO. VirtIO versions supported >=0.1.6.x"},
        @{"Name" = "drivers_path"; "GroupName" = "drivers";
          "Description" = "The location where additional drivers that are needed for the image are located."},
        @{"Name" = "install_updates"; "GroupName" = "updates"; "DefaultValue" = $false; "AsBoolean" = $true;
          "Description" = "If set to true, the latest updates will be downloaded and installed."},
        @{"Name" = "purge_updates"; "GroupName" = "updates"; "DefaultValue" = $false; "AsBoolean" = $true;
          "Description" = "If set to true, will run DISM with /resetbase option. This will reduce the size of
                           WinSXS folder, but after that Windows updates cannot be uninstalled."},
        @{"Name" = "run_sysprep"; "GroupName" = "sysprep"; "DefaultValue" = $true; "AsBoolean" = $true;
          "Description" = "Used to clean the OS on the VM, and to prepare it for a first-time use."},
        @{"Name" = "unattend_xml_path"; "GroupName" = "sysprep"; "DefaultValue" = "UnattendTemplate.xml";
          "Description" = "The path to the Unattend XML template file used for sysprep."},
        @{"Name" = "disable_swap"; "GroupName" = "sysprep"; "DefaultValue" = $false; "AsBoolean" = $true;
          "Description" = "DisableSwap option will disable the swap when the image is generated and will add a setting
                           in the Unattend.xml file which will enable swap at boot time during specialize step.
                           This is required, as by default, the amount of swap space on Windows machine is directly
                           proportional to the RAM size and if the image has in the initial stage low disk space,
                           the first boot will fail due to not enough disk space. The swap is set to the default
                           automatic setting right after the resize of the partitions is performed by cloudbase-init."},
        @{"Name" = "persist_drivers_install"; "GroupName" = "sysprep"; "DefaultValue" = $true; "AsBoolean" = $true;
          "Description" = "In case the hardware on which the image is generated will also be the hardware on
                           which the image will be deployed this can be set to true, otherwise the spawned
                           instance is prone to BSOD."},
        @{"Name" = "beta_release"; "GroupName" = "cloudbase_init"; "DefaultValue" = $false; "AsBoolean" = $true;
          "Description" = "This is a switch that allows the selection of Cloudbase-Init branches. If set to true, the
                           beta branch will be used:
                           https://cloudbase.it/downloads/CloudbaseInitSetup_<arch>.msi, where arch can be x86 or x64
                           otherwise the stable branch will be used:
                           https://cloudbase.it/downloads/CloudbaseInitSetup_Stable_<arch>.msi, where arch can be x86 or x64"},
        @{"Name" = "serial_logging_port"; "GroupName" = "cloudbase_init"; "DefaultValue" = "COM1";
          "Description" = "Serial log port for Cloudbase-Init.
	                   If set to null, the first serial port (if any) from the generation VM will be used"},
        @{"Name" = "wallpaper_path";
          "Description" = "If set, it will replace the Cloudbase Solutions wallpaper to the one specified.
	                   The wallpaper needs to be a valid .jpg/.jpeg image."}
        @{"Name" = "compress_qcow2"; "DefaultValue" = $false; "AsBoolean" = $true;
          "Description" = "If set to true and the target image format is QCOW2, the image conversion will
                           use qemu-img built-in compression. The compressed qcow2 image will be smaller, but the conversion
                           will take longer time."}
    )
}

function Get-WindowsImageConfig {
     <#
    .SYNOPSIS
     This function reads the ini file given as a parameter and returns a dictionary of config options for the Windows
     image to be generated. If there are no values for a set of keys defined in Get-AvailableConfigOptions, the
     default values will be used instead.
     #>
    param([parameter(Mandatory=$true)]
        [string]$ConfigFilePath
    )
    $fullConfigFilePath = Resolve-Path $ConfigFilePath -ErrorAction SilentlyContinue
    if (!$fullConfigFilePath -or (-not (Test-Path $fullConfigFilePath))) {
        Write-Warning ("Config file {0} does not exist." -f $configFilePath)
    }
    $winImageConfig = @{}
    $availableConfigOptions = Get-AvailableConfigOptions
    foreach($availableConfigOption in $availableConfigOptions) {
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
    $lines = @()
    $descriptionSplited = $Description -split '["\n\r"|"\r\n"|\n|\r]'
    foreach ($line in $descriptionSplited) {
        if ($line.trim()) {
            $lines += "# " + $line.trim()
        }
    }
    foreach ($line in $content) {
        if ($Description -and $line.StartsWith($Key) -and ($content[$index -1] -ne $lines)) {
            $content = $content[0..($index -1)], $lines, $content[$index..($content.Length -1)]
            break
        }
        $index += 1
    }
    Set-Content -Value $content -Path $ConfigFilePath -Encoding ASCII
}

function New-WindowsImageConfig {
    <#
    .SYNOPSIS
     This function creates a ini type config file with the options taken from the Get-WindowsImageConfig function.
     #>
    param([parameter(Mandatory=$true)]
        [string]$ConfigFilePath
    )
    if (Test-Path $ConfigFilePath) {
        Write-Warning "$ConfigFilePath exists and it will be rewritten."
    } else {
        New-Item -ItemType File -Path $ConfigFilePath
    }

    $fullConfigFilePath = Resolve-Path $ConfigFilePath -ErrorAction SilentlyContinue
    $availableConfigOptions = Get-AvailableConfigOptions
    foreach($availableConfigOption in $availableConfigOptions) {
        try {
            $groupName = "DEFAULT"
            $value = $availableConfigOption['DefaultValue']
            $asBoolean = $false
            if ($availableConfigOption['GroupName']) {
                $groupName = $availableConfigOption['GroupName']
            }
            if ($availableConfigOption['AsBoolean']) {
                $asBoolean = $availableConfigOption['AsBoolean']
            } else {
                if (!$value) {
                    $value = '""'
                }
            }
            $value = Set-IniFileValue -Path $fullConfigFilePath -Section $groupName `
                                      -Key $availableConfigOption['Name'] `
                                      -Value $value
            Set-IniComment -Path $fullConfigFilePath -Key $availableConfigOption['Name'] `
                           -Description $availableConfigOption['Description']
        } catch {
            Write-Warning ("Config option {0} could not be written." -f @($availableConfigOption['Name']))
        }
        $winImageConfig += @{$availableConfigOption['Name'] = $value}
    }
}

Export-ModuleMember Get-WindowsImageConfig, New-WindowsImageConfig
