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
          "Description" = "This parameter allows to choose between MAAS, KVM, VMware and Hyper-V specific images.
                           For HYPER-V, cloudbase-init will be installed and the generated image should be in vhd or vhdx format.
                           For MAAS, in addition to cloudbase-init, the curtin tools are installed
                           and the generated image should be in raw.tgz format.
                           For KVM, in addition to cloudbase-init, the VirtIO drivers are installed
                           and the generated image should be in qcow2 format."},
        @{"Name" = "disk_layout"; "DefaultValue" = "BIOS";
          "Description" = "This parameter can be set to either BIOS or UEFI."},
        @{"Name" = "product_key";
          "Description" = "The product key for the selected OS. If the value is default_kms_key and the Windows image is
                           ServerStandard or ServerDatacenter (Core), the appropiate KMS key will be used."},
        @{"Name" = "extra_features";
          "Description" = "A comma separated array of extra features that will be enabled on the resulting image.
                           These features need to be present in the ISO file."},
        @{"Name" = "extra_capabilities";
          "Description" = "A comma separated array of extra capabilities that will be enabled on the resulting image.
                           These capabilities need to be present in the ISO file."},
        @{"Name" = "force"; "DefaultValue" = $false; "AsBoolean" = $true;
          "Description" = "It will force the image generation when RunSysprep is False or the selected SwitchName
                           is not an external one. Use this parameter with caution because it can easily generate
                           unstable images."},
        @{"Name" = "install_maas_hooks"; "DefaultValue" = $false; "AsBoolean" = $true;
          "Description" = "If set to true, MAAS Windows curtin hooks will be copied to the image root directory."},
         @{"Name" = "compression_format";
          "Description" = "Select between tar, gz, zip formats or any combination between these."},
        @{"Name" = "zip_password";
          "Description" = "If this parameter is set, after the image is generated,
                           a password protected zip archive with the image will be created. 
                           compression_format must contain zip in order for this parameter to be used"},
        @{"Name" = "gold_image"; "DefaultValue" = $false; "AsBoolean" = $true;
          "Description" = "It will stop the image generation after the updates are installed and cleaned."},
        @{"Name" = "gold_image_path";
          "Description" = "This is the full path of the already generated golden image.
                           It should be a valid VHDX path."},
        @{"Name" = "vmware_tools_path";
          "Description" = "This is a full path to the VMware-tools.exe version that you want to install."},
        @{"Name" = "custom_resources_path";
          "Description" = "This is the full path of a folder with custom resources which will be used by
                           the custom scripts.
                           The resources found at this path will be copied recursively to the image
                           UnattendResources\CustomResources folder."},
        @{"Name" = "custom_scripts_path";
          "Description" = "This is the full path of the folder which can contain a set of PS scripts,
                           that will be copied and executed during the online generation part on the VM.
                           The PowerShell scripts, if existent, will be started by Logon.ps1 script,
                           at different moments during image generation.
                           The purpose of these scripts is to offer to the user a fully
                           customizable way of defining additional logic for tweaking the final image.
                           The scripts files can have the following names: RunBeforeWindowsUpdates.ps1,
                           RunAfterWindowsUpdates.ps1, RunBeforeCloudbaseInitInstall.ps1, RunAfterCloudbaseInitInstall.ps1,
                           RunBeforeSysprep.ps1, RunAfterSysprep.ps1.
                           The script names contain the information on when the script will be executed.
                           One can define only some of the hook scripts and it is not mandatory to define all of them.
                           If a script does not exist, it will not be executed."},
        @{"Name" = "enable_administrator_account"; "DefaultValue" = $false; "AsBoolean" = $true
          "Description" = "If set to true the Administrator account will be enabled on the client
                           versions of Windows, which have the Administrator account disabled by default"},
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
          "Description" = "Disk space (in bytes) assigned to the boot disk for the VM used to generate the image."},
        @{"Name" = "shrink_image_to_minimum_size"; "DefaultValue" = $true; "AsBoolean" = $true
          "Description" = "Whether to shrink the image partition and disk after the image generation is complete."},
        @{"Name" = "virtio_iso_path"; "GroupName" = "drivers";
          "Description" = "The path to the ISO file containing the VirtIO drivers."},
        @{"Name" = "virtio_base_path"; "GroupName" = "drivers";
          "Description" = "The location where the VirtIO drivers are found.
                           For example, the location of a mounted VirtIO ISO. VirtIO versions supported >=0.1.6.x"},
        @{"Name" = "install_qemu_ga"; "GroupName" = "custom";"DefaultValue" = "False";
          "Description" = "Installs QEMU guest agent services from the Fedora VirtIO website.
                           Defaults to 'False' (no installation will be performed).
                           If set to 'True', the following MSI installer will be downloaded and installed:
                             * for x86: https://fedorapeople.org/groups/virt/virtio-win/direct-downloads/archive-qemu-ga/qemu-ga-win-100.0.0.0-3.el7ev/qemu-ga-x86.msi
                             * for x64: https://fedorapeople.org/groups/virt/virtio-win/direct-downloads/archive-qemu-ga/qemu-ga-win-100.0.0.0-3.el7ev/qemu-ga-x64.msi
                           The value can be changed to a custom URL, to allow other QEMU guest agent versions to be installed.
                           Note: QEMU guest agent requires VirtIO drivers to be present on the image.
                          "},
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
        @{"Name" = "msi_path"; "GroupName" = "cloudbase_init";
          "Description" = "If set, the Cloudbase-Init msi at this path will be used.
                          The path needs to be a locally accessible file path."},
        @{"Name" = "cloudbase_init_config_path"; "GroupName" = "cloudbase_init";
          "Description" = "If set, the cloudbase-init.conf is replaced with the file at the path."},
        @{"Name" = "cloudbase_init_unattended_config_path"; "GroupName" = "cloudbase_init";
          "Description" = "If set, the cloudbase-init-unattend.conf is replaced with the file at the path."},
        @{"Name" = "cloudbase_init_use_local_system"; "GroupName" = "cloudbase_init"; "AsBoolean" = $true; "DefaultValue" = $false;
          "Description" = "If set, the Cloudbase-Init service will be run under Local System account.
                           By default, a user named cloudbase-init with admin rights is created and used."},
        @{"Name" = "enable_custom_wallpaper"; "DefaultValue" = $true; "AsBoolean" = $true;
          "Description" = "If set to true, a custom wallpaper will be set according to the values of configuration options
                           wallpaper_path and wallpaper_solid_color"},
        @{"Name" = "wallpaper_path";
          "Description" = "If set, it will replace the Cloudbase Solutions wallpaper to the one specified.
                           The wallpaper needs to be a valid .jpg/.jpeg image."},
        @{"Name" = "wallpaper_solid_color";
          "Description" = "If set, it will replace the Cloudbase Solutions wallpaper to a solid color.
                           Currently, the only allowed solid color is '0 0 0' (black).
                           If both wallpaper_path and wallpaper_solid_color are set,
                           the script will throw an error."},
        @{"Name" = "disable_first_logon_animation"; "DefaultValue" = $false; "AsBoolean" = $true;
          "Description" = "If set, the animation displayed during the first login on Windows Client versions will be disabled."},
        @{"Name" = "compress_qcow2"; "DefaultValue" = $false; "AsBoolean" = $true;
          "Description" = "If set to true and the target image format is QCOW2, the image conversion will
                           use qemu-img built-in compression. The compressed qcow2 image will be smaller, but the conversion
                           will take longer time."},
        @{"Name" = "zero_unused_volume_sectors"; "DefaultValue" = $false; "AsBoolean" = $true;
          "Description" = "If set to true, during final cleanup, https://github.com/felfert/ntfszapfree will be used to zero unused space.
                           This helps qemu-img to minimize image size. In order to benefit from this, an additional invocation
                           of qemu-img convert must be performed after the initial run of the image has shutdown."},
        @{"Name" = "extra_packages";
          "Description" = "A comma separated list of extra packages (referenced by filepath)
                           to slipstream into the underlying image.
                           This allows additional local packages, like security updates, to be added to the image."},
        @{"Name" = "extra_packages_ignore_errors"; "DefaultValue" = $false; "AsBoolean" = $true;
          "Description" = "Ignore failures from DISM when installing extra_packages, such as when
                           updates are skipped which are not applicable to the image."},
        @{"Name" = "enable_shutdown_without_logon"; "DefaultValue" = $false; "AsBoolean" = $true;
          "Description" = "Enables shutdown of the Windows instance from the logon console."},
        @{"Name" = "enable_ping_requests"; "DefaultValue" = $false; "AsBoolean" = $true;
          "Description" = "If set to true, firewall rules will be added to enable ping requests (ipv4 and ipv6)."},
        @{"Name" = "enable_ipv6_eui64"; "DefaultValue" = $false; "AsBoolean" = $true;
          "Description" = "If set to true, use EUI-64 derived IDs and disable privacy extensions for IPv6.
                           If set to false, the IPv6 protocol might not work on OpenStack or CloudStack.
                           See https://github.com/cloudbase/windows-openstack-imaging-tools/issues/192"},
        @{"Name" = "enable_active_mode"; "DefaultValue" = $false; "AsBoolean" = $true;
          "Description" = "If set to true, it will set the High Performance mode and some power mode
                           and registry tweaks to prevent the machine from sleeping / hibernating."},
        @{"Name" = "disable_secure_boot"; "GroupName" = "vm"; "DefaultValue" = $false; "AsBoolean" = $true;
          "Description" = "If set to true and the disk layout is UEFI, the secure boot firmware option will be disabled."},
        @{"Name" = "clean_updates_offline"; "GroupName" = "updates"; "DefaultValue" = $false; "AsBoolean" = $true;
          "Description" = "Clean up the updates / components by running a DISM Cleanup-Image command.
                           This is useful when updates or capabilities are installed offline."},
        @{"Name" = "clean_updates_online"; "GroupName" = "updates"; "DefaultValue" = $true; "AsBoolean" = $true;
          "Description" = "Clean up the updates / components by running a DISM Cleanup-Image command.
                           This is useful when updates or other packages are installed when the instance is running."},
        @{"Name" = "time_zone"; "GroupName" = "custom";
          "Description" = "Set a custom timezone for the Windows image."},
        @{"Name" = "ntp_servers"; "GroupName" = "custom";
          "Description" = "Set custom ntp servers(space separated) for the Windows image"}
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
        Remove-Item -Force $ConfigFilePath
    }
    New-Item -ItemType File -Path $ConfigFilePath | Out-Null

    $fullConfigFilePath = Resolve-Path $ConfigFilePath -ErrorAction SilentlyContinue
    $availableConfigOptions = Get-AvailableConfigOptions
    foreach($availableConfigOption in $availableConfigOptions) {
        try {
            $groupName = "DEFAULT"
            $value = $availableConfigOption['DefaultValue']
            if ($availableConfigOption['GroupName']) {
                $groupName = $availableConfigOption['GroupName']
            }
            if (!$availableConfigOption['AsBoolean'] -and !$value) {
                $value = '""'
            }
            Set-IniFileValue -Path $fullConfigFilePath -Section $groupName `
                             -Key $availableConfigOption['Name'] `
                             -Value $value | Out-Null
            Set-IniComment -Path $fullConfigFilePath -Key $availableConfigOption['Name'] `
                           -Description $availableConfigOption['Description']
        } catch {
            Write-Warning ("Config option {0} could not be written." -f @($availableConfigOption['Name']))
        }
    }
}

Export-ModuleMember Get-WindowsImageConfig, New-WindowsImageConfig
