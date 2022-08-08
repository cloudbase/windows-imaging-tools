Windows Imaging Tools
===============================
[![Master branch](https://ci.appveyor.com/api/projects/status/github/cloudbase/windows-openstack-imaging-tools?branch=master&svg=true)](https://ci.appveyor.com/project/ader1990/windows-openstack-imaging-tools-w885m)

Windows OpenStack Imaging Tools automates the generation of Windows images.<br/>
The tools are a bundle of PowerShell modules and scripts.

The supported target environments for the Windows images are:
* OpenStack with KVM, Hyper-V, VMware and baremetal hypervisor types
* MAAS with KVM, Hyper-V, VMware and baremetal

The generation environment needs to be a Windows one, with Hyper-V virtualization enabled.<br/>
If you plan to run the online Windows setup step on another system / hypervisor, the Hyper-V virtualization is not required.

The following versions of Windows images (both x86 / x64, if existent) to be generated are supported:
* Windows Server 2008 / 2008 R2
* Windows Server 2012 / 2012 R2
* Windows Server 2016 
* Windows Server 2019
* Windows Server 2022
* Windows 7 / 8 / 8.1 / 10 / 11

To generate Windows Nano Server 2016, please use the following repository:

https://github.com/cloudbase/cloudbase-init-offline-install

## Workflow of Windows imaging tools
<img src="https://user-images.githubusercontent.com/1412442/29972658-8fd4d36a-8f35-11e7-80bd-cea90e48e8ba.png" width="750">



## Fast path to create a Windows image

### Requirements:

* A Windows host, with Hyper-V virtualization enabled, PowerShell >=v4 support<br/>
and Windows Assessment and Deployment Kit (ADK)
* A Windows installation ISO or DVD
* Windows compatible drivers, if required by the target environment
* Git environment

### Steps to generate the Windows image
* Clone this repository
* Mount or extract the Windows ISO file
* Download and / or extract the Windows compatible drivers
* If the target environment is MAAS or the image generation is configured to install updates,<br/>
the windows-curtin-hooks and WindowsUpdates git submodules are required.<br/>
Run `git submodule update --init` to retrieve them
* Import the WinImageBuilder.psm1 module
* Use the New-WindowsCloudImage or New-WindowsOnlineCloudImage methods with <br/> the appropriate configuration file

### PowerShell image generation example for OpenStack KVM (host requires Hyper-V enabled)
```powershell
git clone https://github.com/cloudbase/windows-openstack-imaging-tools.git
pushd windows-openstack-imaging-tools
Import-Module .\WinImageBuilder.psm1
Import-Module .\Config.psm1
Import-Module .\UnattendResources\ini.psm1
# Create a config.ini file using the built in function, then set them accordingly to your needs
$ConfigFilePath = ".\config.ini"
New-WindowsImageConfig -ConfigFilePath $ConfigFilePath

# To automate the config options setting:
Set-IniFileValue -Path (Resolve-Path $ConfigFilePath) -Section "DEFAULT" `
                                      -Key "wim_file_path" `
                                      -Value "D:\Sources\install.wim"
# Use the desired command with the config file you just created

New-WindowsOnlineImage -ConfigFilePath $ConfigFilePath

popd

```

## Image generation workflow

### New-WindowsCloudImage

This command does not require Hyper-V to be enabled, but the generated image<br/>
is not ready to be deployed, as it needs to be started manually on another hypervisor.<br/>
The image is ready to be used when it shuts down.

You can find a PowerShell example to generate a raw OpenStack Ironic image that also works on KVM<br/>
in `Examples/create-windows-cloud-image.ps1`

### New-WindowsOnlineImage
This command requires Hyper-V to be enabled, a VMSwitch to be configured for external<br/>
network connectivity if the updates are to be installed, which is highly recommended.

This command uses internally the `New-WindowsCloudImage` to generate the base image and<br/>
start a Hyper-V instance using the base image. After the Hyper-V instance shuts down, <br/>
the resulting VHDX is shrinked to a minimum size and converted to the required format.

You can find a PowerShell example to generate a raw OpenStack Ironic image that also works on KVM<br/>
in `Examples/create-windows-online-cloud-image.ps1`

## Frequently Asked Questions (FAQ)

### The image generation never stops
  * Make sure that the Hyper-V VMSwitch is correctly configured and it allows Internet connectivity<br/>
  if you have configured the image generation to install the Windows updates.
  * Check in the associated Hyper-V VM that the Logon.ps1 script has not failed.<br/>
  If the script failed, there should be a PowerShell window showing the error message.

### I booted an instance with the image and I got a BSOD
  * This is the most common scenario that one can encounter and it is easily fixable.
  * If you boot on KVM hypervisor, make sure that you configure the correct path for the ISO/folder with VirtIO drivers.<br/>
  The configuration options are `virtio_iso_path` and `virtio_base_path`.
  * On the KVM hypervisor side, make sure you start the KVM vm process with the `--enable-kvm` flag.
  * If you boot on a baremetal machine, make sure that either the basic Windows installation has the storage drivers builtin<br/>
  or that you specify the proper path to drivers folder for the `drivers_path` configuration option.

### I booted an instance with the image and I got a forever Windows loading screen
  * This usually happens when the hypervisor does not expose the CPU flags required for that specific Windows version.
  * For example, with Windows 10, you can check https://www.microsoft.com/en-us/windows/windows-10-specifications <br/>
  and make sure that the CPU flags are exposed by your hypervisor of choice.

### Useful links on ask.cloudbase.it
  * https://ask.cloudbase.it/question/2365/windows-server-2016-standard-image-wont-boot-blue-windows-icon-hangs/
  * https://ask.cloudbase.it/question/1227/nano-server-wont-boot/
  * https://ask.cloudbase.it/question/1179/win2012-boot-error-on-openstack-in-vmware-env/

## For developers

### Running unit tests

You will need PowerShell Pester package installed on your system.

It should already be installed on your system if you are running Windows 10.<br/>
If it is not installed you can install it on Windows 10 or greater:

```powershell
Install-Package Pester
```

or you can clone it from: https://github.com/pester/Pester


Running the tests in a closed environment:

```cmd
cmd /c 'powershell.exe -NonInteractive { Invoke-Pester }'
```

This will run all tests without polluting your current shell environment. <br/>
This is not needed if you run it in a Continuous Integration environment.
