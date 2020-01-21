Windows Image Builder
=====================
[![Master branch](https://ci.appveyor.com/api/projects/status/github/cloudbase/windows-openstack-imaging-tools?branch=master&svg=true)](https://ci.appveyor.com/project/ader1990/windows-openstack-imaging-tools-w885m)

Windows Image Builder is a PowerShell module for easy Windows image generation.<br/>

The supported target environments for the Windows images are:
* OpenStack with KVM, Hyper-V, VMware and baremetal hypervisor types
* MAAS with KVM, Hyper-V, VMware and baremetal
* All platforms supported by [cloudbase-init](https://github.com/cloudbase/cloudbase-init)

To generate images, a modern Windows environment is required, with Hyper-V virtualization enabled.<br/>
If you plan to run the online Windows setup step on another system / hypervisor, the Hyper-V virtualization is not required.

The following versions of Windows images are supported:
* Windows Server 2016 / 2019
* Windows Server 2012 / 2012 R2
* Windows Server 2008 / 2008 R2
* Windows 7 / 8 / 8.1 / 10

## How Windows Image Builder works
<img src="https://user-images.githubusercontent.com/1412442/29972658-8fd4d36a-8f35-11e7-80bd-cea90e48e8ba.png" width="750">

## Fast path to create a Windows image

### Requirements:

* A Windows host, with Hyper-V virtualization enabled, PowerShell >=v4 support<br/>
and Windows Assessment and Deployment Kit (ADK). Windows Server 2016 or 2019 is recommended.
* A Windows installation ISO or DVD
* Windows compatible drivers, if required by the target environment
* Internet connection for access to Windows Update Servers

### Steps to generate the Windows image
* Install WindowsImageBuilder PS module from [PSGallery](https://www.powershellgallery.com/packages/WindowsImageBuilder)
* Import the WindowsImageBuilder module
* Use the New-WindowsCloudImage or New-WindowsOnlineCloudImage methods with <br/> the appropriate configuration file

### PowerShell image generation example for OpenStack Hyper-V
```powershell
# Install WindowsImageBuilder module from PSGallery
Install-Module WindowsImageBuilder

# Import the module
Import-Module WindowsImageBuilder

# Create a boilerplate Windows image configuration file
$ConfigFilePath = ".\config.ini"
New-WindowsImageConfig -ConfigFilePath $ConfigFilePath

# Customize config.ini with the Windows ISO path
Set-IniFileValue -Path $ConfigFilePath -Section "DEFAULT"
    -Key "wim_file_path" -Value "<windows_iso_path>"

New-WindowsOnlineImage -ConfigFilePath $ConfigFilePath
```

## Image generation workflow

### New-WindowsCloudImage

This command does not require Hyper-V to be enabled, but the generated image<br/>
is not ready to be deployed, as it needs to be started manually on another hypervisor.<br/>
The image is ready to be used when the instance shuts down.

You can find a PowerShell example to generate a raw OpenStack Ironic image that also works on KVM<br/>
in [create-windows-cloud-image.ps1](Examples/create-windows-cloud-image.ps1).

### New-WindowsOnlineImage
This command requires Hyper-V to be enabled, a VMSwitch to be configured for external<br/>
network connectivity if the updates are to be installed, which is highly recommended.

This command uses internally the `New-WindowsCloudImage` to generate the base image and<br/>
start a Hyper-V instance using the base image. After the Hyper-V instance shuts down, <br/>
the resulting VHDX is shrinked to a minimum size and converted to the required format.

You can find a PowerShell example to generate a raw OpenStack Ironic image that also works on KVM<br/>
in [create-windows-online-cloud-image.ps1](Examples/create-windows-online-cloud-image.ps1).

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
