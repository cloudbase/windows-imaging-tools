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
* Windows Server 2025
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

## QEMU Guest Agent Configuration

### Overview

The QEMU Guest Agent installation supports multiple configuration modes:

- **Source selection**: Install from VirtIO ISO, web download, or automatic fallback
- **Checksum verification**: Optional SHA256 verification for enhanced security
- **Full backward compatibility**: All existing configurations continue to work

### Installation Source Options

The `source` parameter in the `[virtio_qemu_guest_agent]` section controls where the QEMU Guest Agent is obtained from:

| Value | Description | Requires VirtIO ISO | Behavior |
|-------|-------------|---------------------|----------|
| `web` | Download from internet (default) | No | Downloads from fedorapeople.org |
| `iso` | Extract from VirtIO ISO only | **Yes** | Fails if ISO not available or MSI not found |
| `auto` | Try ISO first, fallback to web | No | Intelligent: uses ISO if available, otherwise downloads |

### Configuration Examples

#### 1. Default Installation (Simple)

```ini
[custom]
install_qemu_ga=True
```

Uses the default version from the VirtIO archive (web download).

#### 2. Extract from VirtIO ISO (Offline Mode)

```ini
[drivers]
virtio_iso_path=/path/to/virtio-win.iso

[custom]
install_qemu_ga=True

[virtio_qemu_guest_agent]
source=iso
```

Extracts the QEMU Guest Agent from the VirtIO ISO. Useful for offline environments.

#### 3. Automatic Mode (Recommended)

```ini
[drivers]
virtio_iso_path=/path/to/virtio-win.iso

[custom]
install_qemu_ga=True

[virtio_qemu_guest_agent]
source=auto
```

Tries ISO extraction first, automatically falls back to web download if needed.

#### 4. Secure Installation with Checksum

```ini
[custom]
install_qemu_ga=True

[virtio_qemu_guest_agent]
source=web
url=https://fedorapeople.org/groups/virt/virtio-win/direct-downloads/archive-qemu-ga/qemu-ga-win-VERSION/qemu-ga-x64.msi
checksum=<SHA256_CHECKSUM>
```

Downloads from a custom URL with SHA256 checksum verification. Both `url` and `checksum` must be specified together.

#### 5. Legacy Custom URL

```ini
[custom]
install_qemu_ga=https://example.com/custom-qemu-ga.msi
```

Downloads from a custom URL without checksum verification (backward compatibility).

### Priority Order

The system follows this priority order:

1. **Custom URL + Checksum** (if both provided) → Always used, `source` is ignored
2. **Source-based installation**:
   - `source=iso` → Extract from ISO only (error if fails)
   - `source=auto` → Try ISO, fallback to web
   - `source=web` → Download from internet
3. **Legacy behavior** (backward compatibility):
   - `install_qemu_ga=True` → Default URL
   - `install_qemu_ga=<URL>` → Custom URL without checksum

### VirtIO ISO Structure

The system searches for the QEMU Guest Agent MSI in the following locations within the VirtIO ISO:

- `guest-agent/qemu-ga-x86_64.msi` (for 64-bit) ✓ **Most common**
- `guest-agent/qemu-ga-i386.msi` (for 32-bit) ✓ **Most common**
- `guest-agent/qemu-ga-x64.msi` (alternative naming)
- `guest-agent/qemu-ga-x86.msi` (alternative naming)
- Additional fallback paths and recursive search

The system will automatically detect and use the correct MSI file based on the image architecture.

### Error Handling

#### Source = iso

If the ISO is not found or doesn't contain the guest agent:

```
ERROR: Source is set to 'iso' but VirtIO ISO path is not provided or does not exist: C:\path\to\virtio-win.iso
```

or

```
ERROR: QEMU Guest Agent MSI not found in VirtIO ISO for architecture: x64. 
Searched paths: E:\guest-agent\qemu-ga-x86_64.msi, ...
Please check the ISO structure and update the search paths if needed.
```

#### Source = auto

If extraction from ISO fails, the system automatically falls back to web download:

```
Failed to extract QEMU Guest Agent from VirtIO ISO: <error details>
Falling back to web download...
Using web download for QEMU Guest Agent
Downloading QEMU guest agent installer from https://fedorapeople.org/...
```

### Backward Compatibility

All existing configurations continue to work without modification:

- Configurations without the `[virtio_qemu_guest_agent]` section use the default `source=web`
- The `install_qemu_ga=True` behavior is unchanged (downloads from default URL)
- Custom URLs specified in `install_qemu_ga=<URL>` still work

### Getting the SHA256 Checksum

**Windows (PowerShell)**:
```powershell
Get-FileHash -Path "qemu-ga-x64.msi" -Algorithm SHA256
```

**Linux/macOS**:
```bash
sha256sum qemu-ga-x64.msi
```

### Benefits

- **Offline environments**: Use `source=iso` for air-gapped systems
- **Faster builds**: Avoid network downloads with local ISO
- **Version consistency**: Match guest agent with VirtIO drivers version
- **Security**: SHA256 checksum verification prevents tampering
- **Flexibility**: `source=auto` works both online and offline
- **Bandwidth savings**: Reuse ISO for multiple image builds

### Best Practices

1. **Use `source=auto` for flexibility**: Works both online and offline
2. **Use `source=iso` for strict offline environments**: Ensures no internet access is attempted
3. **Use `source=web` with checksum**: For maximum security when downloading
4. **Match versions**: Keep guest agent version consistent with VirtIO drivers

### Technical Details

#### ISO Mounting

The system:
1. Creates a temporary backup copy of the ISO
2. Mounts the ISO using Windows VirtualDisk API
3. Searches for the QEMU Guest Agent MSI
4. Copies the MSI to the resources directory
5. Safely dismounts and cleans up the temporary ISO

#### Architecture Mapping

| Windows Architecture | ISO Filename |
|---------------------|--------------|
| AMD64 (64-bit) | `qemu-ga-x86_64.msi` |
| x86 (32-bit) | `qemu-ga-i386.msi` |

### Troubleshooting

**Q: The build fails with "QEMU Guest Agent MSI not found in VirtIO ISO"**

A: Your VirtIO ISO might have a different structure. Use `source=auto` to fall back to web download, or `source=web` to skip ISO extraction entirely.

**Q: I want to force internet download even though I have an ISO**

A: Set `source=web` in the configuration.

**Q: How do I ensure version consistency between VirtIO drivers and guest agent?**

A: Use `source=iso` to extract the guest agent from the same VirtIO ISO used for drivers.

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
