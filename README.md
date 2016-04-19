windows-openstack-imaging-tools
===============================

Tools to automate the creation of a Windows image for OpenStack, supporting KVM, Hyper-V, ESXi, baremetal and more.

Supports any version of Windows starting with Windows 2008 R2 and Windows 7, including:

* Windows Server 2008 R2
* Hyper-V Server 2008 R2
* Windows 7
* Windows Server 2012
* Hyper-V Server 2012
* Windows 8
* Windows Server 2012 R2
* Hyper-V Server 2012 R2
* Windows 8.1

Supports both x64 and x86 images.

### How to create a Windows template image

Requirements:

* A host or VM running Windows 
* Clone this repository
* A Windows installation ISO or DVD, that needs to be either mounted or extracted (e.g. with 7-zip)
* For KVM, download the VirtIO tools ISO, e.g. from: http://alt.fedoraproject.org/pub/alt/virtio-win/stable/

Example PowerShell script:

    Import-Module .\WinImageBuilder.psm1

    # The disk format can be: VHD, VHDX, QCow2, VMDK or RAW
    $virtualDiskPath = "c:\Images\mywindowsimage.qcow2"
    # This is the content of your Windows ISO
    $wimFilePath = "D:\sources\install.wim"
    # Optionally, if you target KVM
    $virtIOISOPath = "C:\ISO\virtio-win-0.1-81.iso"

    # Check what images are supported in this Windows ISO
    $images = Get-WimFileImagesInfo -WimFilePath $wimFilePath
    # Select the first one
    $image = $images[0]
    $image

    # The product key is optional
    #$productKey = “xxxxx-xxxxx…"

    # Add -InstallUpdates for the Windows updates (it takes longer and requires
    # more space but it's highly recommended)
    New-WindowsCloudImage -WimFilePath $wimFilePath -ImageName $image.ImageName `
    -VirtualDiskFormat QCow2 -VirtualDiskPath $virtualDiskPath `
    -SizeBytes 16GB -ProductKey $productKey -VirtIOISOPath $virtIOISOPath

No extra configurations are needed for specific Windows versions, the New-WindowsCloudImage cmdlet takes care of everything.

### How to upload the image in OpenStack

We're not yet done, the next steps consist in:

* uploading the image to Glance
* booting an instance on your target hypervisor compute node
* waiting for the setup to complete (the instance will shutdown once the setup is done) 
* take a snapshot of the instance which will contain the final sysprepped image ready for your deployments

TODO: Add OpenStack scripts

### Notes

The Windows host where you plan to create the instance needs either:

* A version greater or equal to the version of the Windows image that you want to generate
* A recent Windows ADK installed

E.g. to generate a Windows Server 2012 R2 image, you need a host running either Windows Server 2012 R2 / Hyper-V Server 2012 R2 or Windows 8.1.


Generate MaaS compatible image
==============================

Generating an image for MaaS follows the same rules outlined above for OpenStack images. For this purpose there is a separate commandlet:


Example:

    Import-Module .\WinImageBuilder.psm1
    # This is the content of your Windows ISO
    $wimFilePath = "D:\sources\install.wim"

    # Check what images are supported in this Windows ISO
    $images = Get-WimFileImagesInfo -WimFilePath $wimFilePath

    # Select the first one. Note, the first image in the index is usually a Server Core
    # image. If you would like to select something else, print the $images variable to see
    # alternatives
    $image = $images[0]

    # If you select to sysprep the image, the Hyper-V role needs to be enabled.
    # You will also need a VMSwitch on your system that allows internet access
    # If the -SwitchName parameter is not used, the commandlet will automatically
    # create an external vmswitch using a net adapter with a default route set
    # Also, if you are targeting an UEFI enabled system, you can use the -DiskLayout UEFI
    # option to create the proper partition layout.

    New-MaaSImage -WimFilePath $wimFilePath -ImageName $image.ImageName`
    -MaaSImagePath C:\images\win2012hvr2-dd -SizeBytes 16GB -Memory 4GB `
    -CpuCores 2 -DiskLayout BIOS -RunSysprep

This commandlet adds the ability to sysprep the image. Please take note that this will require the installation of the Hyper-V role on the local machine. The Memory and CpuCores options allow you to specify the resources that should be allocated to the sysprep VM.

Please make sure that when cloning this repository on Windows, you preserve original line endings. The curtin finalize script will fail otherwise.

The resulting image can be copied to your MaaS install and uploaded as follows:

    maas root boot-resources create name=windows/win2012hvr2 architecture=amd64/generic filetype=ddtgz content@=$HOME/win2012hvr2-dd

### Notes:
    
In order to generate MAAS compatible images, you need to ` git submodule update --init ` in order to get the latest files of windows-curtin-hooks

## How to run tests

You will need pester on your system. It should already be installed on your system if you are running Windows 10. If it is not:

```powershell
Install-Package Pester
```

Running the actual tests:

```powershell
powershell.exe -NonInteractive {Invoke-Pester}
```

This will run all tests without polluting your current shell environment. The -NonInteractive flag will make sure that any test that checks for mandatory parameters will not block the tests if run in an interactive session. This is not needed if you run this in a CI.