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
