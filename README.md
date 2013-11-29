windows-openstack-imaging-tools
===============================

Tools to automate the creation of a Windows image for OpenStack, supporting KVM, Hyper-V, ESXi and more.

Supports any version of Windows starting with Windows 2008 and Windows Vista.

Note: the provided Autounattend.xml targets x64 versions, but it can be easily adapted to x86.



### How to create a Windows template image on KVM


Download the VirtIO tools ISO, e.g. from:
http://alt.fedoraproject.org/pub/alt/virtio-win/latest/images/bin/

You'll need also your Windows installation ISO. In the following example we'll use a Windows Server 2012 R2 
evaluation.

    IMAGE=windows-server-2012-r2.qcow2
    FLOPPY=Autounattend.vfd
    VIRTIO_ISO=virtio-win-0.1-52.iso
    ISO=9600.16384.WINBLUE_RTM.130821-1623_X64FRE_SERVER_EVAL_EN-US-IRM_SSS_X64FREE_EN-US_DV5.ISO

    KVM=/usr/libexec/qemu-kvm
    if [ ! -f "$KVM" ]; then
        KVM=/usr/bin/kvm
    fi

    qemu-img create -f qcow2 -o preallocation=metadata $IMAGE 16G

    $KVM -m 2048 -smp 2 -cdrom $ISO -drive file=$VIRTIO_ISO,index=3,media=cdrom -fda $FLOPPY $IMAGE -boot d -vga std -k en-us -vnc :1

Now you can just wait for the KVM command to exit. You can also connect to the VM via VNC on port 5901 to check 
the status, no user interaction is required.

Note: if you plan to connect remotely via VNC, make sure that the KVM host firewall allows traffic
on this port, e.g.:

    iptables -I INPUT -p tcp --dport 5901 -j ACCEPT


### How to create a Windows template image on Hyper-V

The following Powershell snippet works on both Windows Server and Hyper-V Server 2012 and above:

    $vmname = "OpenStack WS 2012 R2 Standard Evaluation"
    
    # Set the extension to VHD instead of VHDX only if you plan to deploy
    # this image on Grizzly or on Windows / Hyper-V Server 2008 R2
    $vhdpath = "C:\VM\windows-server-2012-r2.vhdx"

    $isoPath = "C:\your\path\9600.16384.WINBLUE_RTM.130821-1623_X64FRE_SERVER_EVAL_EN-US-IRM_SSS_X64FREE_EN-US_DV5.ISO"
    $floppyPath = "C:\your\path\Autounattend.vfd"

    # Set the vswitch accordingly with your configuration
    $vmSwitch = "external"

    New-VHD $vhdpath -Dynamic -SizeBytes (16 * 1024 * 1024 * 1024)
    $vm = New-VM $vmname -MemoryStartupBytes (2048 * 1024 *1024)
    $vm | Set-VM -ProcessorCount 2
    $vm.NetworkAdapters | Connect-VMNetworkAdapter -SwitchName $vmSwitch
    $vm | Add-VMHardDiskDrive -ControllerType IDE -Path $vhdpath
    $vm | Add-VMDvdDrive -Path $isopath
    $vm | Set-VMFloppyDiskDrive -Path $floppyPath

    $vm | Start-Vm

Now you can simply wait for the VM to get installed and configured. It will automatically shutdown once done.
You can check the status with: 

    get-VM $vmname

If you have Cloudbase Hyper-V Nova Compute installed, you can also connect to the VM console with:

    $vm | Get-VMConsole


#### How to set the proper Windows version

The Windows version and edition to be installed can be specified in the Autounattend.xml file contained 
in the Autounattend.flp floppy image. The default is Windows Server 2012 R2 Standard edition. 

This can be easily changed here:

https://github.com/cloudbase/windows-openstack-imaging-tools/blob/05b03fa64dc3d8e5c2c5af97c94aecea61616365/Autounattend.xml#L58

For Windows 8 and above, uncomment the following two options:

    <HideOnlineAccountScreens>true</HideOnlineAccountScreens>
    <HideLocalAccountScreen>true</HideLocalAccountScreen>

On a client OS (Windows 7, 8, etc.) you need also to uncomment the following section:

    <LocalAccounts>
        <LocalAccount wcm:action="add">
        ...
        </LocalAccount>
    </LocalAccounts>

For x86 builds, replace all occurrences of:

    processorArchitecture="amd64"

with:

    processorArchitecture="x86"

Once done, the floppy image can be easily generated on Linux with:

    ./create-autounattend-floppy.sh
