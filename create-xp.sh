#!/bin/bash

ISO="$1"

qemu-img create -f qcow2 -o preallocation=metadata WindowsXP-tmp.qcow2 16G

kvm -name instance-00000220 -M pc -cpu Westmere,+rdtscp,+pdpe1gb,+dca,+pcid,+pdcm,+xtpr,+tm2,+est,+smx,+vmx,+ds_cpl,+monitor,+dtes64,+pclmuldq,+pbe,+tm,+ht,+ss,+acpi,+ds,+vme -enable-kvm -m 4096 -smp 2,sockets=2,cores=1,threads=1 -uuid 1d6ba93c-efeb-468c-b2b9-d6325d5a24ff -smbios type=1,manufacturer="Red Hat Inc.,product=OpenStack Nova,version=2013.1.4-1.el6,serial=44454c4c-4a00-1033-8034-c8c04f595131,uuid=1d6ba93c-efeb-468c-b2b9-d6325d5a24ff" -nodefconfig -nodefaults -chardev socket,id=charmonitor,path=foo.monitor,server,nowait -mon chardev=charmonitor,id=monitor,mode=control -rtc base=utc,driftfix=slew -no-kvm-pit-reinjection -device piix3-usb-uhci,id=usb,bus=pci.0,addr=0x1.0x2 -chardev file,id=charserial0,path=console.log -device isa-serial,chardev=charserial0,id=serial0 -chardev pty,id=charserial1 -device isa-serial,chardev=charserial1,id=serial1 -device usb-tablet,id=input0 -vnc 127.0.0.1:1 -k en-us -vga cirrus -device virtio-balloon-pci,id=balloon0,bus=pci.0,addr=0x5 -netdev user,id=mynet0 -device rtl8139,netdev=mynet0,bus=pci.0,addr=0x3 -drive file="$ISO",index=1,media=cdrom -drive file=virtio-win-latest.iso,index=2,media=cdrom -drive file=xp-support.iso,index=3,media=cdrom WindowsXP-tmp.qcow2 -boot d -fda Autounattend.vfd
qemu-img convert -c -f qcow2 -O qcow2 WindowsXP-tmp.qcow2 WindowsXP.qcow2
rm -f WindowsXP-tmp.qcow2

