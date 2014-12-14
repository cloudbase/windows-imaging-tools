mkdir c:\sysprep
mkdir c:\sysprep\i386
mkdir c:\sysprep\i386\`$oem`$
mkdir c:\Drivers
mkdir c:\Drivers\virtio
cp e:\wxp\x86\* c:\Drivers\virtio
cp e:\xp\x86\* c:\Drivers\virtio
$Shell = New-Object -ComObject Shell.Application
$CabFiles = $Shell.Namespace("d:\support\tools\deploy.cab").Items()
$DestinationFolder = $Shell.Namespace("C:\sysprep")
$DestinationFolder.CopyHere($CabFiles)
copy sysprep.inf c:\sysprep
copy cmdlines.txt c:\sysprep\i386\`$oem`$
attrib -R c:\sysprep\sysprep.inf
attrib -R c:\sysprep\i386\`$oem`$\cmdlines.txt
