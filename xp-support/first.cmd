f:
cd \
start /wait NetFx20SP1_x86.exe /q 
start /wait WindowsXP-KB968930-x86-ENG.exe /passive
PATH=%PATH%;c:\windows\system32\windowspowershell\v1.0
start /wait powershell -ExecutionPolicy ByPass -File SetupSysprep.ps1
start /wait powershell -ExecutionPolicy ByPass -File cloud-init-install.ps1
rem start /wait devmgmt.msc
rem start f:\
start f:\finish.cmd
