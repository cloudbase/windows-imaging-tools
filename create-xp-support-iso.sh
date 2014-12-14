#!/bin/bash
pushd xp-support
if [ ! -f NetFx20SP1_x86.exe ]
then
	curl -o NetFx20SP1_x86.exe http://download.microsoft.com/download/0/8/c/08c19fa4-4c4f-4ffb-9d6c-150906578c9e/NetFx20SP1_x86.exe
fi
if [ ! -f WindowsXP-KB968930-x86-ENG.exe ]
then
	curl -o WindowsXP-KB968930-x86-ENG.exe http://download.microsoft.com/download/E/C/E/ECE99583-2003-455D-B681-68DB610B44A4/WindowsXP-KB968930-x86-ENG.exe
fi
popd
mkisofs -o xp-support.iso -J xp-support
