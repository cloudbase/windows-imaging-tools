#!/bin/bash

editions=('vista' '7' '8' '2008' '2012')
client_editions=('vista' '7' '8')
os_list_above_7=('8' '2012')

edition_vista=[]
edition_7=('Windows 7 ENTERPRISE' 'Windows 7 ENTERPRISEN')
edition_8=('Windows 8 ENTERPRISE' 'Windows 8 PROFESSIONAL' 'Windows 8.1 ENTERPRISE' 'Windows 8.1 PROFESSIONAL')
edition_2008=('Windows Server 2008 R2 SERVERHYPERCORE' 'Windows Server 2008 R2 SERVERSTANDARD')
edition_2012=('Hyper-V Server 2012 SERVERHYPERCORE' 'Windows Server 2012 SERVERSTANDARD' 'Hyper-V Server 2012 R2 SERVERHYPERCORE' 'Windows Server 2012 R2 SERVERSTANDARD')

bitness=64
while getopts ":e:f:p:h" opt; do
	case $opt in
		e)
			edition=$OPTARG
      		;;
		f)
			full_edition=$OPTARG
      		;;
		p)
			bitness=$OPTARG
      		;;
		h)
			echo "Usage: customize.sh -e <edition> -f '<full edition>' [-p 64|32]"
			exit 1
      		;;
		\?)
			echo "Invalid option: -$OPTARG" >&2
			exit 1
			;;
		:)
			echo "Option -$OPTARG requires an argument." >&2
			exit 1
			;;
	esac
done

if [ "x$edition" == "x" ]
then
	echo "Please specify an edition with the -e flag. Known editions:"
	for e in "${editions[@]}"
	do
	    echo "    $e"
	done
	exit 1
fi

if [ "x$full_edition" == "x" ]
then
	echo "Please specify a full edition with the -f flag. Known edition strings for the selected OS:"
	eval known_editions=( '"${edition_'${edition}'[@]}"' )
	for e in "${known_editions[@]}"
	do
	    echo "    $e"
	done
	exit 1
fi

client_os=0
for e in "${client_editions[@]}"
do
	if [ $e == $edition ]
	then
		client_os=1
		break
	fi
done

os_above_7=0
for e in "${os_list_above_7[@]}"
do
	if [ $e == $edition ]
	then
		os_above_7=1
		break
	fi
done

f=Autounattend.xml
cp Autounattend-base.xml $f
xmlstarlet ed -L -u "/_:unattend/_:settings[@pass='windowsPE']/_:component/_:ImageInstall/_:OSImage/_:InstallFrom/_:MetaData/_:Value" -v "$full_edition" $f
if [ $client_os -ne 1 ]
then
	#Remove client os flags
	xmlstarlet ed -L -d "/_:unattend/_:settings[@pass='oobeSystem']/_:component/_:UserAccounts/_:LocalAccounts" $f
fi
if [ $os_above_7 -ne 1 ]
then
	#Remove flags that don't work with 7 and below
	xmlstarlet ed -L -d "/_:unattend/_:settings[@pass='oobeSystem']/_:component/_:OOBE/_:HideOnlineAccountScreens" $f
	xmlstarlet ed -L -d "/_:unattend/_:settings[@pass='oobeSystem']/_:component/_:OOBE/_:HideLocalAccountScreen" $f
fi
if [ "x$bitness" == 'x32' ]
then
	sed -i 's/processorArchitecture="amd64"/processorArchitecture="x86"/g' $f
fi
