#!/bin/bash
BASEURL=http://alt.fedoraproject.org/pub/alt/virtio-win/latest/images/
ISO=`curl "$BASEURL"| grep \.iso | sed 's/.*a href="\(virtio-win-[^"]*\.iso\).*/\1/'`
echo "$ISO" | grep -z '^virtio-win-[^"]*\.iso$' 2>/dev/null
if [ $? -ne 0 ]
then
	echo Failed to find virtio version.
fi
if [ ! -f "$ISO" ]
then
	curl -o "$ISO" "$BASEURL"/"$ISO"
fi
rm -f virtio-win-latest.iso
ln -s "$ISO" virtio-win-latest.iso
