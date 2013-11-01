#!/bin/bash
set -e

if [ $EUID -ne 0 ]; then
    echo "This script must be run as root" 1>&2
    exit 1
fi

BASEDIR=$(dirname $0)

FLOPPY_IMAGE=$BASEDIR/Autounattend.vfd
CONTENT_SRC=$BASEDIR/Autounattend.xml

TMP_FLOPPY_IMAGE=`/bin/mktemp`
TMP_MOUNT_PATH=`/bin/mktemp -d`

rm -rf $TMP_MOUNT_PATH
rm -f $TMP_FLOPPY_IMAGE
dd if=/dev/zero of=$TMP_FLOPPY_IMAGE bs=1k count=1440
mkfs.vfat $TMP_FLOPPY_IMAGE

mkdir $TMP_MOUNT_PATH
mount -t vfat -o loop $TMP_FLOPPY_IMAGE $TMP_MOUNT_PATH
cp $CONTENT_SRC $TMP_MOUNT_PATH

umount $TMP_MOUNT_PATH
rmdir $TMP_MOUNT_PATH

cp $TMP_FLOPPY_IMAGE $FLOPPY_IMAGE
