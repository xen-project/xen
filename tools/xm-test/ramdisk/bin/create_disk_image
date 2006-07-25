#!/bin/bash
###############################################################################
##
##  Copyright (C) International Business Machines  Corp., 2005
##  Author(s):  Daniel Stekloff <dsteklof@us.ibm.com>
##
##  This program is free software; you can redistribute it and/or modify
##  it under the terms of the GNU General Public License as published by
##  the Free Software Foundation; under version 2 of the License.
##
##  This program is distributed in the hope that it will be useful,
##  but WITHOUT ANY WARRANTY; without even the implied warranty of
##  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
##  GNU General Public License for more details.
##
##  You should have received a copy of the GNU General Public License
##  along with this program; if not, write to the Free Software
##  Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
##
###############################################################################
function cleanup()
{
	umount "$MNT"
	rm -Rf "$MNT";
	if [ "$LOOPD" ]; then
		losetup -d $LOOPD
	fi
	if [ "$LOOPP" ]; then
		losetup -d $LOOPP
	fi
	if  [ -e "$IMAGE" ]; then
		rm -f "$IMAGE"
	fi
	if  [ -e "$LCONF" ]; then
		rm -f "$LCONF"
	fi
}

function die()
{
	cleanup
	echo "$@"
	exit 1
}

function usage()
{
	cat << EOU
Command creates a hvm guest disk image for xm-test. 

Usage: $0 [OPTIONS]

OPTIONS:
    -d|--dvrdir <name>       Directory where to find network driver 
                             to use for disk image. 
    -i|--image <name>        Image name to create.
    -k|--kernel <name>       Kernel name to use for disk image.
    -n|--netdrv <name>       Network driver name to use for disk image.
    -r|--rootfs <image>      Rootfs image to use for disk image.

This script defaults to using the 8139too.ko driver for network tests. 
If a dvrdir isn't added on the command-line, it will look in 
/lib/modules/ directory relating to the supplied kernel. If the
network driver is built into the kernel, you can specify the key word
"builtin" with the -d option and the script will continue.

Note: Many network drivers rely upon mii.ko. This script will look
for that module in the same location as the network driver, either
for the kernel or the location used with the -d option.

EOU
}

function check_dependencies()
{
	which lilo > /dev/null 2>&1
	if [ $? -ne 0 ]; then
		die "$PROGNAME requires lilo version 22.7+ to be installed."
	fi
	local pass="$( lilo -V | cut -f3 -d " " | awk -F "." '
		{
			if ($1 >= 22 && $2 >= 7)
				print "true"
			else
				print "false"
		}')"
	if [ $pass = "false" ]; then
		die "$PROGNAME requires lilo version 22.7+ to be installed."
	fi
}

function initialize_globals()
{
	PROGNAME="create_disk_image"
	IMAGE="disk.img"
	KERNEL=""
	DRVDIR=""
	NETDRV="8139too.ko"
	LCONF="lilo.conf"
	LOOPD=""    # Loop device for entire disk image
	LOOPP=""    # Loop device for ext partition
	ROOTFS=""
	MNT="/tmp/$PROGNAME-mnt"
	SIZE=8192
	SECTORS=32
	HEADS=8
	CYLINDERS=$(($SIZE/$SECTORS/$HEADS*2))
	BSIZE=$(($SIZE-$SECTORS))
	OFFSET=$(($SECTORS*512))
}

function get_options()
{
	while [ $# -gt 0 ]; do
		case $1 in
			-d|--drvdir)
				shift
				DRVDIR=${1}
				shift
				;;
			-i|--image)
				shift
				IMAGE=${1}
				shift
				;;
			-k|--kernel)
				shift
				KERNEL=${1}
				shift
				;;
			-n|--netdrv)
				shift
				NETDRV=${1}
				shift
				;;
			-r|--rootfs)
				shift
				ROOTFS=${1}
				shift
				;;
			*)
				usage
				exit 1
				;;
		esac
	done
}

function get_loopd()
{
	local loop

	for i in `seq 0 7`; do
		losetup /dev/loop$i > /dev/null 2>&1
		if [ $? -ne 0 ]; then
			# found one
			echo $i
			return 0
		fi
	done
	die "No free loopback devices."
}

function losetup_image()
{
	local loop=$1
	shift

	# If offset, then associate with it
	if [ $# -eq 1 ]; then
		losetup -o $1 $loop $IMAGE
	else
		losetup $loop $IMAGE
	fi

	if [ $? -ne 0 ]; then
		die "Failed to losetup $IMAGE to $loop."
	fi

	echo "Associated $IMAGE with $loop"
}

function create_disk_image()
{
	dd bs=1024 count=$SIZE of=$IMAGE if=/dev/zero

	fdisk -b 512 -C $CYLINDERS -H $HEADS -S $SECTORS "$IMAGE" > /dev/null 2>&1 << EOF
n
p
1
1

a
1
w
EOF
}

function makefs_image()
{
	mke2fs -N 24 -b 1024 $LOOPP $BSIZE

	if [ $? -ne 0 ]; then
		die "mke2fs $LOOPP failed."
	fi
}

function dd_rootfs_to_image()
{
	if [ ! "$ROOTFS" ]; then
		die "Must specify rootfs image to use."
	fi

	dd if="$ROOTFS" of="$LOOPP" > /dev/null 2>&1
	if [ $? -ne 0 ]; then
		die "Failed to dd $ROOTFS to $LOOPP."
	fi

	# Resize fs to use full partition
	e2fsck -f $LOOPP 
	resize2fs $LOOPP
	if [ $? -ne 0 ]; then
		die "Failed to resize rootfs on $LOOPP."
	fi
}

function get_kernel()
{
	# look in /boot for an existing kernel
	local -a kernels=( `ls /boot | grep vmlinuz` )
	local k

	for k in ${kernels[@]}; do
		case "$k" in
			*xen*)
				continue
				;;
			*)
				KERNEL="/boot/$k"
				echo "Using kernel $KERNEL"
				break
				;;
		esac
	done
}

function copy_kernel_to_image()
{
	if [ ! "$KERNEL" ]; then
		get_kernel || die "Couldn't find a kernel to use."
	fi

	mkdir "$MNT/boot"

	cp "$KERNEL" "$MNT/boot"
}

function copy_netdriver_to_image()
{
	local kernel=`basename $KERNEL`
	local kversion=$( echo $kernel | sed 's/^vmlinuz-//' )
	local fdir="/lib/modules/$kversion/kernel/drivers/net"
                                                                                
	mkdir "$MNT/lib/modules"
	if [ -e "$DRVDIR" ]; then
		if [ -e "$DRVDIR/$NETDRV" ]; then
			cp $DRVDIR/mii.ko $MNT/lib/modules
			cp $DRVDIR/$NETDRV $MNT/lib/modules
		else
			die "Failed to find $NETDRV at $DRVDIR."
		fi
	elif [ -e "$fdir/$NETDRV" ]; then
		cp $fdir/mii.ko $MNT/lib/modules
		cp $fdir/$NETDRV $MNT/lib/modules
	else
		die "Xm-test requires at minimum the 8139too.ko driver to run."
	fi

	# Make sure that modules will be installed
	if [ -e "$MNT/etc/init.d/rcS" ]; then
		echo "insmod /lib/modules/mii.ko" >> $MNT/etc/init.d/rcS
		echo "insmod /lib/modules/$NETDRV" >> $MNT/etc/init.d/rcS
	else
		die "Failed to add insmod command to rcS file on image."
	fi
}

function lilo_image()
{
	local kernel=`basename $KERNEL`

	(
	cat <<EOC
boot=$LOOPD
delay=10
geometric
map=$MNT/boot/map
disk=$LOOPD
        bios=0x80
        sectors=$SECTORS
        heads=$HEADS
        cylinders=$CYLINDERS
        partition=$LOOPP
                start=$SECTORS
image=$MNT/boot/$kernel
	append="root=0301 console=tty0 console=ttyS0"
#	append="root=0301"
        label=Linux
        read-only
EOC
	) > "/$MNT/boot/$LCONF"
}

function install_lilo()
{
	lilo -C "$MNT/boot/$LCONF"
	if [ $? -ne 0 ]; then
		die "Failed to install $MNT/boot/$LCONF."
	fi
}

function add_getty_to_inittab()
{
	local itab=$MNT/etc/inittab

	if [ -e "$itab" ]; then
		echo "# Start getty on serial line" >> $itab
		echo "S0:12345:respawn:/sbin/getty ttyS0" >> $itab
	fi
}


# Main starts here
initialize_globals
check_dependencies

get_options "$@"

create_disk_image

# Get the first free loop device
ldev=$(get_loopd)
LOOPD="/dev/loop$ldev"
losetup_image $LOOPD

# Now associate where the partition will go
ldev=$(get_loopd)
LOOPP="/dev/loop$ldev"
losetup_image $LOOPP $OFFSET

makefs_image

dd_rootfs_to_image

if [ -e "$MNT" ]; then
	rm -Rf "$MNT"
fi

mkdir "$MNT";
if [ $? -ne 0 ]; then
	die "Failed to create temporary mount point $MNT."
fi

mount "$LOOPP" "$MNT";
if [ $? -ne 0 ]; then
	die "Failed to mount $LOOPP on $MNT."
fi

copy_kernel_to_image
if [ ! "$DRVDIR" = "builtin" ]; then
	copy_netdriver_to_image
fi
#add_getty_to_inittab

lilo_image
install_lilo

umount "$MNT"
rm -Rf "$MNT";

losetup -d $LOOPD
losetup -d $LOOPP

exit 0
