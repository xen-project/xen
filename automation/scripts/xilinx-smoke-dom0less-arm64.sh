#!/bin/bash

set -ex

test_variant=$1

if [ -z "${test_variant}" ]; then
    passed="ping test passed"
    dom0_check="
brctl addbr xenbr0
brctl addif xenbr0 eth0
ifconfig eth0 up
ifconfig xenbr0 up
ifconfig xenbr0 192.168.0.1
xl network-attach 1 type=vif
"
    domU_check="
until ifconfig eth0 192.168.0.2 &> /dev/null && ping -c 10 192.168.0.1; do
    sleep 30
done
echo \"${passed}\"
"
fi

if [[ "${test_variant}" == "gem-passthrough" ]]; then
    passed="${test_variant} test passed"

    # For a passthroughed GEM:
    # - bring up the network interface
    # - dynamically assign IP
    # - ping the default gateway
    domU_check="
set -ex
ifconfig eth0 up
udhcpc -i eth0 -n
ping -c 10 \$(ip route | awk '/^default/ {print \$3}')
echo \"${passed}\"
"
fi

# DomU
mkdir -p rootfs
cd rootfs
tar xzf ../binaries/initrd.tar.gz
mkdir proc
mkdir run
mkdir srv
mkdir sys
rm var/run
echo "#!/bin/sh

${domU_check}
/bin/sh" > etc/local.d/xen.start
chmod +x etc/local.d/xen.start
echo "rc_verbose=yes" >> etc/rc.conf
find . | cpio -H newc -o | gzip > ../binaries/domU-rootfs.cpio.gz
cd ..
rm -rf rootfs

# DOM0 rootfs
mkdir -p rootfs
cd rootfs
tar xzf ../binaries/initrd.tar.gz
mkdir proc
mkdir run
mkdir srv
mkdir sys
rm var/run
cp -ar ../binaries/dist/install/* .

echo "#!/bin/bash

export LD_LIBRARY_PATH=/usr/local/lib
bash /etc/init.d/xencommons start

/usr/local/lib/xen/bin/init-dom0less

${dom0_check}
" > etc/local.d/xen.start
chmod +x etc/local.d/xen.start
echo "rc_verbose=yes" >> etc/rc.conf
find . | cpio -H newc -o | gzip > ../binaries/dom0-rootfs.cpio.gz
cd ..


TFTP=/scratch/gitlab-runner/tftp
START=`pwd`

# ImageBuilder
echo 'MEMORY_START="0"
MEMORY_END="0x7ff00000"

DEVICE_TREE="mpsoc_smmu.dtb"
XEN="xen"
DOM0_KERNEL="Image"
DOM0_RAMDISK="dom0-rootfs.cpio.gz"
XEN_CMD="console=dtuart dtuart=serial0 dom0_mem=1024M"

NUM_DOMUS=1
DOMU_KERNEL[0]="Image"
DOMU_RAMDISK[0]="domU-rootfs.cpio.gz"
DOMU_MEM[0]="1024"

LOAD_CMD="tftpb"
UBOOT_SOURCE="boot.source"
UBOOT_SCRIPT="boot.scr"' > $TFTP/config

cp -f binaries/xen $TFTP/
cp -f binaries/Image $TFTP/
cp -f binaries/dom0-rootfs.cpio.gz $TFTP/
cp -f binaries/domU-rootfs.cpio.gz $TFTP/
# export dtb to artifacts
cp $TFTP/mpsoc_smmu.dtb .

if [[ "${test_variant}" == "gem-passthrough" ]]; then
    echo "
    DOMU_PASSTHROUGH_DTB[0]=\"eth0.dtb\"
    DOMU_PASSTHROUGH_PATHS[0]=\"/amba/ethernet@ff0e0000\"" >> $TFTP/config

    # export passthrough dtb to artifacts
    cp $TFTP/eth0.dtb .
fi

rm -rf imagebuilder
git clone https://gitlab.com/ViryaOS/imagebuilder
bash imagebuilder/scripts/uboot-script-gen -t tftp -d $TFTP/ -c $TFTP/config

# restart the board
cd /scratch/gitlab-runner
bash zcu102.sh 2
sleep 5
bash zcu102.sh 1
sleep 5
cd $START

# connect to serial
set +e
stty -F /dev/ttyUSB0 115200
timeout -k 1 120 nohup sh -c "cat /dev/ttyUSB0 | tee smoke.serial | sed 's/\r//'"

# stop the board
cd /scratch/gitlab-runner
bash zcu102.sh 2
cd $START

set -e
(grep -q "^Welcome to Alpine Linux" smoke.serial && grep -q "${passed}" smoke.serial) || exit 1
exit 0
