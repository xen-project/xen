#!/usr/bin/env bash

# Run x86_64 dom0 tests on hardware.

set -ex -o pipefail

fatal() {
    echo "$(basename "$0") $*" >&2
    exit 1
}

WORKDIR="${PWD}"

# Test parameter defaults.
TEST="$1"
PASS_MSG="Test passed: ${TEST}"
XEN_CMD_DOM0="dom0=pvh dom0_max_vcpus=4 dom0_mem=4G"
XEN_CMD_XEN="sched=null loglvl=all guest_loglvl=all console_timestamps=boot"
XEN_CMD_EXTRA=""
DOM0_CMD=""
DOMU_CMD=""
DOMU_CFG='
type = "pvh"
name = "domU"
kernel = "/boot/vmlinuz"
ramdisk = "/boot/initrd-domU"
extra = "root=/dev/ram0 console=hvc0"
memory = 512
'
DOMU_CFG_EXTRA=""
copy_domU_files () { :; }
copy_dom0_files () { :; }

# Select test variant.
if [ "${TEST}" = "ping" ]; then
    DOMU_MSG="domU online"
    DOMU_CMD="
ifconfig eth0 192.168.0.2
until ping -c 10 192.168.0.1; do
    sleep 1
done
echo \"${DOMU_MSG}\"
"
    DOM0_CMD="
brctl addbr xenbr0
brctl addif xenbr0 eth0
ifconfig eth0 up
ifconfig xenbr0 up
ifconfig xenbr0 192.168.0.1
# get domU console content into test log
tail -F /var/log/xen/console/guest-domU.log 2>/dev/null | sed -e \"s/^/(domU) /\" &
xl create /etc/xen/domU.cfg
set +x
until grep -q \"${DOMU_MSG}\" /var/log/xen/console/guest-domU.log; do
    sleep 1
done
set -x
echo \"${PASS_MSG}\"
"
    DOMU_CFG_EXTRA='
vif = [ "bridge=xenbr0", ]
disk = [ ]
'
elif [ "${TEST}" = "argo" ]
then
    PASS_MSG="TEST: Message from DOMU"
    XEN_CMD_EXTRA="argo=1,mac-permissive=1"
    DOMU_CMD="
insmod /root/xen-argo.ko
until false
do
  echo \"${PASS_MSG}\"
  sleep 1
done | argo-exec -p 28333 -d 0 -- /bin/echo
"
    DOM0_CMD="
insmod /root/xen-argo.ko
xl create /etc/xen/domU.cfg
argo-exec -l -p 28333 -- /bin/echo
"
copy_dom0_files ()
{
    cp "${WORKDIR}/binaries/xen-argo.ko" "root/"
    cp -ar "${WORKDIR}/binaries/lib/"* "usr/local/lib/"
    cp "${WORKDIR}/binaries/argo-exec" "usr/local/bin/"
}
copy_domU_files () { copy_dom0_files; }
else
    fatal "Unknown test: ${TEST}"
fi

# Set up domU rootfs.
mkdir -p rootfs
cd rootfs
tar xzf ../binaries/initrd.tar.gz
mkdir proc run srv sys
rm var/run
echo "#!/bin/sh
set -x
export LD_LIBRARY_PATH=/usr/local/lib
PATH=/usr/local/bin:/usr/local/sbin:\$PATH
${DOMU_CMD}
" > etc/local.d/xen.start
chmod +x etc/local.d/xen.start
echo "rc_verbose=yes" >> etc/rc.conf
sed -i -e 's/^Welcome/domU \0/' etc/issue
copy_domU_files
find . | cpio -H newc -o | gzip > ../binaries/domU-rootfs.cpio.gz
cd ..
rm -rf rootfs

# Set up dom0 rootfs.
mkdir -p rootfs
cd rootfs
tar xzf ../binaries/initrd.tar.gz
mkdir boot proc run srv sys
rm var/run
cp -ar ../binaries/dist/install/* .
echo "#!/bin/bash
set -x
export LD_LIBRARY_PATH=/usr/local/lib
bash /etc/init.d/xencommons start
${DOM0_CMD}
" > etc/local.d/xen.start
chmod +x etc/local.d/xen.start
echo "${DOMU_CFG}${DOMU_CFG_EXTRA}" > etc/xen/domU.cfg
echo "rc_verbose=yes" >> etc/rc.conf
echo "XENCONSOLED_TRACE=all" >> etc/default/xencommons
echo "QEMU_XEN=/bin/false" >> etc/default/xencommons
mkdir -p var/log/xen/console
cp ../binaries/bzImage boot/vmlinuz
cp ../binaries/domU-rootfs.cpio.gz boot/initrd-domU
copy_dom0_files
find . | cpio -H newc -o | gzip > ../binaries/dom0-rootfs.cpio.gz
cd ..

# Load software into TFTP server directory.
TFTP="/scratch/gitlab-runner/tftp"
XEN_CMDLINE="${XEN_CMD_CONSOLE} ${XEN_CMD_XEN} ${XEN_CMD_DOM0} ${XEN_CMD_EXTRA}"
cp -f binaries/xen ${TFTP}/${TEST_BOARD}/xen
cp -f binaries/bzImage ${TFTP}/${TEST_BOARD}/vmlinuz
cp -f binaries/dom0-rootfs.cpio.gz ${TFTP}/${TEST_BOARD}/initrd-dom0
echo "
net_default_server=10.0.6.1
multiboot2 (tftp)/${TEST_BOARD}/xen ${XEN_CMDLINE} sync_console
module2 (tftp)/${TEST_BOARD}/vmlinuz console=hvc0 root=/dev/ram0 earlyprintk=xen
module2 (tftp)/${TEST_BOARD}/initrd-dom0
boot
" > ${TFTP}/${TEST_BOARD}/grub.cfg

# Power cycle board and collect serial port output.
SERIAL_DEV="/dev/serial/${TEST_BOARD}"
sh /scratch/gitlab-runner/${TEST_BOARD}.sh 2
sleep 5
sh /scratch/gitlab-runner/${TEST_BOARD}.sh 1
sleep 5
set +e
stty -F ${SERIAL_DEV} 57600

# Capture test result and power off board before exiting.
export PASSED="${PASS_MSG}"
export TEST_CMD="cat ${SERIAL_DEV}"
export TEST_LOG="smoke.serial"

./automation/scripts/console.exp | sed 's/\r\+$//'
TEST_RESULT=$?
sh "/scratch/gitlab-runner/${TEST_BOARD}.sh" 2
exit ${TEST_RESULT}
