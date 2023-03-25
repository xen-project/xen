#!/bin/sh

set -ex

test_variant=$1

wait_and_wakeup=
timeout=120
if [ -z "${test_variant}" ]; then
    passed="ping test passed"
    domU_check="
ifconfig eth0 192.168.0.2
until ping -c 10 192.168.0.1; do
    sleep 1
done
echo \"${passed}\"
"
    dom0_check="
until grep -q \"${passed}\" /var/log/xen/console/guest-domU.log; do
    sleep 1
done
# get domU console content into test log
tail -n 100 /var/log/xen/console/guest-domU.log
echo \"${passed}\"
"
elif [ "${test_variant}" = "s3" ]; then
    passed="suspend test passed"
    wait_and_wakeup="started, suspending"
    domU_check="
ifconfig eth0 192.168.0.2
echo domU started
"
    dom0_check="
until grep 'domU started' /var/log/xen/console/guest-domU.log; do
    sleep 1
done
echo \"${wait_and_wakeup}\"
set -x
echo deep > /sys/power/mem_sleep
echo mem > /sys/power/state
# now wait for resume
sleep 5
# get domU console content into test log
tail -n 100 /var/log/xen/console/guest-domU.log
xl list
xl dmesg | grep 'Finishing wakeup from ACPI S3 state' || exit 1
# check if domU is still alive
ping -c 10 192.168.0.2 || exit 1
echo \"${passed}\"
"
fi

# DomU
mkdir -p rootfs
cd rootfs
# fakeroot is needed to preserve device nodes in rootless podman container
fakeroot -s ../fakeroot-save tar xzf ../binaries/initrd.tar.gz
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
find . | fakeroot -i ../fakeroot-save cpio -H newc -o | gzip > ../binaries/domU-rootfs.cpio.gz
cd ..
rm -rf rootfs

# DOM0 rootfs
mkdir -p rootfs
cd rootfs
fakeroot -s ../fakeroot-save tar xzf ../binaries/initrd.tar.gz
mkdir boot
mkdir proc
mkdir run
mkdir srv
mkdir sys
rm var/run
cp -ar ../binaries/dist/install/* .

echo "#!/bin/bash

export LD_LIBRARY_PATH=/usr/local/lib
bash /etc/init.d/xencommons start

brctl addbr xenbr0
brctl addif xenbr0 eth0
ifconfig eth0 up
ifconfig xenbr0 up
ifconfig xenbr0 192.168.0.1

xl create /etc/xen/domU.cfg
${dom0_check}
" > etc/local.d/xen.start
chmod +x etc/local.d/xen.start
# just PVH for now
echo '
type = "pvh"
name = "domU"
kernel = "/boot/vmlinuz"
ramdisk = "/boot/initrd-domU"
extra = "root=/dev/ram0 console=hvc0"
memory = 512
vif = [ "bridge=xenbr0", ]
disk = [ ]
' > etc/xen/domU.cfg

echo "rc_verbose=yes" >> etc/rc.conf
echo "XENCONSOLED_TRACE=all" >> etc/default/xencommons
echo "QEMU_XEN=/bin/false" >> etc/default/xencommons
mkdir -p var/log/xen/console
cp ../binaries/bzImage boot/vmlinuz
cp ../binaries/domU-rootfs.cpio.gz boot/initrd-domU
find . | fakeroot -i ../fakeroot-save cpio -H newc -o | gzip > ../binaries/dom0-rootfs.cpio.gz
cd ..


TFTP=/scratch/gitlab-runner/tftp
CONTROLLER=control@thor.testnet

echo '
multiboot2 (http)/gitlab-ci/xen console=com1 com1=115200,8n1 loglvl=all guest_loglvl=all
module2 (http)/gitlab-ci/vmlinuz console=hvc0 root=/dev/ram0
module2 (http)/gitlab-ci/initrd-dom0
' > $TFTP/grub.cfg

cp -f binaries/xen $TFTP/xen
cp -f binaries/bzImage $TFTP/vmlinuz
cp -f binaries/dom0-rootfs.cpio.gz $TFTP/initrd-dom0

# start logging the serial; this gives interactive console, don't close its
# stdin to not close it; the 'cat' is important, plain redirection would hang
# until somebody opens the pipe; opening and closing the pipe is used to close
# the console
mkfifo /tmp/console-stdin
cat /tmp/console-stdin |\
ssh $CONTROLLER console | tee smoke.serial &

# start the system pointing at gitlab-ci predefined config
ssh $CONTROLLER gitlabci poweron
trap "ssh $CONTROLLER poweroff; : > /tmp/console-stdin" EXIT

if [ -n "$wait_and_wakeup" ]; then
    # wait for suspend or a timeout
    until grep "$wait_and_wakeup" smoke.serial || [ $timeout -le 0 ]; do
        sleep 1;
        : $((--timeout))
    done
    if [ $timeout -le 0 ]; then
        echo "ERROR: suspend timeout, aborting"
        exit 1
    fi
    # keep it suspended a bit, then wakeup
    sleep 30
    ssh $CONTROLLER wake
fi

until grep "$passed" smoke.serial || [ $timeout -le 0 ]; do
    sleep 1;
    : $((--timeout))
done
if [ $timeout -le 0 ]; then
    echo "ERROR: test timeout, aborting"
    exit 1
fi

sleep 1

(grep -q "^Welcome to Alpine Linux" smoke.serial && grep -q "${passed}" smoke.serial) || exit 1
exit 0
