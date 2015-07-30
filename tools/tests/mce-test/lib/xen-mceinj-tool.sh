#!/bin/bash
#
# Software injection based test cases: test cases are triggered via
# mce-inject tool.
# Copyright (c) 2010, Intel Corporation
# 
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License version
# 2 as published by the Free Software Foundation.
# 
# This program is distributed in the hope that it will be useful, but
# WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
# General Public License for more details.
# 
# You should have received a copy of the GNU General Public License
# along with this program; If not, see <http://www.gnu.org/licenses/>.
#
# Author: Xudong Hao <xudong.hao@intel.com>
#

. $ROOT/config/setup.conf

#Guest Image Preparation
hvm_image_prepare()
{
    local image=$1
    local tmpdir=`mktemp -d`
    local tmpfile=`mktemp`
    local offset=`kpartx -l $image | awk '{print $NF*512}'`
    mount -oloop,offset=$offset $image $tmpdir && echo "mount image to $tmpdir"
    local g_grub=$tmpdir/boot/grub/grub.conf
    if [ $? -ne 0 ]; then
        show "  Mount image failed!"
        return 1
    fi

    if ! grep FLAG_CONSOLE $g_grub; then
        sed -e '/kernel/s/$/ console=ttyS0,115200,8n1 console=tty0/g' \
            $g_grub > $tmpfile
        mv -f $tmpfile $g_grub
        rm -f $tmpfile
        echo "
#### FLAG_CONSOLE #### " >> $g_grub
    fi
    umount $tmpdir
    rm -fr $tmpdir

    return 0
}

create_hvm_guest()
{
    local image=$1
    local originconfig="/etc/xen/xmexample.hvm"
    local TF=`mktemp`
    local case_dir=$ROOT/results/$this_case
    local config=$case_dir/guest_config
    [ -d $case_dir ] || mkdir $case_dir
    [ -f $logfile ] || touch $logfile
    local File=`echo $image|sed "s/\//\\\\\\\\\\//g"`
    local g_name="`basename $image`_`date +%H%M%S`"

    hvm_image_prepare $image

    while getopts ":u:m:" Option
    do
        case $Option in
            u ) vcpus=$OPTARG;;
            m ) memory=$OPTARG;;
            e ) bridge_name=$OPTARG;;
            * ) ;;
        esac
    done

    cp $originconfig $config -f

    if [ -z $image ]; then
        show "Image file $image does not exist, Please input one valid file"
        return 1
    fi

    sed -e "/^disk/s/file:.*,\(hda\)/file:${File},\1/" $config \
          | sed -e "/^disk/s/phy:.*,\(hda\)/file:${File},\1/" >$TF
    mv -f $TF $config

    [ -z $memory ] || sed -i "/^memory/s/^.*$/memory = $memory/" $config
    [ -z $vcpus ] || sed -i "1,/^#vcpus/s/^#vcpus.*$/vcpus=$vcpus/;1d" $config
    sed -i "/^vif/s/vif/#vif/" $config
    sed -i "/^name/s/^.*$/name = \"$g_name\"/" $config

    string1=$(ls /dev/pts | sort)
    xm cr $config
    [ $? -eq 0 ] && domid=`xm list $g_name | tail -n1 | awk '{print $2}'`
    if [ -z $domid ]; then
        show "  Guest can not boot up"
        return 1
    fi
    
    sleep 10

    string2=$(ls /dev/pts | sort)

    get_guest_klog
    sleep 40

    return 0
}

get_guest_klog()
{
    local case_dir=$ROOT/results/$this_case
    gklog=$case_dir/gklog
    [ -d $case_dir ] || mkdir $case_dir
    [ -f $gklog ] || touch $gklog
    for fo in $string2; do
        echo $string1 | grep $fo -wq
        [ $? -eq 1 ] && num=$fo
    done
    cat /dev/pts/$num > $gklog &
}

mce_inject_trigger()
{
    local errtype=$1
    local append=""
    while getopts ":d:u:p:" Option
    do
        case $Option in
            d ) domid=$OPTARG;;
            u ) cpu=$OPTARG;;
            p ) pageaddr=$OPTARG;;
            * ) ;;
        esac
    done

    [ -z $domid ] || append=$append" -d $domid"
    [ -z $cpu ] || append=$append" -c $cpu"
    [ -z $pageaddr ] || append=$append" -p $pageaddr"

    [ -f $ROOT/tools/xen-mceinj ]
    if [ $? -eq 0 ]; then
        xm dmesg -c
        $ROOT/tools/xen-mceinj -t $errtype $append
        if [ $? -ne 0 ]; then
            show "  Failed: Maybe the memory addr is out of range. \
                      Please check whether used xen-mceinj tool correctlly"
            return 1
        fi
    else
        show "  Failed: please compile xen-mce inject tool firstly"
        return 1
    fi
    return 0
}

xen_verify()
{
    local case_dir=$ROOT/results/$this_case
    local xenlog=$case_dir/xenlog
    [ -d $case_dir ] || mkdir $case_dir
    [ -f $xenlog ] || touch $xenlog
    xm dmesg > $xenlog
    grep "Error is successfully recovered" $xenlog > /dev/null
    if [ $? -eq 0 ]; then
        show "  Passed: Xen handle this MCE error successfully"
    else
        show "  Failed: Xen does not handle MCE error correctly !!"
        return 1
    fi
    return 0
}

guest_verify()
{
    grep "kernel page recovery" $gklog > /dev/null
    if [ $? -eq 0 ]; then
        show "  Passed: Guest recive MCE error and solved correctly"
    else
        show "  Failed: Guest fail to solve MCE error"
        return 1
    fi
    return 0
}

mcelog_verify()
{
    local err_type=$1
    local ret=0
    local case_dir=$ROOT/results/$this_case
    local mcelog=$case_dir/mcelog
    [ -d $case_dir ] || mkdir $case_dir
    [ -f $mcelog ] || touch $mcelog
    mcelog > $mcelog
    if [ -z $mcelog ]; then
        show "  Failed: MCELOG does not catch anything"
        return 1
    else
        if [ $err_type -eq 0 ]; then
            grep "MEMORY CONTROLLER MS_CHANNELunspecified_ERR" $mcelog \
                > /dev/null
            ret=$?
        elif [ $err_type -eq 1 ]; then
            grep "Generic CACHE Level-2 Eviction Error" $mcelog > /dev/null
            ret=$?
        elif [ $err_type -eq 2 ]; then
            grep "Data CACHE Level-2 Data-Read Error" $mcelog > /dev/null
            ret=$?
        fi

        if [ $ret -eq 0 ]; then
            show "  Passed: MCElog catch a correct error"
        else 
            show "  Failed: MCE log catch a incorrect error !!"
            return 1
        fi
    fi

    return 0
}

function des_guest()
{
    xm des $domid    
}

function clean_env()
{
    [ -d $ROOT/results ] || mkdir $ROOT/results
    # clean logs and results of last test for this case
    rm -fr $ROOT/results/$this_case/*
}

function show()
{
    local case_dir=$ROOT/results/$this_case
    local logfile=$case_dir/testlog
    [ -d $case_dir ] || mkdir $case_dir
    [ -f $logfile ] || touch $logfile
    echo -e $* | tee -a $logfile > /dev/null
}

function gen_result()
{
    local ret=$1
    local case_dir=$ROOT/results/$this_case
    local result=$case_dir/result
    [ -d $case_dir ] || mkdir $case_dir
    [ -f $result ] || touch $result
    
    if [ $ret -eq 0 ]; then
        echo "PASSED" > $result
    elif [ $ret -eq 1 ]; then
        echo "FAILED" > $result
        echo "   Please check testlog for details!!! " >> $result
    else
        echo "NORESULT" > $result
        echo "   Please check testlog for details!!! " >> $result
    fi
}
