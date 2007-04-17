#!/bin/sh
set -e


# Parse arguments
#
if [ $# -lt 1 -o $# -gt 4 ]; then
    echo "Usage: $0 config-file EXTRAVERSION XEN_TARGET_ARCH XEN_SYSTYPE"
    exit 1
fi

config_file=$1
extraversion=$2
target_arch=$3
systype=$4


# Start with initial config skeleton file, if any.
# Derive from linux-defconfig_xen_x86_32 otherwise.
#
skeleton=buildconfigs/linux-defconfig_${extraversion}_${target_arch}${systype}
[ -r $skeleton ] || skeleton=buildconfigs/linux-defconfig_xen_x86_32
[ -r $skeleton.local ] && skeleton=$skeleton.local
cp $skeleton $config_file


# Update
#
filter_template="s/^#\{0,1\} *\(CONFIG[^= ]*\).*/\/^#\\\{0,1\\\} *\1[= ].*\/d/p"
config_dirs="buildconfigs/conf.linux buildconfigs/conf.linux-${target_arch} buildconfigs/conf.linux-${extraversion} buildconfigs/conf.linux-${target_arch}-${extraversion}"

for config_dir in $config_dirs
do
    if [ -d $config_dir ]; then
        # processing is done in alphanumeric order
        find $config_dir -type f | sort | while read update
        do
            # create the filter rules in a temp file
            filter_rules=`mktemp -t xenupdateconf.XXXXXXXXXX`
            sed -n "${filter_template}" < $update > $filter_rules

            # filter the config file in place, removing any options that
            # will be updated.
            sed -f $filter_rules -i $config_file
            cat $update >> $config_file

            # clean up
            rm -f $filter_rules
        done
    fi
done
