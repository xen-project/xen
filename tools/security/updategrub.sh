#!/bin/sh
# *
# * updategrub
# *
# * Copyright (C) 2005 IBM Corporation
# *
# * Authors:
# * Stefan Berger <stefanb@us.ibm.com>
# *
# * This program is free software; you can redistribute it and/or
# * modify it under the terms of the GNU General Public License as
# * published by the Free Software Foundation, version 2 of the
# * License.
# *
# *
#

if [ -z "$runbash" ]; then
	runbash="1"
	export runbash
	exec sh -c "bash $0 $*"
	exit
fi


# Show usage of this program
usage ()
{
echo "Use this tool to add the binary policy to the Xen grub entry and
have Xen automatically enforce the policy when starting.

Usage: $0 <policy name> <root of xen repository>

<policy name>             : The name of the policy, i.e. xen_null
<root of xen repository>  : The root of the XEN repository. Give
                            complete path.

"
}

# This function sets the global variable 'linux'
# to the name of the linux kernel that was compiled
# For now a pattern should do the trick
getLinuxVersion ()
{
	path=$1
	linux=""
	for f in $path/linux-*-xen0 ; do
		versionfile=$f/include/linux/version.h
		if [ -r $versionfile ]; then
			lnx=`cat $versionfile |                \
			     grep UTS_RELEASE |                \
			     awk '{                            \
			       len=length($3);                 \
			       version=substr($3,2,len-2);     \
			       split(version,numbers,".");     \
			       if (numbers[4]=="") {           \
			         printf("%s.%s.%s",            \
			                 numbers[1],           \
			                 numbers[2],           \
			                 numbers[3]);          \
			       } else {                        \
			         printf("%s.%s.%s[.0-9]*-xen0",\
			                numbers[1],            \
			                numbers[2],            \
			                numbers[3]);           \
			       }                               \
			     }'`
		fi
		if [ "$lnx" != "" ]; then
			linux="[./0-9a-zA-z]*$lnx"
			return;
		fi
	done

	#Last resort.
	linux="vmlinuz-2.[45678].[0-9]*[.0-9]*-xen0$"
}

#Return where the grub.conf file is.
#I only know of one place it can be.
findGrubConf()
{
	grubconf="/boot/grub/grub.conf"
	if [ -w $grubconf ]; then
		return 1
	fi
	return 0
}


#Update the grub configuration file.
#Search for existing entries and replace the current
#policy entry with the policy passed to this script
#
#Arguments passed to this function
# 1st : the grub configuration file
# 2nd : the binary policy file name
# 3rd : the name or pattern of the linux kernel name to match
#
# The algorithm here is based on pattern matching
# and is working correctly if
# - under a title a line beginning with 'kernel' is found
#   whose following item ends with "xen.gz"
#   Example:  kernel /xen.gz dom0_mem=....
# - a module line matching the 3rd parameter is found
#
updateGrub ()
{
	grubconf=$1
	policyfile=$2
	linux=$3

	tmpfile="/tmp/new_grub.conf"

	cat $grubconf |                                \
	         awk -vpolicy=$policyfile              \
	             -vlinux=$linux '{                 \
	           if ( $1 == "title" ) {              \
	             kernelfound = 0;                  \
	             if ( policymaycome == 1 ){        \
	               printf ("\tmodule %s%s\n", path, policy);      \
	             }                                 \
	             policymaycome = 0;                \
	           }                                   \
	           else if ( $1 == "kernel" ) {        \
	             if ( match($2,"xen.gz$") ) {      \
	               path=substr($2,1,RSTART-1);     \
	               kernelfound = 1;                \
	             }                                 \
	           }                                   \
	           else if ( $1 == "module" &&         \
	                     kernelfound == 1 &&       \
	                     match($2,linux) ) {       \
	              policymaycome = 1;               \
	           }                                   \
	           else if ( $1 == "module" &&         \
	                     kernelfound == 1 &&       \
	                     policymaycome == 1 &&     \
	                     match($2,"[0-9a-zA-Z]*.bin$") ) { \
	              printf ("\tmodule %s%s\n", path, policy); \
	              policymaycome = 0;               \
	              kernelfound = 0;                 \
	              dontprint = 1;                   \
	           }                                   \
	           else if ( $1 == "" &&               \
	                     kernelfound == 1 &&       \
	                     policymaycome == 1) {     \
	              dontprint = 1;                   \
	           }                                   \
	           if (dontprint == 0) {               \
	             printf ("%s\n", $0);              \
	           }                                   \
	           dontprint = 0;                      \
	         } END {                               \
	           if ( policymaycome == 1 ) {         \
	             printf ("\tmodule %s%s\n", path, policy);  \
	           }                                   \
	         }' > $tmpfile
	if [ ! -r $tmpfile ]; then
		echo "Could not create temporary file! Aborting."
		exit -1
	fi
	diff $tmpfile $grubconf > /dev/null
	RES=$?
	if [ "$RES" == "0" ]; then
		echo "No changes were made to $grubconf."
	else
		echo "Successfully updated $grubconf."
		mv -f $tmpfile $grubconf
	fi
}

if [ "$1" == "" -o "$2" == "" ]; then
	echo "Error: Not enough command line parameters."
	echo ""
	usage
	exit -1
fi

if [ "$1" == "-?" ]; then
	usage
	exit 0
fi

policy=$1
policyfile=$policy.bin

getLinuxVersion $2

findGrubConf
ERR=$?
if [ $ERR -eq 0 ]; then
	echo "Could not find grub.conf. Aborting."
	exit -1
fi

updateGrub $grubconf $policyfile $linux
