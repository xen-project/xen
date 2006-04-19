# *
# * labelfuncs.sh
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
# * A collection of functions to handle polcies, mapfiles,
# * and ssidrefs.
#


#Some global variables for tools using this module
ACM_DEFAULT_ROOT="/etc/xen/acm-security"

# Set the policy and policydir variables
# Parameters:
# 1st : possible policy name
# 2nd : possible policy directory
# Results:
# The variables policy and policydir will hold the values for locating
# policy information
# If there are no errors, the functions returns a '1',
# a '0' otherwise.
setPolicyVars ()
{
	local ret
	# Set default values
	policydir="$ACM_DEFAULT_ROOT/policies"
	policy=""

	if [ "$1" == "" ]; then
		findGrubConf
		ret=$?
		if [ $ret -eq 0 ]; then
			echo "Could not find grub.conf."
			return 0;
		fi
		findPolicyInGrub $grubconf
		if [ "$policy" == "" ]; then
			echo "Could not find policy in grub.conf. Looked for entry using kernel $linux."
			return 0;
		fi
		echo "Assuming policy to be '$policy'.";
	else
		policy=$1
		if [ "$2" != "" ]; then
			policydir=$2
		fi
	fi

	return 1
}

# Find the mapfile given a policy nmame
# Parameters:
# 1st : the name of the policy whose map file is to be found, i.e.,
#       chwall
# 2nd : the policy directory for locating the map file
# Results:
# The variable mapfile will hold the realtive path to the mapfile
# for the given policy.
# In case the mapfile could be found, the functions returns a '1',
# a '0' otherwise.
findMapFile ()
{
	mapfile="$2/$1/$1.map"
	if [ -r "$mapfile" ]; then
		return 1
	fi
	return 0
}


# Determine the name of the primary policy
# Parameters
# 1st : the path to the mapfile; the path may be relative
#       to the current directory
# Results
# The variable primary will hold the name of the primary policy
getPrimaryPolicy ()
{
	local mapfile=$1
	primary=`cat $mapfile  |   \
	         awk '             \
	          {                \
	            if ( $1 == "PRIMARY" ) { \
	              res=$2;                \
	            }                        \
	          } END {                    \
	            print res;               \
	          } '`
}


# Determine the name of the secondary policy
# Parameters
# 1st : the path to the mapfile; the path may be relative
#       to the current directory
# Results
# The variable secondary will hold the name of the secondary policy
getSecondaryPolicy ()
{
	local mapfile=$1
	secondary=`cat $mapfile  |   \
	         awk '             \
	          {                \
	            if ( $1 == "SECONDARY" ) { \
	              res=$2;                \
	            }                        \
	          } END {                    \
	            print res;               \
	          } '`
}


#Return where the grub.conf file is.
#I only know of one place it can be.
#Returns:
# 1 : if the file is writeable and readable
# 2 : if the file is only readable
# 0 : if the file does not exist
findGrubConf()
{
	grubconf="/boot/grub/grub.conf"
	if [ -w $grubconf ]; then
		return 1
	fi
	if [ -r $grubconf ]; then
		return 2
	fi
	return 0
}


# This function sets the global variable 'linux'
# to the name and version of the Linux kernel that was compiled
# for domain 0.
# If this variable could not be found, the variable 'linux'
# will hold a pattern
# Parameters:
# 1st: the path to reach the root directory of the XEN build tree
#      where linux-*-xen is located at
# Results:
# The variable linux holds then name and version of the compiled
# kernel, i.e., 'vmlinuz-2.6.12-xen'
getLinuxVersion ()
{
	local path
	local versionfile
	local lnx
	if [ "$1" == "" ]; then
		path="/lib/modules/*-xen"
	else
		path="/lib/modules/$1"
	fi

	linux=""
	for f in $path ; do
		versionfile=$f/build/include/linux/version.h
		if [ -r $versionfile ]; then
			lnx=`cat $versionfile | \
			     grep UTS_RELEASE | \
			     awk '{             \
			       len=length($3);  \
			       version=substr($3,2,len-2);     \
			       split(version,numbers,".");     \
			       if (numbers[4]=="") {           \
			         printf("%s.%s.%s",            \
			                 numbers[1],           \
			                 numbers[2],           \
			                 numbers[3]);          \
			       } else {                        \
			         printf("%s.%s.%s[.0-9]*-xen", \
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
	linux="vmlinuz-2.[45678].[0-9]*[.0-9]*-xen$"
}


# Find out with which policy the hypervisor was booted with.
# Parameters
# 1st : The complete path to grub.conf, i.e., /boot/grub/grub.conf
# Result:
# Sets the variable 'policy' to the name of the policy
findPolicyInGrub ()
{
	local grubconf=$1
	local linux=`uname -r`
	policy=`cat $grubconf |                        \
	         awk -vlinux=$linux '{                 \
	           if ( $1 == "title" ) {              \
	             kernelfound = 0;                  \
	             policymaycome = 0;                \
	           }                                   \
	           else if ( $1 == "kernel" ) {        \
	             if ( match($2,"xen.gz$") ) {      \
	               pathlen=RSTART;                 \
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
	                     match($2,"[0-9a-zA-Z_]*.bin$") ) { \
	              policymaycome = 0;               \
	              kernelfound = 0;                 \
	              polname = substr($2,pathlen);    \
	              len=length(polname);             \
	              polname = substr(polname,0,len-4); \
	           }                                   \
	         } END {                               \
	           print polname                       \
	         }'`
}


# Get the SSID of a domain
# Parameters:
# 1st : domain ID, i.e. '1'
# Results
# If the ssid could be found, the variable 'ssid' will hold
# the currently used ssid in the hex format, i.e., '0x00010001'.
# The funtion returns '1' on success, '0' on failure
getSSIDUsingSecpolTool ()
{
	local domid=$1
	export PATH=$PATH:.
	ssid=`xensec_tool getssid -d $domid -f | \
	        grep -E "SSID:" |          \
	        awk '{ print $4 }'`

	if [ "$ssid" != "" ]; then
		return 1
	fi
	return 0
}


# Break the ssid identifier into its high and low values,
# which are equal to the secondary and primary policy references.
# Parameters:
# 1st: ssid to break into high and low value, i.e., '0x00010002'
# Results:
# The variable ssidlo_int and ssidhi_int will hold the low and
# high ssid values as integers.
getSSIDLOHI ()
{
	local ssid=$1
	ssidlo_int=`echo $ssid | awk          \
	            '{                        \
	               len=length($0);        \
	               beg=substr($0,1,2);    \
	               if ( beg == "0x" ) {   \
	                   dig = len - 2;     \
	                   if (dig <= 0) {    \
	                     exit;            \
	                   }                  \
	                   if (dig > 4) {     \
	                     dig=4;           \
	                   }                  \
	                   lo=sprintf("0x%s",substr($0,len-dig+1,dig)); \
	                   print strtonum(lo);\
	               } else {               \
	                   lo=strtonum($0);   \
	                   if (lo < 65536) {  \
	                     print lo;        \
	                   } else {           \
	                     hi=lo;           \
	                     hi2= (hi / 65536);\
	                     hi2_str=sprintf("%d",hi2); \
	                     hi2=strtonum(hi2_str);\
	                     lo=hi-(hi2*65536); \
	                     printf("%d",lo); \
	                   }                  \
			}                     \
	            }'`
	ssidhi_int=`echo $ssid | awk          \
	            '{                        \
	               len=length($0);        \
	               beg=substr($0,1,2);    \
	               if ( beg == "0x" ) {   \
	                   dig = len - 2;     \
	                   if (dig <= 0 ||    \
	                     dig >  8) {      \
	                     exit;            \
	                   }                  \
	                   if (dig < 4) {     \
	                     print 0;         \
	                     exit;            \
	                   }                  \
	                   dig -= 4;          \
	                   hi=sprintf("0x%s",substr($0,len-4-dig+1,dig)); \
	                   print strtonum(hi);\
	               } else {               \
	                   hi=strtonum($0);   \
	                   if (hi >= 65536) { \
	                     hi = hi / 65536; \
	                     printf ("%d",hi);\
	                   } else {           \
	                     printf ("0");    \
	                   }                  \
	               }                      \
	            }'`
	if [ "$ssidhi_int" == "" -o \
	     "$ssidlo_int" == "" ]; then
		return 0;
	fi
	return 1
}


#Update the grub configuration file.
#Search for existing entries and replace the current
#policy entry with the policy passed to this script
#
#Arguments passed to this function
# 1st : the grub configuration file with full path
# 2nd : the binary policy file name, i.e. chwall.bin
# 3rd : the name or pattern of the linux kernel name to match
#       (this determines where the module entry will be made)
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
	local grubconf=$1
	local policyfile=$2
	local linux=$3

	local tmpfile="/tmp/new_grub.conf"

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


#Compile a policy into its binary representation
# Parameters:
# 1st: The directory where the ./policies directory is located at
# 2nd: The name of the policy
genBinPolicy ()
{
	local root=$1
	local policy=$2
	pushd $root > /dev/null
	xensec_xml2bin -d policies $policy > /dev/null
	popd > /dev/null
}


# Copy the bootpolicy into the destination directory
# Generate the policy's .bin and .map files if necessary
# Parameters:
# 1st: Destination directory
# 2nd: The root directory of the security tools; this is where the
#      policies directory is located at
# 3rd: The policy name
# Returns  '1' on success, '0' on failure.
cpBootPolicy ()
{
	local dest=$1
	local root=$2
	local policy=$3
	local binfile=$root/policies/$policy/$policy.bin
	local dstfile=$dest/$policy.bin
	if [ ! -e $binfile ]; then
		genBinPolicy $root $policy
		if [ ! -e $binfile ]; then
			echo "Could not compile policy '$policy'."
			return 0
		fi
	fi

	if [ ! -e $dstfile -o \
	     $binfile -nt $dstfile ]; then
		cp -f $binfile $dstfile
	fi
	return 1
}


# Display all the labels in a given mapfile
# Parameters
# 1st: Full or relative path to the policy's mapfile
showLabels ()
{
	local mapfile=$1
	local line
	local ITEM
	local found=0

	if [ ! -r "$mapfile" -o "$mapfile" == "" ]; then
		echo "Cannot read from vm configuration file $vmfile."
		return -1
	fi

	getPrimaryPolicy $mapfile
	getSecondaryPolicy $mapfile

	echo "The following labels are available:"
	let line=1
	while [ 1 ]; do
		ITEM=`cat $mapfile |         \
		      awk -vline=$line       \
		          -vprimary=$primary \
		      '{                     \
		         if ($1 == "LABEL->SSID" &&  \
		             $2 == "VM" &&           \
		             $3 == primary ) {       \
		           ctr++;                    \
		           if (ctr == line) {        \
		             print $4;               \
		           }                         \
		         }                           \
		       } END {                       \
		       }'`

		if [ "$ITEM" == "" ]; then
			break
		fi
		if [ "$secondary" != "NULL" ]; then
			LABEL=`cat $mapfile |     \
			       awk -vitem=$ITEM   \
			       '{
			          if ($1 == "LABEL->SSID" && \
			              $2 == "VM" &&          \
			              $3 == "CHWALL" &&      \
			              $4 == item ) {         \
			            result = item;           \
			          }                          \
			        } END {                      \
			            print result             \
			        }'`
		else
			LABEL=$ITEM
		fi

		if [ "$LABEL" != "" ]; then
			echo "$LABEL"
			found=1
		fi
		let line=line+1
	done
	if [ "$found" != "1" ]; then
		echo "No labels found."
	fi
}


# Get the default SSID given a mapfile and the policy name
# Parameters
# 1st: Full or relative path to the policy's mapfile
# 2nd: the name of the policy
getDefaultSsid ()
{
	local mapfile=$1
	local pol=$2
	RES=`cat $mapfile    \
	     awk -vpol=$pol  \
	      {              \
	        if ($1 == "LABEL->SSID" && \
	            $2 == "ANY"         && \
	            $3 == pol           && \
	            $4 == "DEFAULT"       ) {\
	              res=$5;                \
	        }                            \
	      } END {                        \
	        printf "%04x", strtonum(res) \
	     }'`
	echo "default NULL mapping is $RES"
	defaultssid=$RES
}


#Relabel a VM configuration file
# Parameters
# 1st: Full or relative path to the VM configuration file
# 2nd: The label to translate into an ssidref
# 3rd: Full or relative path to the policy's map file
# 4th: The mode this function is supposed to operate in:
#      'relabel' : Relabels the file without querying the user
#      other     : Prompts the user whether to proceed
relabel ()
{
	local vmfile=$1
	local label=$2
	local mapfile=$3
	local mode=$4
	local SSIDLO
	local SSIDHI
	local RES

	if [ ! -r "$vmfile" ]; then
		echo "Cannot read from vm configuration file $vmfile."
		return -1
	fi

	if [ ! -w "$vmfile" ]; then
		echo "Cannot write to vm configuration file $vmfile."
		return -1
	fi

	if [ ! -r "$mapfile" ] ; then
		echo "Cannot read mapping file $mapfile."
		return -1
	fi

	# Determine which policy is primary, which sec.
	getPrimaryPolicy $mapfile
	getSecondaryPolicy $mapfile

	# Calculate the primary policy's SSIDREF
	if [ "$primary" == "NULL" ]; then
		SSIDLO="0001"
	else
		SSIDLO=`cat $mapfile |                    \
		        awk -vlabel=$label                \
		            -vprimary=$primary            \
		           '{                             \
		              if ( $1 == "LABEL->SSID" && \
		                   $2 == "VM" &&          \
		                   $3 == primary  &&      \
		                   $4 == label ) {        \
		                result=$5                 \
		              }                           \
		           } END {                        \
		             if (result != "" )           \
		               {printf "%04x", strtonum(result)}\
		           }'`
	fi

	# Calculate the secondary policy's SSIDREF
	if [ "$secondary" == "NULL" ]; then
		if [ "$primary" == "NULL" ]; then
			SSIDHI="0001"
		else
			SSIDHI="0000"
		fi
	else
		SSIDHI=`cat $mapfile |                    \
		        awk -vlabel=$label                \
		            -vsecondary=$secondary        \
		           '{                             \
		              if ( $1 == "LABEL->SSID" && \
		                   $2 == "VM"          && \
		                   $3 == secondary     && \
		                   $4 == label ) {        \
		                result=$5                 \
		              }                           \
		            }  END {                      \
		              if (result != "" )          \
		                {printf "%04x", strtonum(result)}\
		            }'`
	fi

	if [ "$SSIDLO" == "" -o \
	     "$SSIDHI" == "" ]; then
		echo "Could not map the given label '$label'."
		return -1
	fi

	ACM_POLICY=`cat $mapfile |             \
	    awk ' { if ( $1 == "POLICY" ) {    \
	              result=$2                \
	            }                          \
	          }                            \
	          END {                        \
	            if (result != "") {        \
	              printf result            \
	            }                          \
	          }'`

	if [ "$ACM_POLICY" == "" ]; then
		echo "Could not find 'POLICY' entry in map file."
		return -1
	fi

	SSIDREF="0x$SSIDHI$SSIDLO"

	if [ "$mode" != "relabel" ]; then
		RES=`cat $vmfile |  \
		     awk '{         \
		       if ( substr($1,0,7) == "ssidref" ) {\
		         print $0;             \
		       }                       \
		     }'`
		if [ "$RES" != "" ]; then
			echo "Do you want to overwrite the existing mapping ($RES)? (y/N)"
			read user
			if [ "$user" != "y" -a "$user" != "Y" ]; then
				echo "Aborted."
				return 0
			fi
		fi
	fi

	#Write the output
	local vmtmp1="/tmp/__setlabel.tmp1"
	local vmtmp2="/tmp/__setlabel.tmp2"
	touch $vmtmp1
	touch $vmtmp2
	if [ ! -w "$vmtmp1" -o ! -w "$vmtmp2" ]; then
		echo "Cannot create temporary files. Aborting."
		return -1
	fi
	RES=`sed -e '/^#ACM_POLICY/d' $vmfile > $vmtmp1`
	RES=`sed -e '/^#ACM_LABEL/d' $vmtmp1 > $vmtmp2`
	RES=`sed -e '/^ssidref/d' $vmtmp2 > $vmtmp1`
	echo "#ACM_POLICY=$ACM_POLICY" >> $vmtmp1
	echo "#ACM_LABEL=$label" >> $vmtmp1
	echo "ssidref = $SSIDREF" >> $vmtmp1
	mv -f $vmtmp1 $vmfile
	rm -rf $vmtmp1 $vmtmp2
	echo "Mapped label '$label' to ssidref '$SSIDREF'."
}


# Translate an ssidref into its label. This does the reverse lookup
# to the relabel function above.
# This function displays the results.
# Parameters:
# 1st: The ssidref to translate; must be in the form '0x00010002'
# 2nd: Full or relative path to the policy's mapfile
translateSSIDREF ()
{
	local ssidref=$1
	local mapfile=$2
	local line1
	local line2

	if [ ! -r "$mapfile" -o "$mapfile" == "" ]; then
		echo "Cannot read from vm configuration file $vmfile."
		return -1
	fi

	getPrimaryPolicy $mapfile
	getSecondaryPolicy $mapfile

	if [ "$primary" == "NULL" -a "$secondary" == "NULL" ]; then
		echo "There are no labels for the NULL policy."
		return
	fi

	getSSIDLOHI $ssidref
	ret=$?
	if [ $ret -ne 1 ]; then
		echo "Error while parsing the ssid ref number '$ssidref'."
	fi;

	let line1=0
	let line2=0
	while [ 1 ]; do
		ITEM1=`cat $mapfile |                       \
		      awk -vprimary=$primary                \
		          -vssidlo=$ssidlo_int              \
		          -vline=$line1                     \
		      '{                                    \
		         if ( $1 == "LABEL->SSID" &&        \
		              $3 == primary &&              \
		              int($5) == ssidlo     ) {     \
		             if (l == line) {               \
		                 print $4;                  \
		                 exit;                      \
		             }                              \
		             l++;                           \
		         }                                  \
		       }'`

		ITEM2=`cat $mapfile |                       \
		      awk -vsecondary=$secondary            \
		          -vssidhi=$ssidhi_int              \
		          -vline=$line2                     \
		      '{                                    \
		         if ( $1 == "LABEL->SSID" &&        \
		              $3 == secondary &&            \
		              int($5) == ssidhi     ) {     \
		             if (l == line) {               \
		                 print $4;                  \
		                 exit;                      \
		             }                              \
		             l++;                           \
		         }                                  \
		       }'`

		if [ "$secondary" != "NULL" ]; then
			if [ "$ITEM1" == "" ]; then
				let line1=0
				let line2=line2+1
			else
				let line1=line1+1
			fi

			if [ "$ITEM1" == "" -a \
			     "$ITEM2" == "" ]; then
				echo "Could not determine the referenced label."
				break
			fi

			if [ "$ITEM1" == "$ITEM2" ]; then
				echo "Label: $ITEM1"
				break
			fi
		else
			if [ "$ITEM1" != "" ]; then
				echo "Label: $ITEM1"
			else
				if [ "$found" == "0" ]; then
					found=1
				else
					break
				fi
			fi
			let line1=line1+1
		fi
	done
}
