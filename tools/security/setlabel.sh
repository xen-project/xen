#!/bin/sh
# *
# * setlabel
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
# * 'setlabel' labels virtual machine (domain) configuration files with
# * security identifiers that can be enforced in Xen.
# *
# * 'setlabel -?' shows the usage of the program
# *
# * 'setlabel -l vmconfig-file' lists all available labels (only VM
# *            labels are used right now)
# *
# * 'setlabel vmconfig-file security-label map-file' inserts the 'ssidref'
# *                       that corresponds to the security-label under the
# *                       current policy (if policy changes, 'label'
# *                       must be re-run over the configuration files;
# *                       map-file is created during policy translation and
# *                       is found in the policy's directory
#

if [ -z "$runbash" ]; then
	runbash="1"
	export runbash
	exec sh -c "bash $0 $*"
fi


usage ()
{
	echo "Usage: $0 [Option] <vmfile> <label> <policy name> "
	echo "    or $0 -l <policy name>"
	echo ""
	echo "Valid Options are:"
	echo "-r          : to relabel a file without being prompted"
	echo ""
	echo "vmfile      : XEN vm configuration file"
	echo "label       : the label to map"
	echo "policy name : the name of the policy, i.e. 'chwall'"
	echo ""
	echo "-l <policy name> is used to show valid labels in the map file"
	echo ""
}


findMapFile ()
{
	mapfile="./$1.map"
	if [ -r "$mapfile" ]; then
		return 1
	fi

	mapfile="./policies/$1/$1.map"
	if [ -r "$mapfile" ]; then
		return 1
	fi

	return 0
}

showLabels ()
{
	mapfile=$1
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

getPrimaryPolicy ()
{
	mapfile=$1
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

getSecondaryPolicy ()
{
	mapfile=$1
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


getDefaultSsid ()
{
	mapfile=$1
	pol=$2
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

relabel ()
{
	vmfile=$1
	label=$2
	mapfile=$3
	mode=$4

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
		SSIDLO="0000"
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
		SSIDHI="0000"
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
	vmtmp1="/tmp/__setlabel.tmp1"
	vmtmp2="/tmp/__setlabel.tmp2"
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



if [ "$1" == "-r" ]; then
	mode="relabel"
	shift
elif [ "$1" == "-l" ]; then
	mode="show"
	shift
elif [ "$1" == "-?" ]; then
	mode="usage"
fi

if [ "$mode" == "show" ]; then
	if [ "$1" == "" ]; then
		usage
		exit -1;
	fi
	findMapFile $1
	res=$?
	if [ "$res" != "0" ]; then
		showLabels $mapfile
	else
		echo "Could not find map file for policy '$1'."
	fi
elif [ "$mode" == "usage" ]; then
	usage
else
	if [ "$3" == "" ]; then
		usage
		exit -1;
	fi
	findMapFile $3
	res=$?
	if [ "$res" != "0" ]; then
		relabel $1 $2 $mapfile $mode
	else
		echo "Could not find map file for policy '$3'."
	fi

fi
