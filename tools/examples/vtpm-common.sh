#
# Copyright (c) 2005 IBM Corporation
# Copyright (c) 2005 XenSource Ltd.
#
# This library is free software; you can redistribute it and/or
# modify it under the terms of version 2.1 of the GNU Lesser General Public
# License as published by the Free Software Foundation.
#
# This library is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
# Lesser General Public License for more details.
#
# You should have received a copy of the GNU Lesser General Public
# License along with this library; if not, write to the Free Software
# Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
#

dir=$(dirname "$0")
. "$dir/logging.sh"
. "$dir/locking.sh"

VTPMDB="/etc/xen/vtpm.db"

#In the vtpm-impl file some commands should be defined:
#      vtpm_create, vtpm_setup, vtpm_reset, etc. (see below)
#This should be indicated by setting VTPM_IMPL_DEFINED.
if [ -r "$dir/vtpm-impl" ]; then
	. "$dir/vtpm-impl"
fi

if [ -z "$VTPM_IMPL_DEFINED" ]; then
	function vtpm_create () {
		true
	}
	function vtpm_setup() {
		true
	}
	function vtpm_reset() {
		true
	}
	function vtpm_suspend() {
		true
	}
	function vtpm_resume() {
		true
	}
	function vtpm_delete() {
		true
	}
fi


#Find the instance number for the vtpm given the name of the domain
# Parameters
# - vmname : the name of the vm
# Return value
#  Returns '0' if instance number could not be found, otherwise
#  it returns the instance number in the variable 'instance'
function vtpmdb_find_instance () {
	local vmname=$1
	local ret=0
	instance=$(cat $VTPMDB |                   \
	          awk -vvmname=$vmname             \
	          '{                               \
	             if ( 1 != index($1,"#")) {    \
	               if ( $1 == vmname ) {       \
	                 print $2;                 \
	                 exit;                     \
	               }                           \
	             }                             \
	           }')
	if [ "$instance" != "" ]; then
		ret=$instance
	fi
	echo "$ret"
}


# Check whether a particular instance number is still available
# returns "0" if it is not available, "1" otherwise.
function vtpmdb_is_free_instancenum () {
	local instance=$1
	local avail=1
	#Allowed instance number range: 1-255
	if [ $instance -eq 0 -o $instance -gt 255 ]; then
		avail=0
	else
		instances=$(cat $VTPMDB |                \
		           gawk                          \
		           '{                            \
		               if (1 != index($1,"#")) { \
		                 printf("%s ",$2);       \
		               }                         \
		            }')
		for i in $instances; do
			if [ $i -eq $instance ]; then
				avail=0
				break
			fi
		done
	fi
	echo "$avail"
}


# Get an available instance number given the database
# Returns an unused instance number
function vtpmdb_get_free_instancenum () {
	local ctr
	local instances
	local don
	instances=$(cat $VTPMDB |                \
	           gawk                          \
	           '{                            \
	               if (1 != index($1,"#")) { \
	                 printf("%s ",$2);       \
	               }                         \
	            }')
	ctr=1
	don=0
	while [ $don -eq 0 ]; do
		local found
		found=0
		for i in $instances; do
			if [ $i -eq $ctr ]; then
				found=1;
				break;
			fi
		done

		if [ $found -eq 0 ]; then
			don=1
			break
		fi
		let ctr=ctr+1
	done
	echo "$ctr"
}


# Add a domain name and instance number to the DB file
function vtpmdb_add_instance () {
	local vmname=$1
	local inst=$2

	if [ ! -f $VTPMDB ]; then
		echo "#Database for VM to vTPM association" > $VTPMDB
		echo "#1st column: domain name" >> $VTPMDB
		echo "#2nd column: TPM instance number" >> $VTPMDB
	fi
	res=$(vtpmdb_validate_entry $vmname $inst)
	if [ $res -eq 0 ]; then
		echo "$vmname $inst" >> $VTPMDB
	fi
}


#Validate whether an entry is the same as passed to this
#function
function vtpmdb_validate_entry () {
	local rc=0
	local vmname=$1
	local inst=$2

	res=$(cat $VTPMDB |            \
	     gawk -vvmname=$vmname     \
	          -vinst=$inst         \
	     '{                        \
	         if ( 1 == index($1,"#")) {\
	         } else                \
	         if ( $1 == vmname &&  \
	              $2 == inst) {    \
	            printf("1");       \
	            exit;              \
	         } else                \
	         if ( $1 == vmname ||  \
	              $2 == inst) {    \
	            printf("2");       \
	            exit;              \
	         }                     \
	     }')

	if [ "$res" == "1" ]; then
		let rc=1
	elif [ "$res" == "2" ]; then
		let rc=2
	fi
	echo "$rc"
}


#Remove an entry from the vTPM database given its domain name
#and instance number
function vtpmdb_remove_entry () {
	local vmname=$1
	local instance=$2
	local VTPMDB_TMP="$VTPMDB".tmp
	$(cat $VTPMDB |            \
	 gawk -vvmname=$vmname     \
	 '{                        \
	    if ( $1 != vmname ) {  \
	      print $0;            \
	    }                      \
	 '} > $VTPMDB_TMP)
	if [ -e $VTPMDB_TMP ]; then
		mv -f $VTPMDB_TMP $VTPMDB
		vtpm_delete $instance
	else
		log err "Error creating temporary file '$VTPMDB_TMP'."
	fi
}


# Find the reason for the creation of this device:
# Set global REASON variable to 'resume' or 'create'
function vtpm_get_create_reason () {
	local resume=$(xenstore-read $XENBUS_PATH/resume)
	if [ "$resume" == "True" ]; then
		REASON="resume"
	else
		REASON="create"
	fi
}


#Create a vTPM instance
# If no entry in the TPM database is found, the instance is
# created and an entry added to the database.
function vtpm_create_instance () {
	local domname=$(xenstore_read "$XENBUS_PATH"/domain)
	local res
	local instance
	vtpm_get_create_reason

	claim_lock vtpmdb
	instance=$(vtpmdb_find_instance $domname)
	if [ "$instance" == "0" ]; then
		#Try to give the preferred instance to the domain
		instance=$(xenstore_read "$XENBUS_PATH"/pref_instance)
		if [ "$instance" != "" ]; then
			res=$(vtpmdb_is_free_instancenum $instance)
			if [ $res -eq 0 ]; then
				instance=$(vtpmdb_get_free_instancenum)
			fi
		else
			instance=$(vtpmdb_get_free_instancenum)
		fi
		vtpmdb_add_instance $domname $instance
		if [ "$REASON" == "create" ]; then
			vtpm_create $instance
		elif [ "$REASON" == "resume" ]; then
			vtpm_resume $instance $domname
		else
			#default case for 'now'
			vtpm_create $instance
		fi
	fi

	release_lock vtpmdb

	if [ "$REASON" == "create" ]; then
		vtpm_reset $instance
	fi
	xenstore_write $XENBUS_PATH/instance $instance
}


#Remove an instance when a VM is terminating or suspending.
#Since it is assumed that the VM will appear again, the
#entry is kept in the VTPMDB file.
function vtpm_remove_instance () {
	local domname=$(xenstore_read "$XENBUS_PATH"/domain)

	claim_lock vtpmdb

	instance=$(vtpmdb_find_instance $domname)

	if [ "$instance" != "0" ]; then
		if [ "$REASON" == "suspend" ]; then
			vtpm_suspend $instance
		fi
	fi

	release_lock vtpmdb
}


#Remove an entry in the VTPMDB file given the domain's name
#1st parameter: The name of the domain
function vtpm_delete_instance () {
	local rc

	claim_lock vtpmdb

	instance=$(vtpmdb_find_instance $1)
	if [ "$instance" != "0" ]; then
		vtpmdb_remove_entry $1 $instance
	fi

	release_lock vtpmdb
}
