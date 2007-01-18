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
#      vtpm_create, vtpm_setup, vtpm_start, etc. (see below)
if [ -r "$dir/vtpm-impl.alt" ]; then
	. "$dir/vtpm-impl.alt"
elif [ -r "$dir/vtpm-impl" ]; then
	. "$dir/vtpm-impl"
else
	function vtpm_create () {
		true
	}
	function vtpm_setup() {
		true
	}
	function vtpm_start() {
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
	function vtpm_migrate() {
		echo "Error: vTPM migration accross machines not implemented."
	}
	function vtpm_migrate_local() {
		echo "Error: local vTPM migration not supported"
	}
	function vtpm_migrate_recover() {
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
	local vmname ret instance
	vmname=$1
	ret=0

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
	local instance instances avail i
	instance=$1
	avail=1
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
	local ctr instances don found
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
	local res vmname inst
	vmname=$1
	inst=$2

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
	local res rc vmname inst
	rc=0
	vmname=$1
	inst=$2

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
		rc=1
	elif [ "$res" == "2" ]; then
		rc=2
	fi
	echo "$rc"
}


#Remove an entry from the vTPM database given its domain name
#and instance number
function vtpmdb_remove_entry () {
	local vmname instance VTPMDB_TMP
	vmname=$1
	instance=$2
	VTPMDB_TMP="$VTPMDB".tmp

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
# Returns 'resume' or 'create'
function vtpm_get_create_reason () {
	local resume
	resume=$(xenstore_read $XENBUS_PATH/resume)
	if [ "$resume" == "True" ]; then
		echo "resume"
	else
		echo "create"
	fi
}


#Create a vTPM instance
# If no entry in the TPM database is found, the instance is
# created and an entry added to the database.
function vtpm_create_instance () {
	local res instance domname reason
	domname=$(xenstore_read "$XENBUS_PATH"/domain)
	reason=$(vtpm_get_create_reason)

	claim_lock vtpmdb
	instance=$(vtpmdb_find_instance $domname)

	if [ "$instance" == "0" -a "$reason" != "create" ]; then
		release_lock vtpmdb
		return
	fi

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

		vtpm_create $instance

		if [ $vtpm_fatal_error -eq 0 ]; then
			vtpmdb_add_instance $domname $instance
		fi
	else
		if [ "$reason" == "resume" ]; then
			vtpm_resume $instance
		else
			vtpm_start $instance
		fi
	fi

	release_lock vtpmdb

	xenstore_write $XENBUS_PATH/instance $instance
}


#Remove an instance when a VM is terminating or suspending.
#Since it is assumed that the VM will appear again, the
#entry is kept in the VTPMDB file.
function vtpm_remove_instance () {
	local instance reason domname
	#Stop script execution quietly if path does not exist (anymore)
	xenstore-exists "$XENBUS_PATH"/domain
	domname=$(xenstore_read "$XENBUS_PATH"/domain)

	if [ "$domname" != "" ]; then
		claim_lock vtpmdb

		instance=$(vtpmdb_find_instance $domname)

		if [ "$instance" != "0" ]; then
			vtpm_suspend $instance
		fi

		release_lock vtpmdb
	fi
}


#Remove an entry in the VTPMDB file given the domain's name
#1st parameter: The name of the domain
function vtpm_delete_instance () {
	local instance

	claim_lock vtpmdb

	instance=$(vtpmdb_find_instance $1)
	if [ "$instance" != "0" ]; then
		vtpmdb_remove_entry $1 $instance
	fi

	release_lock vtpmdb
}

# Determine whether the given address is local to this machine
# Return values:
#  "-1" : the given machine name is invalid
#  "0"  : this is not an address of this machine
#  "1"  : this is an address local to this machine
function vtpm_isLocalAddress() {
	local addr res
	addr=$(ping $1 -c 1 |  \
	       gawk '{ print substr($3,2,length($3)-2); exit }')
	if [ "$addr" == "" ]; then
		echo "-1"
		return
	fi
	res=$(ifconfig | grep "inet addr" |  \
	     gawk -vaddr=$addr               \
	     '{                              \
	        if ( addr == substr($2, 6)) {\
	          print "1";                 \
	        }                            \
	     }'                              \
	    )
	if [ "$res" == "" ]; then
		echo "0"
		return
	fi
	echo "1"
}

# Perform a migration step. This function differentiates between migration
# to the local host or to a remote machine.
# Parameters:
# 1st: destination host to migrate to
# 2nd: name of the domain to migrate
# 3rd: the migration step to perform
function vtpm_migration_step() {
	local res=$(vtpm_isLocalAddress $1)
	if [ "$res" == "0" ]; then
		vtpm_migrate $1 $2 $3
	else
		vtpm_migrate_local
	fi
}

# Recover from migration due to an error. This function differentiates
# between migration to the local host or to a remote machine.
# Parameters:
# 1st: destination host the migration was going to
# 2nd: name of the domain that was to be migrated
# 3rd: the last successful migration step that was done
function vtpm_recover() {
	local res
	res=$(vtpm_isLocalAddress $1)
	if [ "$res" == "0" ]; then
		vtpm_migrate_recover $1 $2 $3
	fi
}


#Determine the domain id given a domain's name.
#1st parameter: name of the domain
#return value: domain id  or -1 if domain id could not be determined
function vtpm_domid_from_name () {
	local id name ids
	ids=$(xenstore-list /local/domain)
	for id in $ids; do
		name=$(xenstore_read /local/domain/$id/name)
		if [ "$name" == "$1" ]; then
			echo "$id"
			return
		fi
	done
	echo "-1"
}


#Add a virtual TPM instance number and its associated domain name
#to the VTPMDB file and activate usage of this virtual TPM instance
#by writing the instance number into the xenstore
#1st parm: name of virtual machine
#2nd parm: instance of assoicate virtual TPM
function vtpm_add_and_activate() {
	local domid=$(vtpm_domid_from_name $1)
	if [ "$domid" != "-1" ]; then
		vtpmdb_add_instance $1 $2
		xenstore-write backend/vtpm/$domid/0/instance $2
	fi
}
