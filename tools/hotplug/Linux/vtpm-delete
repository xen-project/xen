#!/bin/bash

# This scripts must be called the following way:
# vtpm-delete <vtpm uuid>
# or
# vtpm-delete --vmname <vm name>

dir=$(dirname "$0")
. "$dir/vtpm-common.sh"

if [ "$1" == "--vmname" ]; then
	vtpm_uuid=$(vtpm_uuid_from_vmname $2)
	if [ "$vtpm_uuid" != "" ];then
		vtpm_delete_instance $vtpm_uuid
	fi
else
	vtpm_delete_instance $1
fi
