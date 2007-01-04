#!/bin/bash

dir=$(dirname "$0")
. "$dir/vtpm-hotplug-common.sh"

vtpm_fatal_error=0

case "$command" in
  add)
    vtpm_create_instance
  ;;
  remove)
    vtpm_remove_instance
  ;;
esac

if [ $vtpm_fatal_error -eq 0 ]; then
	log debug "Successful vTPM operation '$command'."
	success
else
	fatal "Error while executing vTPM operation '$command'."
fi
