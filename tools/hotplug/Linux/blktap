#!/bin/bash

# Copyright (c) 2005, XenSource Ltd.

dir=$(dirname "$0")
. "$dir/xen-hotplug-common.sh"
. "$dir/block-common.sh"

findCommand "$@"

##
# check_blktap_sharing file mode
#
# Perform the sharing check for the given blktap and mode.
#
check_blktap_sharing()
{
    local file="$1"
    local mode="$2"

    local base_path="$XENBUS_BASE_PATH/$XENBUS_TYPE"
    for dom in $(xenstore-list "$base_path")
    do
        for dev in $(xenstore-list "$base_path/$dom")
        do
            params=$(xenstore_read_default "$base_path/$dom/$dev/params" "" | cut -d: -f2)
            if [ "$file" = "$params" ]
            then

                if [ "$mode" = 'w' ]
                then
                    if ! same_vm "$dom" 
                    then
                        echo 'guest'
                        return
                    fi
                else 
                    local m=$(xenstore_read_default "$base_path/$dom/$dev/mode" "")
                    m=$(canonicalise_mode "$m")

                    if [ "$m" = 'w' ] 
                    then
                        if ! same_vm "$dom"
                        then
                            echo 'guest'
                            return
                        fi
                    fi
                fi
            fi
        done
    done

    echo 'ok'
}


t=$(xenstore_read_default "$XENBUS_PATH/type" 'MISSING')
if [ -n "$t" ]
then
    p=$(xenstore_read "$XENBUS_PATH/params")
    p=${p#tapdisk:}
    # if we have a ':', chew from head including :
    if echo $p | grep -q \:
    then
        p=${p#*:}
    fi
fi
# some versions of readlink cannot be passed a regular file
if [ -L "$p" ]; then
    file=$(readlink -f "$p") || fatal "$p link does not exist."
else
    file="$p"
fi

if [ "$command" = 'add' ]
then
    [ -e "$file" ] || { fatal $file does not exist; }

    FRONTEND_ID=$(xenstore_read "$XENBUS_PATH/frontend-id")
    FRONTEND_UUID=$(xenstore_read "/local/domain/$FRONTEND_ID/vm")
    mode=$(xenstore_read "$XENBUS_PATH/mode")
    mode=$(canonicalise_mode "$mode")

    if [ "$mode" != '!' ] 
    then
        result=$(check_blktap_sharing "$file" "$mode")
        [ "$result" = 'ok' ] || ebusy "$file already in use by other domain"
    fi

    success
fi

exit 0
