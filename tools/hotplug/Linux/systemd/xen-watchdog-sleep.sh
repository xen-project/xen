#!/bin/sh

# The first argument ($1) is:
#     "pre" or "post"
# The second argument ($2) is:
#     "suspend", "hibernate", "hybrid-sleep", or "suspend-then-hibernate"

. /etc/xen/scripts/hotplugpath.sh

SERVICE_NAME="xen-watchdog.service"
STATE_FILE="${XEN_RUN_DIR}/xen-watchdog-sleep-flag"

case "$1" in
pre)
    if systemctl is-active --quiet "${SERVICE_NAME}"; then
        touch "${STATE_FILE}"
        echo "Stopping ${SERVICE_NAME} before $2."
        systemctl stop "${SERVICE_NAME}"
    fi
    ;;
post)
    if [ -f "${STATE_FILE}" ]; then
        echo "Starting ${SERVICE_NAME} after $2."
        systemctl start "${SERVICE_NAME}"
        rm "${STATE_FILE}"
    fi
    ;;
*)
    echo "Script called with unknown action '$1'. Arguments: '$@'"
    exit 1
    ;;
esac

exit 0
