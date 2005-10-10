set -e

export PATH=/sbin:/bin:/usr/bin:/usr/sbin:$PATH

log() {
  local level="$1"
  shift
  logger -p "daemon.$level" -- "$0:" "$@" || echo "$0 $@" >&2
}

xenstore_read() {
  local v=$(xenstore-read "$XENBUS_PATH"/type || true)
  if [ "$v" == "" ]
  then
    log error "xenstore-read $XENBUS_PATH/type failed."
    exit 1
  fi
  echo "$v"
}

xenstore_write() {
  log debug "Writing $@ to xenstore."
  xenstore-write "$@" || log error "Writing $@ to xenstore failed."
}

log debug "$@" "XENBUS_PATH=$XENBUS_PATH"
