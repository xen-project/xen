#!/bin/sh

# prepend CROSS_BIN_PATH to find the right "strip"
if [ -n "$CROSS_BIN_PATH" ]; then
    PATH="$CROSS_BIN_PATH:$PATH"
fi

exec $_INSTALL "$@"
