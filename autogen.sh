#!/bin/sh -e
cd tools
autoconf
autoheader
cd ../stubdom
autoconf
