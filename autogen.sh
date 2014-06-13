#!/bin/sh -e
autoconf -f
( cd tools
  autoconf -f
  autoheader
)
( cd stubdom
  autoconf -f
)
( cd docs
  autoconf -f
)
