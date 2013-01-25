#!/bin/sh -e
autoconf
( cd tools
  autoconf
  autoheader
)
( cd stubdom
  autoconf
)
( cd docs
  autoconf
)
