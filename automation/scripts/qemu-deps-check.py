#!/usr/bin/env python3
# -*- coding: utf-8 -*-
import sys

if sys.version_info < (3, 8):
    print("Python %d.%d.%d too old" %
          (sys.version_info.major,
           sys.version_info.minor,
           sys.version_info.micro))
    exit(1)

try:
    import tomllib
except ImportError:
    try:
        import tomli
    except ImportError:
        print("No tomli")
        exit(1)
