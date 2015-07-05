#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""
XL migration stream format
"""

MAGIC = "Xen saved domain, xl format\n \0 \r"

HEADER_FORMAT = "=IIII"

MANDATORY_FLAG_STREAMV2 = 2
