#!/usr/bin/env python

#
# Start execution of specified domain.
#

import Xc, sys, re

xc = Xc.new()

if len(sys.argv) != 2:
    print "Specify a domain identifier"
    sys.exit()

xc.domain_start( dom=int(sys.argv[1]) )
