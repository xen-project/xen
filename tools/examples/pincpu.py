#!/usr/bin/env python

#
# Destroy specified domain.
#

import Xc, sys, re

xc = Xc.new()

if len(sys.argv) < 3:
    print "Specify a domain identifier and CPU"
    sys.exit()

xc.domain_pincpu( dom=int(sys.argv[1]), cpu=int(sys.argv[2]))

