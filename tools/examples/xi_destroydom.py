#!/usr/bin/env python

#
# Destroy specified domain.
#

import Xc, sys, re

xc = Xc.new()

if len(sys.argv) < 2:
    print "Specify a domain identifier"
    sys.exit()

if (len(sys.argv) > 2) and re.match( 'force', sys.argv[2] ):
    xc.domain_destroy( dom=int(sys.argv[1]), force=1 )
else:
    xc.domain_destroy( dom=int(sys.argv[1]), force=0 )
