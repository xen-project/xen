#!/usr/bin/python

#
# List info on all domains.
#

import Xc, sys
xc = Xc.new()
print xc.domain_getinfo()

