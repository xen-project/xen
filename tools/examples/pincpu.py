#!/usr/bin/env python

#
# Destroy specified domain.
#

import Xc, sys, re, time

xc = Xc.new()

if len(sys.argv) < 3:
    print "Specify a domain identifier and CPU"
    sys.exit()

dom = int(sys.argv[1])
cpu = int(sys.argv[2])

orig_state = xc.domain_getinfo(first_dom=dom, max_doms=1)[0]['stopped']

while xc.domain_getinfo(first_dom=dom, max_doms=1)[0]['stopped'] != 1:
    xc.domain_stop( dom=dom )
    time.sleep(0.1)

xc.domain_pincpu( dom, cpu )

if orig_state == 0:
    xc.domain_start( dom=dom )




