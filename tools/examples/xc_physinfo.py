#!/usr/bin/env python

# Get information about the physical host machine

import Xc

xc = Xc.new()

info = xc.physinfo()

fmt_info = [ ( 'CPU cores', info['cores']),
             ('Hyperthreads per core', info['ht_per_core']),
             ('CPU Speed (MHz)', info['cpu_khz'] / 1000),
             ('Total physical mem (MB)', info['total_pages'] / 256),
             ('Free physical mem (MB)', info['free_pages'] / 256) ]
      

for (item, val) in fmt_info:
    print "%-23s" % item, ':', val

