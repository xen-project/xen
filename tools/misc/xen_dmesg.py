#!/usr/bin/env python

"""Reads out the contents of the console ring

Usage: readconsolering.py [-c]
The -c option causes the contents to be cleared.
"""

import sys, Xc # import the Xc Xen Control module

xc = Xc.new() # get a new instance of the control interface

clear_buffer = False

if sys.argv[1:] != []:
    if sys.argv[1] == "-c":
        clear_buffer = True
    else:
        print >> sys.stderr, "Usage: " + sys.argv[0] + """ [-c]
       Reads the contents of the console buffer.
       (specifying -c will also clear current contents)"""

# Get the console ring's contents as a string and print it out.
# If argument to readconsolering is true then the buffer is cleared as well as
# fetching the (pre-clearing) contents.
print xc.readconsolering(clear_buffer)
