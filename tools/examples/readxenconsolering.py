#!/usr/bin/env python

# Copyright (C) 2003 by Intel Research Cambridge

# File:   tools/examples/readconsolering.py
# Author: Mark A Williamson (mark.a.williamson@intel.com)
# Date:   2003-12-02

# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License, or (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA  02111-1307, USA.

 

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
