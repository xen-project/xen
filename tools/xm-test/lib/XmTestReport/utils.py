#!/usr/bin/python

"""
 utils.py - Utilities for reporting xm-test results

 Copyright (C) International Business Machines Corp., 2005
 Author: Dan Smith <danms@us.ibm.com>

 This program is free software; you can redistribute it and/or modify
 it under the terms of the GNU General Public License as published by
 the Free Software Foundation; under version 2 of the License.

 This program is distributed in the hope that it will be useful,
 but WITHOUT ANY WARRANTY; without even the implied warranty of
 MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 GNU General Public License for more details.

 You should have received a copy of the GNU General Public License
 along with this program; if not, write to the Free Software
 Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA

"""

from xml.sax.saxutils import escape

def tagify(tag, string):
    return "<%s>%s</%s>" % (tag, escape(string.strip()), tag)


  
  
