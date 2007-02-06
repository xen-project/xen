#!/usr/bin/python
"""
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

import atexit
import Test
import xapi

# Tracking of managed domains
_managedDomains = []
_VMuuids = []
registered = 0

def addManagedDomain(name):
    global registered
    _managedDomains.append(name)
    if not registered:
        atexit.register(destroyManagedDomains)
        registered = 1

def delManagedDomain(name):
    if name in _managedDomains:
        del _managedDomains[_managedDomains.index(name)]

def addXAPIDomain(uuid):
    global registered
    _VMuuids.append(uuid)
    if not registered:
        atexit.register(destroyManagedDomains)
        registered = 1

def delXAPIDomain(uuid):
    _VMuuids.remove(uuid)

def destroyManagedDomains():
    if len(_managedDomains) > 0:
        for m in _managedDomains:
            Test.traceCommand("xm destroy %s" % m)
            Test.traceCommand("xm delete %s" % m)
    if len(_VMuuids) > 0:
        for uuid in _VMuuids:
            Test.traceCommand("xm destroy %s" % uuid)
            Test.traceCommand("xm delete %s" % uuid)


