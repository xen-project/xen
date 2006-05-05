#
# Copyright (C) International Business Machines Corp., 2005
# Author: Dan Smith <danms@us.ibm.com>
#

from Console import *
from Test import *
from Xm import *
from XenDomain import *
from config import *
from XenDevice import *
from NetConfig import *

# Use the auxbin module in Xend to determine the correct Python path.  We
# take the first installed instance of auxbin that we find, and then run it
# to determine the correct path, appending that to sys.path.

AUXBIN = 'xen/util/auxbin.py'

for p in ['python%s' % sys.version[:3], 'python']:
    for l in ['/usr/lib64', '/usr/lib']:
        d = os.path.join(l, p)
        if os.path.exists(os.path.join(d, AUXBIN)):
            sys.path.append(d)
            import xen.util.auxbin
            libpath = xen.util.auxbin.libpath()
            sys.path = sys.path[:-1]
            sys.path.append(libpath)
            break

# Give this test a clean slate
destroyAllDomUs()

if os.environ.get("TEST_VERBOSE"):
    verbose = True
else:
    verbose = False

if verbose:
    timeStamp()

# We need to track network configuration, like ips, etc.
xmtest_netconf = NetConfig()
