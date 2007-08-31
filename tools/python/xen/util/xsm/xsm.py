XEN_SECURITY_MODULE = "flask"
from xsm_core import *

import xen.util.xsm.flask.flask as xsm_module

xsm_init(xsm_module)
from xen.util.xsm.flask.flask import *
del xsm_module

