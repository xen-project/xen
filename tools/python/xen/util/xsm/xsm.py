import sys
import string
from xen.xend import XendOptions
from xen.util import xsconstants
from xsm_core import xsm_init

xoptions = XendOptions.instance()
xsm_module_name = xoptions.get_xsm_module_name()

xsconstants.XS_POLICY_USE = eval("xsconstants.XS_POLICY_" +
                                 string.upper(xsm_module_name))

xsm_module_path = "xen.util.xsm." + xsm_module_name + "." + xsm_module_name
xsm_module = __import__(xsm_module_path, globals(), locals(), ['*'])

xsm_init(xsm_module)

for op in dir(xsm_module):
    if not hasattr(sys.modules[__name__], op):
        setattr(sys.modules[__name__], op, getattr(xsm_module, op, None))
