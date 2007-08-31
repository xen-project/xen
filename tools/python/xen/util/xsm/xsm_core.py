import sys
import xen.util.xsm.dummy.dummy as dummy

def xsm_init(self):
    for op in dir(dummy):
        if not hasattr(self, op):
            setattr(self, op, getattr(dummy, op, None))
