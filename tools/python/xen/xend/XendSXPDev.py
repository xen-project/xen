#!/usr/bin/env python
#
# Helper functions for dealing with the sxp representation of devices

import types

# This includes a generic equivalent of pci_opts_list_to_sxp()
def dev_dict_to_sxp(dev):
    def f((key, val)):
        if isinstance(val, types.ListType):
            return map(lambda x: [key, x], val)
        return [[key, val]]
    dev_sxp = ['dev'] + reduce(lambda x, y: x + y, map(f, dev.items()))
    return dev_sxp
