# Copyright (C) 2004 Mike Wray <mike.wray@hp.com>

"""Handler for vnet operations.
"""

import sxp
import XendDB

class XendVnet:
    """Index of all vnets. Singleton.
    """

    dbpath = "vnet"

    def __init__(self):
        # Table of vnet info indexed by vnet id.
        self.vnet = {}
        self.db = XendDB.XendDB(self.dbpath)
        self.vnet = self.db.fetchall("")

    def vnet_ls(self):
        """List all vnets.
        """
        return self.vnet.keys()

    def vnets(self):
        return self.vnet.values()

    def vnet_get(self, id):
        """Get a vnet.

        id	vnet id
        """
        return self.vnet.get(id)

    def vnet_create(self, info):
        """Create a vnet.

        info	config
        """
        self.vnet_configure(info)

    def vnet_configure(self, info):
        """Configure a vnet.
        id	vnet id
        info	config
        """
        # Need to configure for real.
        # Only sync if succeeded - otherwise need to back out.
        self.vnet[info.id] = info
        self.db.save(info.id, info)

    def vnet_delete(self, id):
        """Delete a vnet.

        id	vnet id
        """
        # Need to delete for real. What if fails?
        if id in self.vnet:
            del self.vnet[id]
            self.db.delete(id)

def instance():
    global inst
    try:
        inst
    except:
        inst = XendVnet()
    return inst
