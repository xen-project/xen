# Copyright (C) 2004 Mike Wray <mike.wray@hp.com>

"""Handler for vnet operations.
"""

from xen.util import Brctl

import sxp
import XendDB
from XendError import XendError
from XendLogging import log

def vnet_cmd(cmd):
    out = None
    try:
        try:
            out = file("/proc/vnet/policy", "wb")
            sxp.show(cmd, out)
        except IOError, ex:
            raise XendError(str(ex))
    finally:
        if out: out.close()

class XendVnetInfo:
    
    vifctl_ops = {'up': 'vif.add', 'down': 'vif.del'}
    
    def __init__(self, config):
        self.config = config
        self.id = sxp.child_value(config, 'id')
        self.id = str(self.id)
        self.bridge = sxp.child_value(config, 'bridge')
        if not self.bridge:
            self.bridge = "vnet%s" % self.id
        self.vnetif = sxp.child_value(config, 'vnetif')
        if not self.vnetif:
            self.vnetif = "vnetif%s" % self.id

    def sxpr(self):
        return self.config

    def configure(self):
        log.info("Configuring vnet %s", self.id)
        val = vnet_cmd(['vnet.add'] + sxp.children(self.config))
        Brctl.bridge_create(self.bridge)
        Brctl.vif_bridge_add({'bridge': self.bridge, 'vif': self.vnetif})
        return val
        
    def delete(self):
        log.info("Deleting vnet %s", self.id)
        Brctl.vif_bridge_rem({'bridge': self.bridge, 'vif': self.vnetif})
        Brctl.bridge_del(self.bridge)
        return vnet_cmd(['vnet.del', self.id])

    def vifctl(self, op, vif, vmac):
        try:
            fn = self.vifctl_ops[op]
            return vnet_cmd([fn, ['vnet', self.id], ['vif', vif], ['vmac', vmac]])
        except XendError:
            log.warning("vifctl failed: op=%s vif=%s mac=%s", op, vif, vmac)

class XendVnet:
    """Index of all vnets. Singleton.
    """

    dbpath = "vnet"

    def __init__(self):
        # Table of vnet info indexed by vnet id.
        self.vnet = {}
        self.db = XendDB.XendDB(self.dbpath)
        vnets = self.db.fetchall("")
        for config in vnets.values():
            info = XendVnetInfo(config)
            self.vnet[info.id] = info
            try:
                info.configure()
            except XendError, ex:
                log.warning("Failed to configure vnet %s: %s", str(info.id), str(ex))

    def vnet_of_bridge(self, bridge):
        """Get the vnet for a bridge (if any).

        @param bridge: bridge name
        @return vnet or None
        """
        for v in self.vnet.values():
            if v.bridge == bridge:
                return v
        else:
            return None

    def vnet_ls(self):
        """List all vnet ids.
        """
        return self.vnet.keys()

    def vnets(self):
        """List all vnets.
        """
        return self.vnet.values()

    def vnet_get(self, id):
        """Get a vnet.

        @param id: vnet id
        """
        id = str(id)
        return self.vnet.get(id)

    def vnet_create(self, config):
        """Create a vnet.

        @param config: config
        """
        info = XendVnetInfo(config)
        self.vnet[info.id] = info
        self.db.save(info.id, info.sxpr())
        info.configure()

    def vnet_delete(self, id):
        """Delete a vnet.

        @param id: vnet id
        """
        info = self.vnet_get(id)
        if info:
            del self.vnet[id]
            self.db.delete(id)
            info.delete()

def instance():
    global inst
    try:
        inst
    except:
        inst = XendVnet()
    return inst
