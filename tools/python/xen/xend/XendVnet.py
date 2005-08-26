#============================================================================
# This library is free software; you can redistribute it and/or
# modify it under the terms of version 2.1 of the GNU Lesser General Public
# License as published by the Free Software Foundation.
#
# This library is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
# Lesser General Public License for more details.
#
# You should have received a copy of the GNU Lesser General Public
# License along with this library; if not, write to the Free Software
# Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
#============================================================================
# Copyright (C) 2004, 2005 Mike Wray <mike.wray@hp.com>
#============================================================================

"""Handler for vnet operations.
"""

from xen.util import Brctl
from xen.xend import sxp
from xen.xend.XendError import XendError
from xen.xend.XendLogging import log
from xen.xend.xenstore import XenNode, DBMap, DBVar

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

    __exports__ = [
        DBVar('id',     ty='str'),
        DBVar('dbid',   ty='str'),
        DBVar('config', ty='sxpr'),
       ]
    
    def __init__(self, db, config=None):
        if config:
            self.id = sxp.child_value(config, 'id')
            self.id = str(self.id)
            self.dbid = self.id.replace(':', '-')
            self.db = db.addChild(self.dbid)
            self.config = config
        else:
            self.db = db
            self.importFromDB()
            config = self.config
            
        self.bridge = sxp.child_value(config, 'bridge')
        if not self.bridge:
            self.bridge = "vnet%s" % self.id
        self.vnetif = sxp.child_value(config, 'vnetif')
        if not self.vnetif:
            self.vnetif = "vnif%s" % self.id

    def saveToDB(self, save=False, sync=False):
        self.db.saveDB(save=save, sync=sync)

    def exportToDB(self, save=False, sync=False):
        self.db.exportToDB(self, fields=self.__exports__, save=save, sync=sync)

    def importFromDB(self):
        self.db.importFromDB(self, fields=self.__exports__)

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
        val = vnet_cmd(['vnet.del', self.id])
        self.db.delete()
        return val

    def vifctl(self, op, vif, vmac):
        try:
            fn = self.vifctl_ops[op]
            return vnet_cmd([fn, ['vnet', self.id], ['vif', vif], ['vmac', vmac]])
        except XendError:
            log.warning("vifctl failed: op=%s vif=%s mac=%s", op, vif, vmac)

class XendVnet:
    """Index of all vnets. Singleton.
    """

    dbpath = "/vnet"

    def __init__(self):
        # Table of vnet info indexed by vnet id.
        self.vnet = {}
        self.db = DBMap(db=XenNode(self.dbpath))
        self.db.readDB()
        for vnetdb in self.db.values():
            try:
                info = XendVnetInfo(vnetdb)
                self.vnet[info.id] = info
                info.configure()
            except XendError, ex:
                log.warning("Failed to configure vnet %s: %s", str(info.id), str(ex))
            except Exception, ex:
                log.exception("Vnet error")
                vnetdb.delete()

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
        info = XendVnetInfo(self.db, config=config)
        self.vnet[info.id] = info
        info.saveToDB()
        info.configure()

    def vnet_delete(self, id):
        """Delete a vnet.

        @param id: vnet id
        """
        info = self.vnet_get(id)
        if info:
            del self.vnet[id]
            info.delete()

def instance():
    global inst
    try:
        inst
    except:
        inst = XendVnet()
    return inst
