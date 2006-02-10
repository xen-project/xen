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
# Copyright (C) 2005 XenSource Ltd
#============================================================================

"""Handler for vnet operations.
"""

from xen.util import Brctl
from xen.xend import sxp
from xen.xend.XendError import XendError
from xen.xend.XendLogging import log
from xen.xend.xenstore.xstransact import xstransact


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

    def __init__(self, dbpath, config=None):
        if config:
            self.id = str(sxp.child_value(config, 'id'))
            self.dbid = self.id.replace(':', '-')
            self.dbpath = dbpath + '/' + self.dbid
            self.config = config
        else:
            self.dbpath = dbpath
            self.importFromDB()
            
        self.bridge = sxp.child_value(self.config, 'bridge')
        if not self.bridge:
            self.bridge = "vnet%s" % self.id
        self.vnetif = sxp.child_value(self.config, 'vnetif')
        if not self.vnetif:
            self.vnetif = "vnif%s" % self.id


    def exportToDB(self, save=False, sync=False):
        to_store = {
            'id' : self.id,
            'dbid' : self.dbid,
            'config' : sxp.to_string(self.config)
            }
        xstransact.Write(self.dbpath, to_store)


    def importFromDB(self):
        (self.id, self.dbid, c) = xstransact.Gather(self.dbpath,
                                                    ('id', str),
                                                    ('dbid', str),
                                                    ('config', str))
        self.config = sxp.from_string(c)


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
        xstransact.Remove(self.dbpath)
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
        listing = xstransact.List(self.dbpath)
        for entry in listing:
            try:
                info = XendVnetInfo(self.dbpath + '/' + entry)
                self.vnet[info.id] = info
                info.configure()
            except XendError, ex:
                log.warning("Failed to configure vnet %s: %s", str(info.id), str(ex))
            except Exception, ex:
                log.exception("Vnet error")
                xstransact.Remove(self.dbpath + '/' + entry)

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

        @param id vnet id
        """
        id = str(id)
        return self.vnet.get(id)

    def vnet_create(self, config):
        """Create a vnet.

        @param config: config
        """
        info = XendVnetInfo(self.dbpath, config=config)
        self.vnet[info.id] = info
        info.exportToDB()
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
