# Copyright (C) 2004 Mike Wray <mike.wray@hp.com>

import socket
import Xc
xc = Xc.new()

import sxp
import XendRoot
xroot = XendRoot.instance()
import XendDB

import EventServer
eserver = EventServer.instance()

from xenmgr.server import SrvConsoleServer
xcd = SrvConsoleServer.instance()

class XendConsoleInfo:
    """Console information record.
    """

    def __init__(self, console, dom1, port1, dom2, port2, conn=None):
        self.console = console
        self.dom1  = int(dom1)
        self.port1 = int(port1)
        self.dom2  = int(dom2)
        self.port2 = int(port2)
        self.conn  = conn
        #self.id = "%d.%d-%d.%d" % (self.dom1, self.port1, self.dom2, self.port2)
        self.id = str(port1)

    def __str__(self):
        s = "console"
        s += " id=%s" % self.id
        s += " src=%d.%d" % (self.dom1, self.port1)
        s += " dst=%d.%d" % (self.dom2, self.port2)
        s += " port=%s" % self.console
        if self.conn:
            s += " conn=%s:%s" % (self.conn[0], self.conn[1])
        return s

    def sxpr(self):
        sxpr = ['console',
                ['id', self.id],
                ['src', self.dom1, self.port1],
                ['dst', self.dom2, self.port2],
                ['port', self.console],
                ]
        if self.conn:
            sxpr.append(['connected', self.conn[0], self.conn[1]])
        return sxpr

    def connection(self):
        return self.conn

    def update(self, consinfo):
        conn = sxp.child(consinfo, 'connected')
        if conn:
            self.conn = conn[1:]
        else:
            self.conn = None

    def uri(self):
        """Get the uri to use to connect to the console.
        This will be a telnet: uri.

        return uri
        """
        host = socket.gethostname()
        return "telnet://%s:%s" % (host, self.console)

class XendConsole:

    dbpath = "console"

    def  __init__(self):
        self.db = XendDB.XendDB(self.dbpath)
        self.console = {}
        self.console_db = self.db.fetchall("")
        if xroot.get_rebooted():
            print 'XendConsole> rebooted: removing all console info'
            self.rm_all()
        eserver.subscribe('xend.domain.died', self.onDomainDied)
        eserver.subscribe('xend.domain.destroy', self.onDomainDied)

    def rm_all(self):
        """Remove all console info. Used after reboot.
        """
        for (k, v) in self.console_db.items():
            self._delete_console(k)

    def refresh(self):
        consoles = xcd.consoles()
        cons = {}
        for consinfo in consoles:
            id = str(sxp.child_value(consinfo, 'id'))
            cons[id] = consinfo
            if id not in self.console:
                self._new_console(consinfo)
        for c in self.console.values():
            consinfo = cons.get(c.id)
            if consinfo:
                c.update(consinfo)
            else:
                self._delete_console(c.id)

    def onDomainDied(self, event, val):
        dom = int(val)
        #print 'XendConsole>onDomainDied', 'event', event, "dom=", dom
        for c in self.consoles():
            #print 'onDomainDied', "dom=", dom, "dom1=", c.dom1, "dom2=", c.dom2
            if (c.dom1 == dom) or (c.dom2 == dom):
                'XendConsole>onDomainDied', 'delete console dom=', dom
                ctrl = xcd.get_domain_console(dom)
                if ctrl:
                    ctrl.close()
                self._delete_console(c.id)

    def sync(self):
        self.db.saveall("", self.console_db)

    def sync_console(self, id):
        self.db.save(id, self.console_db[id])

    def _new_console(self, consinfo):
        # todo: xen needs a call to get current domain id.
        dom1 = 0
        port1 = sxp.child_value(consinfo, 'local_port')
        dom2 = sxp.child_value(consinfo, 'domain')
        port2 = sxp.child_value(consinfo, 'remote_port')
        console = sxp.child_value(consinfo, 'console_port')
        info = XendConsoleInfo(console, dom1, int(port1), int(dom2), int(port2))
        info.update(consinfo)
        self._add_console(info.id, info)
        return info

    def _add_console(self, id, info):
        self.console[id] = info
        self.console_db[id] = info.sxpr()
        self.sync_console(id)

    def _delete_console(self, id):
        if id in self.console:
            del self.console[id]
        if id in self.console_db:
            del self.console_db[id]
            self.db.delete(id)

    def console_ls(self):
        self.refresh()
        return self.console.keys()

    def consoles(self):
        self.refresh()
        return self.console.values()
    
    def console_create(self, dom):
        consinfo = xcd.console_create(dom)
        info = self._new_console(consinfo)
        return info
    
    def console_get(self, id):
        self.refresh()
        return self.console.get(id)

    def console_delete(self, id):
        self._delete_console(id)

    def console_disconnect(self, id):
        id = int(id)
        xcd.console_disconnect(id)

def instance():
    global inst
    try:
        inst
    except:
        inst = XendConsole()
    return inst
