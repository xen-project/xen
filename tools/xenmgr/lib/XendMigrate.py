# Copyright (C) 2004 Mike Wray <mike.wray@hp.com>

import sys
import socket

import sxp
import XendDB
import EventServer; eserver = EventServer.instance()

class XendMigrateInfo:

    # states: begin, active, failed, succeeded?

    def __init__(self, id, dom, dst):
        self.id = id
        self.state = 'begin'
        self.src_host = socket.gethostname()
        self.src_dom = dom
        self.dst_host = dst
        self.dst_dom = None
        
    def set_state(self, state):
        self.state = state

    def get_state(self):
        return self.state

    def sxpr(self):
        sxpr = ['migrate', ['id', self.id], ['state', self.state] ]
        sxpr_src = ['src', ['host', self.src_host], ['domain', self.src_dom] ]
        sxpr.append(sxpr_src)
        sxpr_dst = ['dst', ['host', self.dst] ]
        if self.dst_dom:
            sxpr_dst.append(['domain', self.dst_dom])
        sxpr.append(sxpr_dst)
        return sxpr
    

class XendMigrate:
    # Represents migration in progress.
    # Use log for indications of begin/end/errors?
    # Need logging of: domain create/halt, migrate begin/end/fail
    # Log via event server?

    dbpath = "migrate"
    
    def __init__(self):
        self.db = XendDB.XendDB(self.dbpath)
        self.migrate = {}
        self.migrate_db = self.db.fetchall("")
        self.id = 0

    def nextid(self):
        self.id += 1
        return "%d" % self.id

    def sync(self):
        self.db.saveall("", self.migrate_db)

    def sync_migrate(self, id):
        self.db.save(id, self.migrate_db[id])

    def close(self):
        pass

    def _add_migrate(self, id, info):
        self.migrate[id] = info
        self.migrate_db[id] = info.sxpr()
        self.sync_migrate(id)
        #eserver.inject('xend.migrate.begin', info.sxpr())

    def _delete_migrate(self, id):
        #eserver.inject('xend.migrate.end', id)
        del self.migrate[id]
        del self.migrate_db[id]
        self.db.delete(id)

    def migrate_ls(self):
        return self.migrate.keys()

    def migrates(self):
        return self.migrate.values()

    def migrate_get(self, id):
        return self.migrate.get(id)
    
    def migrate_begin(self, dom, dst):
        # Check dom for existence, not migrating already.
        # Create migrate info, tell xend to migrate it?
        # - or fork migrate command ourselves?
        # Subscribe to migrate notifications (for updating).
        id = self.nextid()
        info = XenMigrateInfo(id, dom, dst)
        self._add_migrate(id, info)
        return id

def instance():
    global inst
    try:
        inst
    except:
        inst = XendMigrate()
    return inst
