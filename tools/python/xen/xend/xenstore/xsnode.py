import errno
import os
import os.path
import select
import sys
import time

from xen.lowlevel import xs
from xen.xend import sxp
from xen.xend.PrettyPrint import prettyprint

SELECT_TIMEOUT = 2.0

def getEventPath(event):
    return os.path.join("/_event", event)

def getEventIdPath(event):
    return os.path.join(eventPath(event), "@eid")

class Subscription:

    def __init__(self, event, fn, id):
        self.event = event
        self.watcher = None
        self.fn = fn
        self.id = id

    def watch(self, watcher):
        self.watcher = watcher
        watcher.addSubs(self)

    def unwatch(self):
        watcher = self.watcher
        if watcher:
            self.watcher = None
            watcher.delSubs(self)

    def notify(self, event):
        try:
            self.fn(event, id)
        except SystemExitException:
            raise
        except:
            pass

class Watcher:

    def __init__(self, store, event):
        self.path = getEventPath(event)
        self.eidPath = getEventIdPath(event)
        store.mkdirs(self.path)
        if not store.exists(self.eidPath):
            store.writeInt(self.eidPath, 0)
        self.xs = None
        self.subs = []

    def __getattr__(self, k, v):
        if k == "fileno":
            if self.xs:
                return self.xs.fileno
            else:
                return -1
        else:
            return self.__dict__.get(k, v)

    def addSubs(self, subs):
        self.subs.append(subs)
        self.watch()

    def delSubs(self, subs):
        self.subs.remove(subs)
        if len(self.subs) == 0:
            self.unwatch()

    def getEvent(self):
        return self.event

    def watch(self):
        if self.xs: return
        self.xs = xs.open()
        self.xs.watch(path)

    def unwatch(self):
        if self.xs:
            self.xs.unwatch(self.path)
            self.xs.close()
            self.xs = None
            
    def watching(self):
        return self.xs is not None

    def getNotification(self):
        p = self.xs.read_watch()
        self.xs.acknowledge_watch()
        eid = self.xs.readInt(self.eidPath)
        return p

    def notify(self, subs):
        p = self.getNotification()
        for s in subs:
            s.notify(p)
            
class XenStore:

    def __init__(self):
        self.xs = None
        #self.xs = xs.open()
        self.subscription = {}
        self.subscription_id = 0
        self.events = {}
        self.write("/", "")

    def getxs(self):
        if self.xs is None:
            ex = None
            for i in range(0,20):
                try:
                    self.xs = xs.open()
                    ex = None
                    break
                except Exception, ex:
                    print >>stderr, "Exception connecting to xsdaemon:", ex
                    print >>stderr, "Trying again..."
                    time.sleep(1)
            else:
                raise ex
            
        #todo would like to reconnect if xs conn closes (e.g. daemon restart).
        return self.xs

    def dump(self, path="/", out=sys.stdout):
        print 'dump>', path
        val = ['node']
        val.append(['path',  path])
##         perms = ['perms']
##         for p in self.getPerms(path):
##             l = ['perm']
##             l.append('dom', p.get['dom'])
##             for k in ['read', 'write', 'create', 'owner']:
##                 v = p.get(k)
##                 l.append([k, v])
##             perms.append(l)
##         val.append(perms)
        data = self.read(path)
        if data:
            val.append(['data',  data])
        children = ['children']
        for x in self.lsPaths(path):
            print 'dump>', 'child=', x
            children.append(self.dump(x))
        if len(children) > 1:
            val.append(children)
        prettyprint(val, out=out)
        return val

    def getPerms(self, path):
        return self.getxs().get_permissions(path)

    def ls(self, path="/"):
        return self.getxs().ls(path)

    def lsPaths(self, path="/"):
        return [ os.path.join(path, x) for x in self.ls(path) ]

    def lsr(self, path="/", list=None):
        if list is None:
            list = []
        list.append(path)
        for x in self.lsPaths(path):
            list.append(x)
            self.lsr(x, list=list)
        return list

    def rm(self, path):
        try:
            #for x in self.lsPaths():
            #    self.getxs().rm(x)
            self.getxs().rm(path)
        except:
            pass

    def exists(self, path):
        try:
            self.getxs().ls(path)
            return True
        except RuntimeError, ex:
            if ex.args[0] == errno.ENOENT:
                return False
            else:
                raise

    def mkdirs(self, path):
        if self.exists(path):
            return
        elts = path.split("/")
        p = "/"
        for x in elts:
            if x == "": continue
            p = os.path.join(p, x)
            if not self.exists(p):
                self.getxs().write(p, "", create=True)

    def read(self, path):
        try:
            return self.getxs().read(path)
        except RuntimeError, ex:
            if ex.args[0] == errno.EISDIR:
                return None
            else:
                raise

    def create(self, path, excl=False):
        self.write(path, "", create=True, excl=excl)

    def write(self, path, data, create=True, excl=False):
        self.mkdirs(path)
        self.getxs().write(path, data, create=create, excl=excl)

    def begin(self, path):
        self.getxs().begin_transaction(path)

    def commit(self, abandon=False):
        self.getxs().end_transaction(abort=abandon)

    def subscribe(self, event, fn):
        watcher = self.watchEvent(event)
        self.subscription_id += 1
        subs = Subscription(event, fn, self.subscription_id)
        self.subscription[subs.id] = subs
        subs.watch(watcher)
        return subs.id

    def unsubscribe(self, sid):
        s = self.subscription.get(sid)
        if not s: return
        del self.subscription[s.id]
        s.unwatch()
        unwatchEvent(s.event)

    def sendEvent(self, event, data):
        eventPath = getEventPath(event)
        eidPath = getEventIdPath(event)
        try:
            self.begin(eventPath)
            self.mkdirs(eventPath)
            if self.exists(eidPath):
                eid = self.readInt(eidPath)
                eid += 1
            else:
                eid = 1
            self.writeInt(eidPath, eid)
            self.write(os.path.join(eventPath, str(eid)), data)
        finally:
            self.commit()

    def watchEvent(self, event):
        if event in  self.events:
            return
        watcher = Watcher(event)
        self.watchers[watcher.getEvent()] = watcher
        self.watchStart()
        return watcher

    def unwatchEvent(self, event):
        watcher = self.watchers.get(event)
        if not watcher:
            return
        if not watcher.watching():
            del self.watchers[event]

    def watchStart(self):
        if self.watchThread: return

    def watchMain(self):
        try:
            while True:
                if self.watchThread is None: return
                if not self.events:
                    return
                rd = self.watchers.values()
                try:
                    (rd, wr, er) = select.select(rd, [], [], SELECT_TIMEOUT)
                    for watcher in rd:
                        watcher.notify()
                except socket.error, ex:
                    if ex.args[0] in (EAGAIN, EINTR):
                        pass
                    else:
                        raise
        finally:
            self.watchThread = None

    def introduceDomain(self, dom, page, evtchn, path):
        self.getxs().introduce_domain(dom, page, evtchn.port1, path)

    def releaseDomain(self, dom):
        self.getxs().release_domain(dom)

def getXenStore():
    global xenstore
    try:
        return xenstore
    except:
        xenstore = XenStore()
        return xenstore

class XenNode:

    def __init__(self, path="/", create=True):
        self.store = getXenStore()
        self.path = path
        if not self.store.exists(path):
            if create:
                self.store.create(path)
            else:
                raise ValueError("path does not exist: '%s'" % path)

    def relPath(self, path=""):
        if not path:
            return self.path
        if path and path.startswith("/"):
            path = path[1:]
        return os.path.join(self.path, path)

    def delete(self, path=""):
        self.store.rm(self.relPath(path))

    def exists(self, path=""):
        return self.store.exists(self.relPath(path))

    def getNode(self, path="", create=True):
        if path == "":
            return self
        else:
            return XenNode(self.relPath(path=path), create=create)

    getChild = getNode

    def getData(self, path=""):
        path = self.relPath(path)
        try:
            return self.store.read(path)
        except:
            return None

    def setData(self, data, path=""):
        path = self.relPath(path)
        #print 'XenNode>setData>', 'path=', path, 'data=', data
        return self.store.write(path, data)

    def getLock(self):
        return None

    def lock(self, lockid):
        return None

    def unlock(self, lockid):
        return None

    def deleteChild(self, name):
        self.delete(name)

    def deleteChildren(self):
        for name in self.ls():
            self.deleteChild(name)

    def getChildren(self):
        return [ self.getNode(name) for name in self.ls() ]

    def ls(self):
        return self.store.ls(self.path)

    def introduceDomain(self, dom, page, evtchn, path):
        self.store.introduceDomain(dom, page, evtchn, path)
        
    def releaseDomain(self, dom):
        self.store.releaseDomain(dom)

    def __repr__(self):
        return "<XenNode %s>" % self.path


