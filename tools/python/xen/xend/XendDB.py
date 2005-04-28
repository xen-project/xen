# Copyright (C) 2004 Mike Wray <mike.wray@hp.com>

import os
import os.path
import errno
import dircache
import time

import sxp
import XendRoot
xroot = XendRoot.instance()

class XendDB:
    """Persistence for Xend. Stores data in files and directories.
    """

    def __init__(self, path=None):
        self.dbpath = xroot.get_dbroot()
        if path:
            self.dbpath = os.path.join(self.dbpath, path)
        pass

    def listdir(self, dpath):
        try:
            return dircache.listdir(dpath)
        except:
            return []

    def filepath(self, path):
        return os.path.join(self.dbpath, path)
        
    def fetch(self, path):
        fpath = self.filepath(path)
        return self.fetchfile(fpath)

    def fetchfile(self, fpath):
        pin = sxp.Parser()
        fin = file(fpath, "rb")
        try:
            while 1:
                try:
                    buf = fin.read(1024)
                except IOError, ex:
                    if ex.errno == errno.EINTR:
                        continue
                    else:
                        raise
                pin.input(buf)
                if buf == '':
                    pin.input_eof()
                    break
        finally:
            fin.close()
        return pin.get_val()

    def save(self, path, sxpr):
        fpath = self.filepath(path)
        return self.savefile(fpath, sxpr)
    
    def savefile(self, fpath, sxpr):
        backup = False
        fdir = os.path.dirname(fpath)
        if not os.path.isdir(fdir):
            os.makedirs(fdir)
        if os.path.exists(fpath):
            backup = True
            real_fpath = fpath
            fpath += ".new."
            
        fout = file(fpath, "wb+")
        try:
            try:
                t = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime())
                fout.write("# %s %s\n" % (fpath, t))
                sxp.show(sxpr, out=fout)
            finally:
                fout.close()
        except:
            if backup:
                try:
                    os.unlink(fpath)
                except:
                    pass
                raise
        if backup:
            os.rename(fpath, real_fpath)

    def fetchall(self, path):
        dpath = self.filepath(path)
        d = {}
        for k in self.listdir(dpath):
            try:
                v = self.fetchfile(os.path.join(dpath, k))
                d[k] = v
            except:
                pass
        return d

    def saveall(self, path, d):
        for (k, v) in d.items():
            self.save(os.path.join(path, k), v)

    def delete(self, path):
        dpath = self.filepath(path)
        os.unlink(dpath)

    def ls(self, path):
        dpath = self.filepath(path)
        return self.listdir(dpath)
        

        
