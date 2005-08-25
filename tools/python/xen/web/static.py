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
# Copyright (C) 2005 Mike Wray <mike.wray@hp.com>
#============================================================================
import os

from resource import Resource

class File(Resource):

    isLeaf = True

    def __init__(self, filename, defaultType=None):
        if defaultType is None:
            defaultType = "text/plain"
        self.filename = filename
        self.type = defaultType
        self.encoding = None

    def getFileSize(self):
        try:
            info = os.stat(self.filename)
            return info.st_size
        except:
            return 0

    def render(self, req):
        if self.type:
            req.setHeader('Content-Type', self.type)
        if self.encoding:
            req.setHeader('Content-Encoding', self.encoding)
        req.setHeader('Content-Length', self.getFileSize())
        try:
            io = file(self.filename, "r")
            while True:
                buf = io.read(1024)
                if not buf:
                    break
                req.write(buf)
        except IOError:
            pass
        try:
            if io:
                io.close()
        except:
            pass
        

        
