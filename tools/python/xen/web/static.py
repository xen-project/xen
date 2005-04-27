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
        

        
