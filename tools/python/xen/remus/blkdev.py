handlers = []

class BlkDevException(Exception): pass

class BlkDev(object):
    "Object representing a VM block device"
    def __init__(self, **props):
        self.uname = ''
        if 'dev' not in props:
            raise BlkDevException('no device')
        #if 'uname' not in props:
            #raise BlkDevException('no uname')
        if 'mode' not in props:
            raise BlkDevException('no mode')
        self.__dict__.update(props)
        self.dev = props['dev'].rstrip(':disk')

    def __str__(self):
        return '%s,%s,%s' % (self.uname, self.dev, self.mode)

def register(handler):
    "register a block device class with parser"
    if handler not in handlers:
        handlers.insert(0, handler)

def parse(props):
    "turn a vm device dictionary into a blkdev object"
    for handler in handlers:
        if handler.handles(**props):
            return handler(**props)
    return BlkDev(**props)
