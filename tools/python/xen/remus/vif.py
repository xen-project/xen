from xen.remus.util import canonifymac

class VIF(object):
    def __init__(self, **props):
        self.dev = 'unknown'
        self.__dict__.update(props)
        if 'mac' in props:
            self.mac = canonifymac(props['mac'])

    def __str__(self):
        return self.mac

def parse(props, domid, index):
    "turn a vm device dictionary into a vif object"
    vif = VIF(**props)
    vif.dev = 'vif%d.%d' % (domid, index)

    return vif
