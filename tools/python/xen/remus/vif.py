from xen.remus.util import canonifymac

class VIF(object):
    def __init__(self, **props):
        self.__dict__.update(props)
        if 'mac' in props:
            self.mac = canonifymac(props['mac'])

    def __str__(self):
        return self.mac

def parse(props):
    "turn a vm device dictionary into a vif object"
    return VIF(**props)
