import blkdev

class VBD(blkdev.BlkDev):
    def handles(self, **props):
        uname = props.get('uname', '')
        return uname.startswith('phy:')
    handles = classmethod(handles)

blkdev.register(VBD)
