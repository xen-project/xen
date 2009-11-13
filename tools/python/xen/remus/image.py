# VM image file manipulation

import logging, struct

import vm

SIGNATURE = 'LinuxGuestRecord'
LONGLEN = struct.calcsize('L')
INTLEN = struct.calcsize('i')
PAGE_SIZE = 4096
# ~0L
P2M_EXT_SIG = 4294967295L
# frames per page
FPP = 1024
LTAB_MASK = 0xf << 28
BATCH_SIZE = 1024
IDXLEN = INTLEN + BATCH_SIZE * LONGLEN

logging.basicConfig(level=logging.DEBUG)
log = logging.getLogger()

class VMParseException(Exception): pass

class VMImage(object):
    def __init__(self, img=None):
        """img may be a path or a file object.
        If compact is True, apply checkpoints to base image instead
        of simply concatenating them.
        """
        self.img = img

        self.dom = None
        self.fd = None
        self.header = None
        self.nr_pfns = 0
        # p2m extension header (unparsed)
        self.p2mext = None

        if self.img:
            self.open(self.img)

    def open(self, img):
        if isinstance(img, str):
            self.fd = file(img, 'rb')
        else:
            self.fd = img

        self.readheader()

    def readheader(self):
        sig = self.fd.read(len(SIGNATURE))
        if sig != SIGNATURE:
            raise VMParseException("Bad signature in image")

        hlen = self.fd.read(INTLEN)
        hlen, = struct.unpack('!i', hlen)

        self.header = self.fd.read(hlen)
        self.dom = parseheader(self.header)

    def readp2mfl(self):
        "read the P2M frame list"
        pfnlen = self.fd.read(LONGLEN)
        self.nr_pfns, = struct.unpack('L', pfnlen)
        p2m0 = self.fd.read(LONGLEN)

        p2mhdr = p2m0
        p2m0, = struct.unpack('L', p2m0)
        if p2m0 == P2M_EXT_SIG:
            elen = self.fd.read(INTLEN)
            elen, = struct.unpack('I', elen)

            self.p2mext = self.fd.read(elen)

            p2m0 = self.fd.read(LONGLEN)
            p2m0, = struct.unpack('L', p2m0)
        p2mfl = [p2m0]

        p2mfle = (self.nr_pfns + FPP - 1)/FPP - 1
        p2ms = self.fd.read(LONGLEN * p2mfle)
        p2mfl.extend(struct.unpack('%dL' % p2mfle, p2ms))

        self.p2mfl = p2mfl

    def flush(self):
        self.ofd.write(self.tail)

class Writer(object):
    """compress a stream of checkpoints into a single image of the
    last checkpoint"""
    def __init__(self, fd, compact=False):
        self.fd = fd
        self.compact = compact

        self.vm = None
        self.tail = None
        # offset to first batch of pages
        self.imgstart = 0
        # PFN mappings
        self.pfns = []

    def __del__(self):
        self.close()

    def writeheader(self):
        hlen = struct.pack('!i', len(self.vm.header))
        header = ''.join([SIGNATURE, hlen, self.vm.header])
        self.fd.write(header)

    def writep2mfl(self):
        p2m = [struct.pack('L', self.vm.nr_pfns)]
        if self.vm.p2mext:
            p2m.extend([struct.pack('L', P2M_EXT_SIG), self.vm.p2mext])
        p2m.append(struct.pack('%dL' % len(self.vm.p2mfl), *self.vm.p2mfl))
        self.fd.write(''.join(p2m))

    def writebatch(self, batch):
        def offset(pfn):
            isz = (pfn / BATCH_SIZE + 1) * IDXLEN
            return self.imgstart + isz + pfn * PAGE_SIZE

        if not self.compact:
            return self.fd.write(batch)

        batch = parsebatch(batch)
        # sort pages for better disk seek behaviour
        batch.sort(lambda x, y: cmp(x[0] & ~LTAB_MASK, y[0] & ~LTAB_MASK))

        for pfndesc, page in batch:
            pfn = pfndesc & ~LTAB_MASK
            if pfn > self.vm.nr_pfns:
                log.error('INVALID PFN: %d' % pfn)
            if len(self.pfns) <= pfn:
                self.pfns.extend([0] * (pfn - len(self.pfns) + 1))
            self.pfns[pfn] = pfndesc
            self.fd.seek(offset(pfn))
            self.fd.write(page)

        #print "max offset: %d, %d" % (len(self.pfns), offset(self.pfns[-1]))

    def writeindex(self):
        "Write batch header in front of each page"
        hdrlen = INTLEN + BATCH_SIZE * LONGLEN
        batches = (len(self.pfns) + BATCH_SIZE - 1) / BATCH_SIZE

        for i in xrange(batches):
            offset = self.imgstart + i * (hdrlen + (PAGE_SIZE * BATCH_SIZE))
            pfnoff = i * BATCH_SIZE
            # python auto-clamps overreads
            pfns = self.pfns[pfnoff:pfnoff + BATCH_SIZE]

            self.fd.seek(offset)
            self.fd.write(struct.pack('i', len(pfns)))
            self.fd.write(struct.pack('%dL' % len(pfns), *pfns))

    def slurp(self, ifd):
        """Apply an incremental checkpoint to a loaded image.
        accepts a path or a file object."""
        if isinstance(ifd, str):
            ifd = file(ifd, 'rb')

        if not self.vm:
            self.vm = VMImage(ifd)
            self.writeheader()

            self.vm.readp2mfl()
            self.writep2mfl()
            self.imgstart = self.fd.tell()

        while True:
            l, batch = readbatch(ifd)
            if l <= 0:
                break
            self.writebatch(batch)
        self.tail = batch + ifd.read()

    def flush(self):
        if self.tail:
            self.fd.seek(0, 2)
            self.fd.write(self.tail)
            if self.compact:
                self.writeindex()
        self.tail = None

    def close(self):
        self.flush()

def parseheader(header):
    "parses a header sexpression"
    return vm.parsedominfo(vm.strtosxpr(header))

def makeheader(dominfo):
    "create an image header from a VM dominfo sxpr"
    items = [SIGNATURE]
    sxpr = vm.sxprtostr(dominfo)
    items.append(struct.pack('!i', len(sxpr)))
    items.append(sxpr)
    return ''.join(items)

def readbatch(fd):
    batch = []
    batchlen = fd.read(INTLEN)
    batch.append(batchlen)
    batchlen, = struct.unpack('i', batchlen)
    log.info("batch length: %d" % batchlen)
    if batchlen <= 0:
        return (batchlen, batch[0])

    batchfns = fd.read(LONGLEN * batchlen)
    batch.append(batchfns)
    pages = fd.read(PAGE_SIZE * batchlen)
    if len(pages) != PAGE_SIZE * batchlen:
        log.error('SHORT READ: %d' % len(pages))
    batch.append(pages)

    return (batchlen, ''.join(batch))

def parsebatch(batch):
    "parse a batch string into pages"
    batchlen, batch = batch[:INTLEN], batch[INTLEN:]
    batchlen, = struct.unpack('i', batchlen)
    #print 'batch length: %d' % batchlen
    pfnlen = batchlen * LONGLEN
    pfns = struct.unpack('%dL' % batchlen, batch[:pfnlen])
    pagebuf = batch[pfnlen:]
    pages = [pagebuf[i*PAGE_SIZE:(i+1)*PAGE_SIZE] for i in xrange(batchlen)]
    return zip(pfns, pages)
