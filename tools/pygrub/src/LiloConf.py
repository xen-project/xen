#
#LiloConf.py
#

import sys, re, os
import logging
import GrubConf

class LiloImage(object):
    def __init__(self, lines, path):
        self.reset(lines, path)

    def __repr__(self):
        return ("title: %s\n"
                "  root: %s\n"
                "  kernel: %s\n"
                "  args: %s\n"
                "  initrd: %s\n" %(self.title, self.root, self.kernel,
                                   self.args, self.initrd))
    def reset(self, lines, path):
        self._root = self._initrd = self._kernel = self._args = None
        self.title = ""
        self.lines = []
        self.path = path
        map(self.set_from_line, lines)
        self.root = "" # dummy

    def set_from_line(self, line, replace = None):
        (com, arg) = GrubConf.grub_exact_split(line, 2)

        if self.commands.has_key(com):
            if self.commands[com] is not None:
                exec("%s = r\'%s\'" %(self.commands[com], re.sub('^"(.+)"$', r"\1", arg.strip())))
            else:
                logging.info("Ignored image directive %s" %(com,))
        else:
            logging.warning("Unknown image directive %s" %(com,))

        # now put the line in the list of lines
        if replace is None:
            self.lines.append(line)
        else:
            self.lines.pop(replace)
            self.lines.insert(replace, line)

    def set_kernel(self, val):
        self._kernel = (None, self.path + "/" + val)
    def get_kernel(self):
        return self._kernel
    kernel = property(get_kernel, set_kernel)

    def set_initrd(self, val):
        self._initrd = (None, self.path + "/" + val)
    def get_initrd(self):
        return self._initrd
    initrd = property(get_initrd, set_initrd)

    # set up command handlers
    commands = { "label": "self.title",
                 "root": "self.root",
                 "rootnoverify": "self.root",
                 "image": "self.kernel",
                 "initrd": "self.initrd",
                 "append": "self.args",
                 "read-only": None,
                 "chainloader": None,
                 "module": None}

class LiloConfigFile(object):
    def __init__(self, fn = None):
        self.filename = fn
        self.images = []
        self.timeout = -1
        self._default = 0

        if fn is not None:
            self.parse()

    def parse(self, buf = None):
        if buf is None:
            if self.filename is None:
                raise ValueError, "No config file defined to parse!"

            f = open(self.filename, 'r')
            lines = f.readlines()
            f.close()
        else:
            lines = buf.split("\n")

        path = os.path.dirname(self.filename)
        img = []
        for l in lines:
            l = l.strip()
            # skip blank lines
            if len(l) == 0:
                continue
            # skip comments
            if l.startswith('#'):
                continue
            # new image
            if l.startswith("image"):
                if len(img) > 0:
                    self.add_image(LiloImage(img, path))
                img = [l]
                continue

            if len(img) > 0:
                img.append(l)
                continue

            (com, arg) = GrubConf.grub_exact_split(l, 2)
            if self.commands.has_key(com):
                if self.commands[com] is not None:
                    exec("%s = r\"%s\"" %(self.commands[com], arg.strip()))
                else:
                    logging.info("Ignored directive %s" %(com,))
            else:
                logging.warning("Unknown directive %s" %(com,))

        if len(img) > 0:
            self.add_image(LiloImage(img, path))

    def add_image(self, image):
        self.images.append(image)

    def _get_default(self):
        for i in range(0, len(self.images) - 1):
            if self.images[i].title == self._default:
                return i
        return 0
    def _set_default(self, val):
        self._default = val
    default = property(_get_default, _set_default)

    commands = { "default": "self.default",
                 "timeout": "self.timeout",
                 "prompt": None,
                 "relocatable": None,
                 }

if __name__ == "__main__":
    if sys.argv < 2:
        raise RuntimeError, "Need a grub.conf to read"
    g = LiloConfigFile(sys.argv[1])
    for i in g.images:
        print i #, i.title, i.root, i.kernel, i.args, i.initrd
    print g.default
