#
# ExtLinuxConf.py - Simple syslinux config parsing
#
# Copyright 2010 Citrix Systems Ltd.
#
# This software may be freely redistributed under the terms of the GNU
# general public license.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
#

import sys, re, os
import logging
import GrubConf

class ExtLinuxImage(object):
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
        self._initrd = self._kernel = self._readonly = None
        self._args = ""
        self.title = ""
        self.lines = []
        self.path = path
        self.root = ""
        map(self.set_from_line, lines)

    def set_from_line(self, line, replace = None):
        (com, arg) = GrubConf.grub_exact_split(line, 2)
        com = com.lower()

        # Special handling for mboot.c32
        if com.lower() == "append" and self.kernel is not None:
            (_,kernel) = self.kernel
            if kernel.endswith("mboot.c32"):
                kernel = None
                args = None
                initrd = None
                modules = arg.split("---")

                if len(modules) == 3: # Assume Xen + Kernel + Initrd
                    (_,kernel,initrd) = modules
                elif len(modules) == 2: # Assume Kernel + Initrd
                    (kernel,initrd) = modules

                if kernel:
                    setattr(self, "kernel", kernel.strip())
                if initrd:
                    setattr(self, "initrd", initrd.strip())

                # Bypass regular self.commands handling
                com = None
            elif "initrd=" in arg:
                # find initrd image in append line
                args = arg.strip().split(" ")
                for a in args:
                    if a.lower().startswith("initrd="):
                        setattr(self, "initrd", a.replace("initrd=", ""))
                        arg = arg.replace(a, "")

        if com is not None and self.commands.has_key(com):
            if self.commands[com] is not None:
                setattr(self, self.commands[com], re.sub('^"(.+)"$', r"\1", arg.strip()))
            else:
                logging.info("Ignored image directive %s" %(com,))
        elif com is not None:
            logging.warning("Unknown image directive %s" %(com,))

        # now put the line in the list of lines
        if replace is None:
            self.lines.append(line)
        else:
            self.lines.pop(replace)
            self.lines.insert(replace, line)

    def set_kernel(self, val):
        if val.find(" ") == -1:
            self._kernel = (None,val)
            self._args = None
            return
        (kernel, args) = val.split(None, 1)
        self._kernel = (None,kernel)
        self._args = args
    def get_kernel(self):
        return self._kernel
    def set_args(self, val):
        self._args = val
    def get_args(self):
        return self._args
    kernel = property(get_kernel, set_kernel)
    args = property(get_args, set_args)

    def set_initrd(self, val):
        self._initrd = (None,val)
    def get_initrd(self):
        return self._initrd
    initrd = property(get_initrd, set_initrd)

    def set_readonly(self, val):
        self._readonly = 1
    def get_readonly(self):
        return self._readonly
    readonly = property(get_readonly, set_readonly)

    # set up command handlers
    commands = {
        "label": "title",
        "kernel": "kernel",
        "append": "args"}

class ExtLinuxConfigFile(object):
    def __init__(self, fn = None):
        self.filename = fn
        self.images = []
        self.timeout = -1
        self._default = 0

        if fn is not None:
            self.parse()

    def new_image(self, title, lines):
        # ExtLinuxImage constructor doesn't have title but since path
        # is being used by get_{kernel|initrd} functions we pass
        # empty string rather than None (see lines above)
        return ExtLinuxImage(lines, "")

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
            if l.lower().startswith("label"):
                if len(img) > 0:
                    self.add_image(ExtLinuxImage(img, path))
                img = [l]
                continue

            if len(img) > 0:
                img.append(l)
                continue

            (com, arg) = GrubConf.grub_exact_split(l, 2)
            com = com.lower()
            if self.commands.has_key(com):
                if self.commands[com] is not None:
                    setattr(self, self.commands[com], arg.strip())
                else:
                    logging.info("Ignored directive %s" %(com,))
            else:
                logging.warning("Unknown directive %s" %(com,))

        if len(img) > 0:
            self.add_image(ExtLinuxImage(img, path))

    def hasPassword(self):
        return False

    def hasPasswordAccess(self):
        return True

    def add_image(self, image):
        self.images.append(image)

    def _get_default(self):
        for i in range(len(self.images)):
            if self.images[i].title == self._default:
                return i
        return 0
    def _set_default(self, val):
        self._default = val
    default = property(_get_default, _set_default)

    commands = { "default": "default",
                 "timeout": "timeout",
                 "serial": None,
                 "prompt": None,
                 "display": None,
                 "f1": None,
                 "f2": None,
                 }
        
if __name__ == "__main__":
    if len(sys.argv) < 2:
        raise RuntimeError, "Need a configuration file to read"
    g = ExtLinuxConfigFile(sys.argv[1])
    for i in g.images:
        print i
    print g.default
