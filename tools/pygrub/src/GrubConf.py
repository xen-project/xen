#
# GrubConf.py - Simple grub.conf parsing
#
# Copyright 2009 Citrix Systems Inc.
# Copyright 2005-2006 Red Hat, Inc.
# Jeremy Katz <katzj@redhat.com>
#
# This software may be freely redistributed under the terms of the GNU
# general public license.
#
# You should have received a copy of the GNU General Public License
# along with this program; If not, see <http://www.gnu.org/licenses/>.
#

import os, sys
import logging
import re

def grub_split(s, maxsplit = -1):
    eq = s.find('=')
    if eq == -1:
        return s.split(None, maxsplit)

    # see which of a space or tab is first
    sp = s.find(' ')
    tab = s.find('\t')
    if (tab != -1 and tab < sp) or (tab != -1 and sp == -1):
        sp = tab

    if eq != -1 and eq < sp or (eq != -1 and sp == -1):
        return s.split('=', maxsplit)
    else:
        return s.split(None, maxsplit)

def grub_exact_split(s, num):
    ret = grub_split(s, num - 1)
    if len(ret) < num:
        return ret + [""] * (num - len(ret))
    return ret

def get_path(s):
    """Returns a tuple of (GrubDiskPart, path) corresponding to string."""
    if not s.startswith('('):
        return (None, s)
    idx = s.find(')')
    if idx == -1:
        raise ValueError, "Unable to find matching ')'"
    d = s[:idx]
    return (GrubDiskPart(d), s[idx + 1:])

class GrubDiskPart(object):
    def __init__(self, str):
        if str.find(',') != -1:
            (self.disk, self.part) = str.split(",", 2)
        else:
            self.disk = str
            self.part = None

    def __repr__(self):
        if self.part is not None:
            return "d%dp%d" %(self.disk, self.part)
        else:
            return "d%d" %(self.disk,)

    def get_disk(self):
        return self._disk
    def set_disk(self, val):
        val = val.replace("(", "").replace(")", "")
        if val.startswith("/dev/xvd"):
            disk = val[len("/dev/xvd")]
            self._disk = ord(disk)-ord('a')
        else:
            self._disk = int(val[2:])
    disk = property(get_disk, set_disk)

    def get_part(self):
        return self._part
    def set_part(self, val):
        if val is None:
            self._part = val
            return
        val = val.replace("(", "").replace(")", "")
        if val[:5] == "msdos":
            val = val[5:]
        if val[:3] == "gpt":
            val = val[3:]
        self._part = int(val)
    part = property(get_part, set_part)

class _GrubImage(object):
    def __init__(self, title, lines):
        self.reset(lines)
        self.title = title.strip()

    def __repr__(self):
        return ("title: %s\n" 
                "  root: %s\n"
                "  kernel: %s\n"
                "  args: %s\n"
                "  initrd: %s\n" %(self.title, self.root, self.kernel,
                                   self.args, self.initrd))
    def _parse(self, lines):
        map(self.set_from_line, lines)

    def reset(self, lines):
        self._root = self._initrd = self._kernel = self._args = None
        self.lines = []
        self._parse(lines)

    def set_root(self, val):
        self._root = GrubDiskPart(val)
    def get_root(self):
        return self._root
    root = property(get_root, set_root)

    def set_kernel(self, val):
        if val.find(" ") == -1:
            self._kernel = get_path(val)
            self._args = None
            return
        (kernel, args) = val.split(None, 1)
        self._kernel = get_path(kernel)
        self._args = args
    def get_kernel(self):
        return self._kernel
    def get_args(self):
        return self._args
    kernel = property(get_kernel, set_kernel)
    args = property(get_args)

    def set_initrd(self, val):
        self._initrd = get_path(val)
    def get_initrd(self):
        return self._initrd
    initrd = property(get_initrd, set_initrd)

class GrubImage(_GrubImage):
    def __init__(self, title, lines):
        _GrubImage.__init__(self, title, lines)
    
    def set_from_line(self, line, replace = None):
        (com, arg) = grub_exact_split(line, 2)

        if self.commands.has_key(com):
            if self.commands[com] is not None:
                setattr(self, self.commands[com], arg.strip())
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

    # set up command handlers
    commands = { "root": "root",
                 "rootnoverify": "root",
                 "kernel": "kernel",
                 "initrd": "initrd",
                 "chainloader": None,
                 "module": None}

class _GrubConfigFile(object):
    def __init__(self, fn = None):
        self.filename = fn
        self.images = []
        self.timeout = -1
        self._default = 0
        self.passwordAccess = True
        self.passExc = None

        if fn is not None:
            self.parse()

    def parse(self, buf = None):
        raise RuntimeError, "unimplemented parse function"   

    def hasPasswordAccess(self):
        return self.passwordAccess

    def setPasswordAccess(self, val):
        self.passwordAccess = val

    def hasPassword(self):
        return hasattr(self, 'password')

    def checkPassword(self, password):
        # Always allow if no password defined in grub.conf
        if not self.hasPassword():
            return True

        pwd = getattr(self, 'password').split()

        # We check whether password is in MD5 hash for comparison
        if pwd[0] == '--md5':
            try:
                import crypt
                if crypt.crypt(password, pwd[1]) == pwd[1]:
                    return True
            except Exception, e:
                self.passExc = "Can't verify password: %s" % str(e)
                return False

        # ... and if not, we compare it as a plain text
        if pwd[0] == password:
            return True

        return False

    def set(self, line):
        (com, arg) = grub_exact_split(line, 2)
        if self.commands.has_key(com):
            if self.commands[com] is not None:
                setattr(self, self.commands[com], arg.strip())
            else:
                logging.info("Ignored directive %s" %(com,))
        else:
            logging.warning("Unknown directive %s" %(com,))

    def add_image(self, image):
        self.images.append(image)

    def _get_default(self):
        return self._default
    def _set_default(self, val):
        if val == "saved":
            self._default = 0
        else:
            self._default = val

        if self._default < 0:
            raise ValueError, "default must be positive number"
    default = property(_get_default, _set_default)

    def set_splash(self, val):
        self._splash = get_path(val)
    def get_splash(self):
        return self._splash
    splash = property(get_splash, set_splash)

    # set up command handlers
    commands = { "default": "default",
                 "timeout": "timeout",
                 "fallback": "fallback",
                 "hiddenmenu": "hiddenmenu",
                 "splashimage": "splash",
                 "password": "password" }
    for c in ("bootp", "color", "device", "dhcp", "hide", "ifconfig",
              "pager", "partnew", "parttype", "rarp", "serial",
              "setkey", "terminal", "terminfo", "tftpserver", "unhide"):
        commands[c] = None
    del c

class GrubConfigFile(_GrubConfigFile):
    def __init__(self, fn = None):
        _GrubConfigFile.__init__(self,fn)
        
    def new_image(self, title, lines):
        return GrubImage(title, lines)

    def parse(self, buf = None):
        if buf is None:
            if self.filename is None:
                raise ValueError, "No config file defined to parse!"

            f = open(self.filename, 'r')
            lines = f.readlines()
            f.close()
        else:
            lines = buf.split("\n")

        img = None
        title = ""
        for l in lines:
            l = l.strip()
            # skip blank lines
            if len(l) == 0:
                continue
            # skip comments
            if l.startswith('#'):
                continue
            # new image
            if l.startswith("title"):
                if img is not None:
                    self.add_image(GrubImage(title, img))
                img = []
                title = l[6:]
                continue
                
            if img is not None:
                img.append(l)
                continue

            (com, arg) = grub_exact_split(l, 2)
            if self.commands.has_key(com):
                if self.commands[com] is not None:
                    setattr(self, self.commands[com], arg.strip())
                else:
                    logging.info("Ignored directive %s" %(com,))
            else:
                logging.warning("Unknown directive %s" %(com,))
                
        if img:
            self.add_image(GrubImage(title, img))

        if self.hasPassword():
            self.setPasswordAccess(False)

def grub2_handle_set(arg):
    (com,arg) = grub_split(arg,2)
    com="set:" + com
    m = re.match("([\"\'])(.*)\\1", arg)
    if m is not None:
        arg=m.group(2) 
    return (com,arg)

class Grub2Image(_GrubImage):
    def __init__(self, title, lines):
        _GrubImage.__init__(self, title, lines)

    def set_from_line(self, line, replace = None):
        (com, arg) = grub_exact_split(line, 2)

        if com == "set":
            (com,arg) = grub2_handle_set(arg)
            
        if self.commands.has_key(com):
            if self.commands[com] is not None:
                setattr(self, self.commands[com], arg.strip())
            else:
                logging.info("Ignored image directive %s" %(com,))
        elif com.startswith('set:'):
            pass
        else:
            logging.warning("Unknown image directive %s" %(com,))

        # now put the line in the list of lines
        if replace is None:
            self.lines.append(line)
        else:
            self.lines.pop(replace)
            self.lines.insert(replace, line)
                
    commands = {'set:root': 'root',
                'linux': 'kernel',
                'linux16': 'kernel',
                'initrd': 'initrd',
                'initrd16': 'initrd',
                'echo': None,
                'insmod': None,
                'search': None}
    
class Grub2ConfigFile(_GrubConfigFile):
    def __init__(self, fn = None):
        _GrubConfigFile.__init__(self, fn)
       
    def new_image(self, title, lines):
        return Grub2Image(title, lines)
 
    def parse(self, buf = None):
        if buf is None:
            if self.filename is None:
                raise ValueError, "No config file defined to parse!"

            f = open(self.filename, 'r')
            lines = f.readlines()
            f.close()
        else:
            lines = buf.split("\n")

        in_function = False
        img = None
        title = ""
        menu_level=0
        for l in lines:
            l = l.strip()
            # skip blank lines
            if len(l) == 0:
                continue
            # skip comments
            if l.startswith('#'):
                continue

            # skip function declarations
            if l.startswith('function'):
                in_function = True
                continue
            if in_function:
                if l.startswith('}'):
                    in_function = False
                continue

            # new image
            title_match = re.match('^menuentry ["\'](.*?)["\'] (.*){', l)
            if title_match:
                if img is not None:
                    raise RuntimeError, "syntax error: cannot nest menuentry (%d %s)" % (len(img),img)
                img = []
                title = title_match.group(1)
                continue

            if l.startswith("submenu"):
                menu_level += 1
                continue

            if l.startswith("}"):
                if img is None:
                    if menu_level > 0:
                        menu_level -= 1
                        continue
                    else:
                        raise RuntimeError, "syntax error: closing brace without menuentry"

                self.add_image(Grub2Image(title, img))
                img = None
                continue

            if img is not None:
                img.append(l)
                continue

            (com, arg) = grub_exact_split(l, 2)
        
            if com == "set":
                (com,arg) = grub2_handle_set(arg)
                
            if self.commands.has_key(com):
                if self.commands[com] is not None:
                    arg_strip = arg.strip()
                    if arg_strip == "${saved_entry}" or arg_strip == "${next_entry}":
                        logging.warning("grub2's saved_entry/next_entry not supported")
                        arg = "0"
                    setattr(self, self.commands[com], arg_strip)
                else:
                    logging.info("Ignored directive %s" %(com,))
            elif com.startswith('set:'):
                pass
            else:
                logging.warning("Unknown directive %s" %(com,))
            
        if img is not None:
            raise RuntimeError, "syntax error: end of file with open menuentry(%d %s)" % (len(img),img)

        if self.hasPassword():
            self.setPasswordAccess(False)

    commands = {'set:default': 'default',
                'set:root': 'root',
                'set:timeout': 'timeout',
                'terminal': None,
                'insmod': None,
                'load_env': None,
                'save_env': None,
                'search': None,
                'if': None,
                'fi': None,
                }
        
if __name__ == "__main__":
    if len(sys.argv) < 3:
        raise RuntimeError, "Need a grub version (\"grub\" or \"grub2\") and a grub.conf or grub.cfg to read"
    if sys.argv[1] == "grub":
        g = GrubConfigFile(sys.argv[2])
    elif sys.argv[1] == "grub2":
        g = Grub2ConfigFile(sys.argv[2])
    else:
        raise RuntimeError, "Unknown config type %s" % sys.argv[1]
    for i in g.images:
        print i #, i.title, i.root, i.kernel, i.args, i.initrd
