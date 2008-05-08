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
# Copyright (C) 2006,2007 International Business Machines Corp.
# Author: Stefan Berger <stefanb@us.ibm.com>
#============================================================================

import re
import os, stat
import tempfile
import shutil
import threading

from xen.xend.XendLogging import log
from xen.util import mkdir
import xen.util.xsm.xsm as security

#
# Functions for modifying entries in the bootloader, i.e. adding
# a module to boot the system with a policy.
#

def get_default_title():
    """ See description in Bootloader class below """
    return __bootloader.get_default_title()


def get_boot_policies():
    """ See description in Bootloader class below """
    return __bootloader.get_boot_policies()


def add_boot_policy(index, binpolname):
    """ See description in Bootloader class below """
    return __bootloader.add_boot_policy(index, binpolname)


def rm_policy_from_boottitle(index, unamelist):
    """ See description in Bootloader class below """
    return __bootloader.rm_policy_from_boottitle(index, unamelist)


def set_kernel_attval(index, att, val):
    """ See description in Bootloader class below """
    return __bootloader.set_kernel_attval(index, att, val)


def get_kernel_val(index, att):
    """ See description in Bootloader class below """
    return __bootloader.get_kernel_val(index, att)


def set_boot_policy(title_idx, filename):
    boottitles = get_boot_policies()
    for key in boottitles.iterkeys():
        boottitles[key] += ".bin"
    if boottitles.has_key(title_idx):
        rm_policy_from_boottitle(title_idx, [ boottitles[title_idx] ])
    rc = add_boot_policy(title_idx, filename)
    return rc


def loads_default_policy(filename):
    """ Determine whether the given policy is loaded by the default boot title """
    policy = get_default_policy()
    if policy:
        polfile = policy + ".bin"
        if     polfile == filename or \
           "/"+polfile == filename:
            return True
    return False


def get_default_policy():
    """ Get the name of the policy loaded by the default boot title """
    title = get_default_title()
    policies = get_boot_policies()
    return policies.get(title)


def set_default_boot_policy(filename):
    """ Set the boot policy in the default title to the given name. """
    title = get_default_title()
    return set_boot_policy(title, filename)


def __is_bootdir_mounted():
    """
       Determine whether the boot partition /boot is mounted or not
    """
    rc = False
    file = open("/proc/mounts")
    for line in file:
        tmp = line.split(" ")
        if tmp[1] == "/boot":
            rc = True
            break
    return rc

def get_prefix():
    if __is_bootdir_mounted():
        return "/"
    else:
        return "/boot/"



class Bootloader:
    """ Bootloader class that real bootloader implementations must overwrite """
    def __init__(self):
        pass

    def probe(self):
        """ Test whether this implementation of a bootloader is supported on the
            local system """
        return True

    def get_default_title(self):
        """ Get the index (starting with 0) of the default boot title
            This number is read from the grub configuration file.
            In case of an error '-1' is returned
            @rtype: int
            @return: the index of the default boot title
        """
        return None

    def get_boot_policies(self):
        """ Get a dictionary of policies that the system is booting with.
            @rtype: dict
            @return: dictionary of boot titles where the keys are the
                     indices of the boot titles
        """
        return {}

    def add_boot_policy(self, index, binpolname):
        """ Add the binary policy for automatic loading when
            booting the system. Add it to the boot title at index
            'index'.
        """
        return False

    def rm_policy_from_boottitle(self, index, unamelist):
        """ Remove a policy from the given title. A list of possible policies
            must be given to detect what module to remove
        """
        return False

    def set_kernel_attval(self, index, att, val):
        """
            Append an attribut/value pair to the kernel line.
            @param index : The index of the title to modify
            @param att   : The attribute to add
            @param val   : The value to add. If no value or the special value
                           '<>' is given, then the attribute will be removed.
                           If an empty value is given, then only the attribute
                           is added in the format "att", otherwise "att=val"
                           is added.
        """
        return False

    def get_kernel_val(self, index, att):
        """
            Get an attribute's value from the kernel line.
            @param index : The index of the title to get the attribute/value from
            @param att   : The attribute to read the value of
        """
        return None


class Grub(Bootloader):
    """ Implementation for manipulating bootloader entries in grub according
        to the 'Bootloader' class interface """

    def __init__(self):
        self.__bootfile_lock = threading.RLock()
        self.title_re = re.compile("\s*title\s", re.IGNORECASE)
        self.module_re = re.compile("\s+module\s", re.IGNORECASE)
        self.policy_re = re.compile(".*\.bin", re.IGNORECASE)
        self.kernel_re = re.compile("\s*kernel\s", re.IGNORECASE)
        Bootloader.__init__(self)

    def probe(self):
        try:
            boot_file = self.__get_bootfile()
        except:
            return False
        return True


    def __get_bootfile(self):
        """ Get the name of the bootfile """
        boot_file = "/boot/grub/grub.conf"
        alt_boot_file = "/boot/grub/menu.lst"

        if not os.path.isfile(boot_file):
            #take alternate boot file instead
            boot_file = alt_boot_file

        #follow symlink since menue.lst might be linked to grub.conf
        if not os.path.exists(boot_file):
            raise IOError("Boot file \'%s\' not found." % boot_file)

        if stat.S_ISLNK(os.lstat(boot_file)[stat.ST_MODE]):
            new_name = os.readlink(boot_file)
            if new_name[0] == "/":
                boot_file = new_name
            else:
                path = boot_file.split('/')
                path[len(path)-1] = new_name
                boot_file = '/'.join(path)
        if not os.path.exists(boot_file):
            raise IOError("Boot file \'%s\' not found." % boot_file)
        return boot_file


    def get_default_title(self):
        """ Get the index (starting with 0) of the default boot title
            This number is read from the grub configuration file.
            In case of an error '-1' is returned
            @rtype: int
            @return: the index of the default boot title
        """
        def_re = re.compile("default", re.IGNORECASE)
        default = None
        try:
            boot_file = self.__get_bootfile()
        except:
            return default
        try:
            self.__bootfile_lock.acquire()
            grub_fd = open(boot_file)
            for line in grub_fd:
                line = line.rstrip()
                if def_re.match(line):
                    #remove 'default='
                    line = line.lstrip()[8:]
                    default = int(line)
                    break
        finally:
            self.__bootfile_lock.release()
        return default


    def get_boot_policies(self):
        """ Get a dictionary of policies that the system is booting with.
            @rtype: dict
            @return: dictionary of boot titles where the keys are the
                     indices of the boot titles
        """
        policies = {}
        within_title = 0
        idx = -1
        try:
            boot_file = self.__get_bootfile()
        except:
            return policies
        try:
            self.__bootfile_lock.acquire()

            grub_fd = open(boot_file)
            for line in grub_fd:
                if self.title_re.match(line):
                    within_title = 1
                    idx = idx + 1
                if within_title and self.module_re.match(line):
                    if self.policy_re.match(line):
                        start = line.find("module")
                        pol = line[start+6:]
                        pol = pol.strip()
                        if pol[0] == '/':
                            pol = pol[1:]
                        if pol[0:5] == "boot/":
                            pol = pol[5:]
                        if pol.endswith(".bin"):
                            pol = pol[:-4]
                        policies[idx] = pol
        finally:
            self.__bootfile_lock.release()
        return policies


    def add_boot_policy(self, index, binpolname):
        """ Add the binary policy for automatic loading when
            booting the system. Add it to the boot title at index
            'index'.
        """
        ctr = 0
        module_line = ""
        within_title = 0
        found = False
        try:
            boot_file = self.__get_bootfile()
        except:
            return False
        try:
            self.__bootfile_lock.acquire()
            grub_fd = open(boot_file)
            (tmp_fd, tmp_grub) = tempfile.mkstemp()
            for line in grub_fd:
                if self.title_re.match(line):
                    if module_line != "" and not found:
                        os.write(tmp_fd, module_line)
                        found = True

                    if ctr == index:
                        within_title = 1
                    else:
                        within_title = 0
                    ctr = ctr + 1
                elif within_title and self.module_re.match(line):
                    start = line.find("module")
                    l = line[start+6:len(line)]
                    l = l.lstrip()
                    if l[0] == '/':
                        prefix = "/"
                    else:
                        prefix = ""
                    prefix = get_prefix()
                    module_line = "\tmodule %s%s\n" % (prefix,binpolname)
                else:
                    if module_line != "" and not found:
                        os.write(tmp_fd, module_line)
                        found = True

                os.write(tmp_fd, line)

            if module_line != "" and not found:
                if ord(line[-1]) not in [ 10 ]:
                    os.write(tmp_fd, '\n')
                os.write(tmp_fd, module_line)
                found = True

            shutil.move(boot_file, boot_file+"_save")
            shutil.copyfile(tmp_grub, boot_file)
            os.close(tmp_fd)
            try:
                os.remove(tmp_grub)
            except:
                pass
        finally:
            self.__bootfile_lock.release()
        return found


    def rm_policy_from_boottitle(self, index, unamelist):
        """ Remove a policy from the given title. A list of possible policies
            must be given to detect what module to remove
        """
        found = False
        ctr = 0
        within_title = 0

        prefix = get_prefix()
        namelist = [prefix+name for name in unamelist]

        try:
            boot_file = self.__get_bootfile()
        except:
            return False
        try:
            self.__bootfile_lock.acquire()

            grub_fd = open(boot_file)
            (tmp_fd, tmp_grub) = tempfile.mkstemp()
            for line in grub_fd:
                omit_line = False
                if self.title_re.match(line):
                    if ctr == index:
                        within_title = 1
                    else:
                        within_title = 0
                    ctr = ctr + 1
                if within_title and self.module_re.match(line):
                    if self.policy_re.match(line):
                        start = line.find("module")
                        pol = line[start+6:len(line)]
                        pol = pol.strip()
                        if pol in namelist:
                            omit_line = True
                            found = True
                if not omit_line:
                    os.write(tmp_fd, line)
            if found:
                shutil.move(boot_file, boot_file+"_save")
                shutil.copyfile(tmp_grub, boot_file)
            os.close(tmp_fd)
            try:
                os.remove(tmp_grub)
            except:
                pass
        finally:
            self.__bootfile_lock.release()
        return found


    def set_kernel_attval(self, index, att, val):
        """
            Append an attribut/value pair to the kernel line.
            @param index : The index of the title to modify
            @param att   : The attribute to add
            @param val   : The value to add. If no value or the special value
                           '<>' is given, then the attribute will be removed.
                           If an empty value is given, then only the attribute
                           is added in the format "att", otherwise "att=val"
                           is added.
        """
        found = False
        ctr = 0
        within_title = 0
        try:
            boot_file = self.__get_bootfile()
        except:
            False
        try:
            self.__bootfile_lock.acquire()

            grub_fd = open(boot_file)
            (tmp_fd, tmp_grub) = tempfile.mkstemp()
            for line in grub_fd:
                if self.title_re.match(line):
                    if ctr == index:
                        within_title = 1
                    else:
                        within_title = 0
                    ctr = ctr + 1
                if within_title and self.kernel_re.match(line):
                    nitems = []
                    items = line.split(" ")
                    i = 0
                    while i < len(items):
                        el = items[i].split("=",1)
                        if el[0] != att:
                            nitems.append(items[i].rstrip("\n"))
                        i += 1
                    if val == "":
                        nitems.append("%s" % (att))
                    elif val != None and val != "<>":
                        nitems.append("%s=%s" % (att,val))
                    line = " ".join(nitems) + "\n"
                os.write(tmp_fd, line)
            shutil.move(boot_file, boot_file+"_save")
            shutil.copyfile(tmp_grub, boot_file)
            os.close(tmp_fd)
            try:
                os.remove(tmp_grub)
            except:
                pass
        finally:
            self.__bootfile_lock.release()
        return found


    def get_kernel_val(self, index, att):
        """
            Get an attribute's value from the kernel line.
            @param index : The index of the title to get the attribute/value from
            @param att   : The attribute to read the value of
        """
        ctr = 0
        within_title = 0
        try:
            boot_file = self.__get_bootfile()
        except:
            return None
        try:
            self.__bootfile_lock.acquire()

            grub_fd = open(boot_file)
            for line in grub_fd:
                if self.title_re.match(line):
                    if ctr == index:
                        within_title = 1
                    else:
                        within_title = 0
                    ctr = ctr + 1
                if within_title and self.kernel_re.match(line):
                    line = line.strip()
                    items = line.split(" ")
                    i = 0
                    while i < len(items):
                        el = items[i].split("=",1)
                        if el[0] == att:
                            if len(el) == 1:
                                return "<>"
                            return el[1]
                        i += 1
        finally:
            self.__bootfile_lock.release()
        return None # Not found

class LatePolicyLoader(Bootloader):
    """ A fake bootloader file that holds the policy to load automatically
        once xend has started up and the Domain-0 label to set. """
    def __init__(self):
        self.__bootfile_lock = threading.RLock()
        self.PATH = security.security_dir_prefix
        self.FILENAME = self.PATH + "/xen_boot_policy"
        self.DEFAULT_TITLE = "ANY"
        self.POLICY_ATTR = "POLICY"
        Bootloader.__init__(self)

    def probe(self):
        try:
            _dir=os.path.dirname(self.FILENAME)
            mkdir.parents(_dir, stat.S_IRWXU)
        except:
            return False
        return True

    def get_default_title(self):
        return self.DEFAULT_TITLE

    def get_boot_policies(self):
        policies = {}
        try:
            self.__bootfile_lock.acquire()

            res = self.__loadcontent()

            pol = res.get( self.POLICY_ATTR )
            if pol:
                policies.update({ self.DEFAULT_TITLE : pol })

        finally:
            self.__bootfile_lock.release()

        return policies

    def add_boot_policy(self, index, binpolname):
        try:
            self.__bootfile_lock.acquire()

            res = self.__loadcontent()
            if binpolname.endswith(".bin"):
                binpolname = binpolname[0:-4]
            res[ self.POLICY_ATTR ] = binpolname
            self.__writecontent(res)
        finally:
            self.__bootfile_lock.release()

        return True

    def rm_policy_from_boottitle(self, index, unamelist):
        try:
            self.__bootfile_lock.acquire()

            res = self.__loadcontent()
            if self.POLICY_ATTR in res:
                del(res[self.POLICY_ATTR])
            self.__writecontent(res)
        finally:
            self.__bootfile_lock.release()

        return True

    def set_kernel_attval(self, index, att, val):
        try:
            self.__bootfile_lock.acquire()

            res = self.__loadcontent()
            res[att] = val
            self.__writecontent(res)
        finally:
            self.__bootfile_lock.release()

        return True

    def get_kernel_val(self, index, att):
        try:
            self.__bootfile_lock.acquire()

            res = self.__loadcontent()
            return res.get(att)
        finally:
            self.__bootfile_lock.release()

    def __loadcontent(self):
        res={}
        try:
            file = open(self.FILENAME)
            for line in file:
                tmp = line.split("=",1)
                if len(tmp) == 2:
                   res[tmp[0]] = tmp[1].strip()
            file.close()
        except:
            pass

        return res

    def __writecontent(self, items):
        rc = True
        try:
            file = open(self.FILENAME,"w")
            if file:
                for key, value in items.items():
                    file.write("%s=%s\n" % (str(key),str(value)))
                file.close()
        except:
            rc = False

        return rc


__bootloader = Bootloader()

def init():
    global __bootloader
    grub = Grub()
    if grub.probe() == True:
        __bootloader = grub
    else:
        late = LatePolicyLoader()
        if late.probe() == True:
            __bootloader = late
