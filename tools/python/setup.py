
from distutils.core import setup, Extension
import os

XEN_ROOT = "../.."

extra_compile_args  = [ "-fno-strict-aliasing", "-Werror" ]

PATH_XEN      = XEN_ROOT + "/tools/include"
PATH_LIBXC    = XEN_ROOT + "/tools/libxc"
PATH_LIBXL    = XEN_ROOT + "/tools/libxl"
PATH_XENSTORE = XEN_ROOT + "/tools/xenstore"

xc = Extension("xc",
               extra_compile_args = extra_compile_args,
               include_dirs       = [ PATH_XEN, PATH_LIBXC, "xen/lowlevel/xc" ],
               library_dirs       = [ PATH_LIBXC ],
               libraries          = [ "xenctrl", "xenguest" ],
               depends            = [ PATH_LIBXC + "/libxenctrl.so", PATH_LIBXC + "/libxenguest.so" ],
               sources            = [ "xen/lowlevel/xc/xc.c" ])

xs = Extension("xs",
               extra_compile_args = extra_compile_args,
               include_dirs       = [ PATH_XEN, PATH_XENSTORE, "xen/lowlevel/xs" ],
               library_dirs       = [ PATH_XENSTORE ],
               libraries          = [ "xenstore" ],
               depends            = [ PATH_XENSTORE + "/libxenstore.so" ],
               sources            = [ "xen/lowlevel/xs/xs.c" ])

scf = Extension("scf",
               extra_compile_args = extra_compile_args,
               include_dirs       = [ "xen/lowlevel/scf" ],
               library_dirs       = [ ],
               libraries          = [ ],
               depends            = [ ],
               sources            = [ "xen/lowlevel/scf/scf.c" ])

process = Extension("process",
               extra_compile_args = extra_compile_args,
               include_dirs       = [ "xen/lowlevel/process" ],
               library_dirs       = [ ],
               libraries          = [ "contract" ],
               depends            = [ ],
               sources            = [ "xen/lowlevel/process/process.c" ])

flask = Extension("flask",
               extra_compile_args = extra_compile_args,
               include_dirs       = [ PATH_XEN, PATH_LIBXC, "xen/lowlevel/flask" ],
               library_dirs       = [ PATH_LIBXC ],
               libraries          = [ "xenctrl" ],
               depends            = [ PATH_LIBXC + "/libxenctrl.so" ],
               sources            = [ "xen/lowlevel/flask/flask.c" ])

ptsname = Extension("ptsname",
               extra_compile_args = extra_compile_args,
               include_dirs       = [ "ptsname" ],
               library_dirs       = [ ],
               libraries          = [ ],
               depends            = [ ],
               sources            = [ "ptsname/ptsname.c" ])

checkpoint = Extension("checkpoint",
               extra_compile_args = extra_compile_args,
               include_dirs       = [ PATH_XEN, PATH_LIBXC, PATH_XENSTORE ],
               library_dirs       = [ PATH_LIBXC, PATH_XENSTORE ],
               libraries          = [ "xenctrl", "xenguest", "xenstore", "rt" ],
               depends            = [ PATH_LIBXC + "/libxenctrl.so",
                                      PATH_LIBXC + "/libxenguest.so",
                                      PATH_XENSTORE + "/libxenstore.so" ],
               sources            = [ "xen/lowlevel/checkpoint/checkpoint.c",
                                      "xen/lowlevel/checkpoint/libcheckpoint.c"])

netlink = Extension("netlink",
               extra_compile_args = extra_compile_args,
               include_dirs       = [ ],
               library_dirs       = [ ],
               libraries          = [ ],
               depends            = [ ],
               sources            = [ "xen/lowlevel/netlink/netlink.c",
                                      "xen/lowlevel/netlink/libnetlink.c"])

xl = Extension("xl",
               extra_compile_args = extra_compile_args,
               include_dirs       = [ PATH_XEN, PATH_LIBXL, PATH_LIBXC, "xen/lowlevel/xl" ],
               library_dirs       = [ PATH_LIBXL ],
               libraries          = [ "xenlight" ],
               depends            = [ PATH_LIBXL + "/libxenlight.so" ],
               sources            = [ "xen/lowlevel/xl/xl.c", "xen/lowlevel/xl/_pyxl_types.c" ])

plat = os.uname()[0]
modules = [ xc, xs, ptsname, flask ]
#modules.extend([ xl ])
if plat == 'SunOS':
    modules.extend([ scf, process ])
if plat == 'Linux':
    modules.extend([ checkpoint, netlink ])

setup(name            = 'xen',
      version         = '3.0',
      description     = 'Xen',
      packages        = ['xen',
                         'xen.lowlevel',
                         'xen.util',
                         'xen.util.xsm',
                         'xen.util.xsm.dummy',
                         'xen.util.xsm.flask',
                         'xen.util.xsm.acm',
                         'xen.xend',
                         'xen.xend.server',
                         'xen.xend.xenstore',
                         'xen.xm',
                         'xen.web',
                         'xen.sv',
                         'xen.xsview',
                         'xen.remus',
                         'xen.xend.tests',
                         'xen.xend.server.tests',
                         'xen.xend.xenstore.tests',
                         'xen.xm.tests'
                         ],
      ext_package = "xen.lowlevel",
      ext_modules = modules
      )

os.chdir('logging')
execfile('setup.py')
