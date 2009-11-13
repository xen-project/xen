
from distutils.core import setup, Extension
import os

XEN_ROOT = "../.."

extra_compile_args  = [ "-fno-strict-aliasing", "-Werror" ]

include_dirs = [ XEN_ROOT + "/tools/libxc",
                 XEN_ROOT + "/tools/xenstore",
                 XEN_ROOT + "/tools/include",
                 ]

library_dirs = [ XEN_ROOT + "/tools/libxc",
                 XEN_ROOT + "/tools/xenstore",
                 ]

libraries = [ "xenctrl", "xenguest", "xenstore" ]

xc = Extension("xc",
               extra_compile_args = extra_compile_args,
               include_dirs       = include_dirs + [ "xen/lowlevel/xc" ],
               library_dirs       = library_dirs,
               libraries          = libraries,
               sources            = [ "xen/lowlevel/xc/xc.c" ])

xs = Extension("xs",
               extra_compile_args = extra_compile_args,
               include_dirs       = include_dirs + [ "xen/lowlevel/xs" ],
               library_dirs       = library_dirs,
               libraries          = libraries,
               sources            = [ "xen/lowlevel/xs/xs.c" ])

scf = Extension("scf",
               extra_compile_args = extra_compile_args,
               include_dirs       = include_dirs + [ "xen/lowlevel/scf" ],
               library_dirs       = library_dirs,
               libraries          = libraries,
               sources            = [ "xen/lowlevel/scf/scf.c" ])
             
process = Extension("process",
               extra_compile_args = extra_compile_args,
               include_dirs       = include_dirs + [ "xen/lowlevel/process" ],
               library_dirs       = library_dirs,
               libraries          = libraries + [ "contract" ],
               sources            = [ "xen/lowlevel/process/process.c" ])

acm = Extension("acm",
               extra_compile_args = extra_compile_args,
               include_dirs       = include_dirs + [ "xen/lowlevel/acm" ],
               library_dirs       = library_dirs,
               libraries          = libraries,
               sources            = [ "xen/lowlevel/acm/acm.c" ])

flask = Extension("flask",
               extra_compile_args = extra_compile_args,
               include_dirs       = include_dirs + [ "xen/lowlevel/flask" ] + 
                                        [ "../flask/libflask/include" ],
               library_dirs       = library_dirs + [ "../flask/libflask" ],
               libraries          = libraries + [ "flask" ],
               sources            = [ "xen/lowlevel/flask/flask.c" ])

ptsname = Extension("ptsname",
               extra_compile_args = extra_compile_args,
               include_dirs       = include_dirs + [ "ptsname" ],
               library_dirs       = library_dirs,
               libraries          = libraries,
               sources            = [ "ptsname/ptsname.c" ])

checkpoint = Extension("checkpoint",
                       extra_compile_args = extra_compile_args,
                       include_dirs       = include_dirs,
                       library_dirs       = library_dirs,
                       libraries          = libraries + [ "rt" ],
                       sources            = [ "xen/lowlevel/checkpoint/checkpoint.c",
                                              "xen/lowlevel/checkpoint/libcheckpoint.c"])

netlink = Extension("netlink",
                    extra_compile_args = extra_compile_args,
                    include_dirs       = include_dirs,
                    library_dirs       = library_dirs,
                    libraries          = libraries,
                    sources            = [ "xen/lowlevel/netlink/netlink.c",
                                           "xen/lowlevel/netlink/libnetlink.c"])

modules = [ xc, xs, ptsname, acm, flask ]
plat = os.uname()[0]
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
