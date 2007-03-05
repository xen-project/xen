
from distutils.core import setup, Extension
import os

XEN_ROOT = "../.."

extra_compile_args  = [ "-fno-strict-aliasing", "-Werror" ]

include_dirs = [ XEN_ROOT + "/tools/libxc",
                 XEN_ROOT + "/tools/xenstore",
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
             
acm = Extension("acm",
               extra_compile_args = extra_compile_args,
               include_dirs       = include_dirs + [ "xen/lowlevel/acm" ],
               library_dirs       = library_dirs,
               libraries          = libraries,
               sources            = [ "xen/lowlevel/acm/acm.c" ])

ptsname = Extension("ptsname",
               extra_compile_args = extra_compile_args,
               include_dirs       = include_dirs + [ "ptsname" ],
               library_dirs       = library_dirs,
               libraries          = libraries,
               sources            = [ "ptsname/ptsname.c" ])

modules = [ xc, xs, acm, ptsname ]
if os.uname()[0] == 'SunOS':
    modules.append(scf)

setup(name            = 'xen',
      version         = '3.0',
      description     = 'Xen',
      packages        = ['xen',
                         'xen.lowlevel',
                         'xen.util',
                         'xen.xend',
                         'xen.xend.server',
                         'xen.xend.xenstore',
                         'xen.xm',
                         'xen.web',
                         'xen.sv',

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
