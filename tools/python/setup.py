
from distutils.core import setup, Extension
import os

XEN_ROOT = "../.."

extra_compile_args  = [ "-fno-strict-aliasing", "-Wall", "-Werror" ]


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
                         'xen.xm.tests'
                         ],
      ext_package = "xen.lowlevel",
      ext_modules = [ xc, xs ]
      )

os.chdir('logging')
execfile('setup.py')
