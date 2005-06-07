
from distutils.core import setup, Extension
import os

XEN_ROOT = "../.."

extra_compile_args  = [ "-fno-strict-aliasing", "-Wall", "-Werror" ]


include_dirs = [ XEN_ROOT + "/tools/python/xen/lowlevel/xu",
                 XEN_ROOT + "/tools/libxc",
                 XEN_ROOT + "/tools/xenstore",
                 XEN_ROOT + "/tools/xcs",
                 ]

library_dirs = [ XEN_ROOT + "/tools/libxc",
                 XEN_ROOT + "/tools/xenstore",
                 ]

libraries = [ "xc", "xenstore" ]

xc = Extension("xc",
               extra_compile_args = extra_compile_args,
               include_dirs       = include_dirs + [ "xen/lowlevel/xc" ],
               library_dirs       = library_dirs,
               libraries          = libraries,
               sources            = [ "xen/lowlevel/xc/xc.c" ])

xu = Extension("xu",
               extra_compile_args = extra_compile_args,
               include_dirs       = include_dirs + [ "xen/lowlevel/xu" ],
               library_dirs       = library_dirs,
               libraries          = libraries,
               sources            = [ "xen/lowlevel/xu/xu.c" ])

xs = Extension("xs",
               extra_compile_args = extra_compile_args,
               include_dirs       = include_dirs + [ "xen/lowlevel/xs" ],
               library_dirs       = library_dirs,
               libraries          = libraries,
               sources            = [ "xen/lowlevel/xs/xs.c" ])

setup(name            = 'xen',
      version         = '2.0',
      description     = 'Xen',
      packages        = ['xen',
                         'xen.lowlevel',
                         'xen.util',
                         'xen.xend',
                         'xen.xend.server',
                         'xen.xend.xenstore',
                         'xen.xm',
                         'xen.web',
                         ],
      ext_package = "xen.lowlevel",
      ext_modules = [ xc, xu, xs ]
      )

os.chdir('logging')
execfile('setup.py')
