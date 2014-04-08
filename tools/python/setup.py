
from distutils.core import setup, Extension
import os, sys

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

xl = Extension("xl",
               extra_compile_args = extra_compile_args,
               include_dirs       = [ PATH_XEN, PATH_LIBXL, PATH_LIBXC, "xen/lowlevel/xl" ],
               library_dirs       = [ PATH_LIBXL ],
               libraries          = [ "xenlight" ],
               depends            = [ PATH_LIBXL + "/libxenlight.so" ],
               sources            = [ "xen/lowlevel/xl/xl.c", "xen/lowlevel/xl/_pyxl_types.c" ])

plat = os.uname()[0]
modules = [ xc, xs ]
#modules.extend([ xl ])

setup(name            = 'xen',
      version         = '3.0',
      description     = 'Xen',
      packages        = ['xen',
                         'xen.lowlevel',
                        ],
      ext_package = "xen.lowlevel",
      ext_modules = modules
      )
