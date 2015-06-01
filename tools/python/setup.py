
from distutils.core import setup, Extension
import os, sys

XEN_ROOT = "../.."

extra_compile_args  = [ "-fno-strict-aliasing", "-Werror" ]

PATH_XEN      = XEN_ROOT + "/tools/include"
PATH_LIBXENTOOLLOG = XEN_ROOT + "/tools/libs/toollog"
PATH_LIBXENEVTCHN = XEN_ROOT + "/tools/libs/evtchn"
PATH_LIBXC    = XEN_ROOT + "/tools/libxc"
PATH_LIBXL    = XEN_ROOT + "/tools/libxl"
PATH_XENSTORE = XEN_ROOT + "/tools/xenstore"

xc = Extension("xc",
               extra_compile_args = extra_compile_args,
               include_dirs       = [ PATH_XEN,
                                      PATH_LIBXENTOOLLOG + "/include",
                                      PATH_LIBXENEVTCHN + "/include",
                                      PATH_LIBXC + "/include",
                                      "xen/lowlevel/xc" ],
               library_dirs       = [ PATH_LIBXC ],
               libraries          = [ "xenctrl", "xenguest" ],
               depends            = [ PATH_LIBXC + "/libxenctrl.so", PATH_LIBXC + "/libxenguest.so" ],
               extra_link_args    = [ "-Wl,-rpath-link="+PATH_LIBXENTOOLLOG ],
               sources            = [ "xen/lowlevel/xc/xc.c" ])

xs = Extension("xs",
               extra_compile_args = extra_compile_args,
               include_dirs       = [ PATH_XEN, PATH_XENSTORE + "/include", "xen/lowlevel/xs" ],
               library_dirs       = [ PATH_XENSTORE ],
               libraries          = [ "xenstore" ],
               depends            = [ PATH_XENSTORE + "/libxenstore.so" ],
               sources            = [ "xen/lowlevel/xs/xs.c" ])

plat = os.uname()[0]
modules = [ xc, xs ]

setup(name            = 'xen',
      version         = '3.0',
      description     = 'Xen',
      packages        = ['xen',
                         'xen.migration',
                         'xen.lowlevel',
                        ],
      ext_package = "xen.lowlevel",
      ext_modules = modules
      )
