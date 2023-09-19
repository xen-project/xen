# Prefer setuptools, fall back to distutils
try:
    from setuptools import setup, Extension
except ImportError:
    from distutils.core import setup, Extension
import os, sys

XEN_ROOT = "../.."

SHLIB_libxenctrl = os.environ['SHLIB_libxenctrl'].split()
SHLIB_libxenguest = os.environ['SHLIB_libxenguest'].split()
SHLIB_libxenstore = os.environ['SHLIB_libxenstore'].split()

extra_compile_args  = [ "-fno-strict-aliasing" ]

PATH_XEN      = XEN_ROOT + "/tools/include"
PATH_LIBXENTOOLLOG = XEN_ROOT + "/tools/libs/toollog"
PATH_LIBXENEVTCHN = XEN_ROOT + "/tools/libs/evtchn"
PATH_LIBXENCTRL = XEN_ROOT + "/tools/libs/ctrl"
PATH_LIBXENGUEST = XEN_ROOT + "/tools/libs/guest"
PATH_XENSTORE = XEN_ROOT + "/tools/libs/store"

xc = Extension("xc",
               extra_compile_args = extra_compile_args,
               include_dirs       = [ PATH_XEN,
                                      PATH_LIBXENTOOLLOG + "/include",
                                      PATH_LIBXENEVTCHN + "/include",
                                      PATH_LIBXENCTRL + "/include",
                                      PATH_LIBXENGUEST + "/include",
                                      "xen/lowlevel/xc" ],
               library_dirs       = [ PATH_LIBXENCTRL, PATH_LIBXENGUEST ],
               libraries          = [ "xenctrl", "xenguest" ],
               depends            = [ PATH_LIBXENCTRL + "/libxenctrl.so", PATH_LIBXENGUEST + "/libxenguest.so" ],
               extra_link_args    = SHLIB_libxenctrl + SHLIB_libxenguest,
               sources            = [ "xen/lowlevel/xc/xc.c" ])

xs = Extension("xs",
               extra_compile_args = extra_compile_args,
               include_dirs       = [ PATH_XEN, PATH_XENSTORE + "/include", "xen/lowlevel/xs" ],
               library_dirs       = [ PATH_XENSTORE ],
               libraries          = [ "xenstore" ],
               depends            = [ PATH_XENSTORE + "/libxenstore.so" ],
               extra_link_args    = SHLIB_libxenstore,
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
