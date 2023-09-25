# Prefer setuptools, fall back to distutils
try:
    from setuptools import setup, Extension
except ImportError:
    from distutils.core import setup, Extension
import os
import sys

extra_compile_args  = [ "-fno-strict-aliasing" ]

XEN_ROOT = "../.."

xenfsimage = Extension("xenfsimage",
    extra_compile_args = extra_compile_args,
    include_dirs = [ XEN_ROOT + "/tools/libfsimage/common/" ],
    library_dirs = [ XEN_ROOT + "/tools/libfsimage/common/" ],
    libraries = ["xenfsimage"],
    sources = ["src/fsimage/fsimage.c"])

pkgs = [ 'grub' ]

setup(name='pygrub',
      version='0.7',
      description='Boot loader that looks a lot like grub for Xen',
      author='Jeremy Katz',
      author_email='katzj@redhat.com',
      license='GPL',
      package_dir={'grub': 'src', 'fsimage': 'src'},
      packages=pkgs,
      ext_modules = [ xenfsimage ]
      )
