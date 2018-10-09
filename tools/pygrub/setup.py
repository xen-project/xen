from distutils.core import setup, Extension
from distutils.ccompiler import new_compiler
import os
import sys

extra_compile_args  = [ "-fno-strict-aliasing", "-Werror" ]

XEN_ROOT = "../.."

xenfsimage = Extension("xenfsimage",
    extra_compile_args = extra_compile_args,
    include_dirs = [ XEN_ROOT + "/tools/libfsimage/common/" ],
    library_dirs = [ XEN_ROOT + "/tools/libfsimage/common/" ],
    libraries = ["xenfsimage"],
    sources = ["src/fsimage/fsimage.c"])

pkgs = [ 'grub' ]

setup(name='pygrub',
      version='0.6',
      description='Boot loader that looks a lot like grub for Xen',
      author='Jeremy Katz',
      author_email='katzj@redhat.com',
      license='GPL',
      package_dir={'grub': 'src', 'fsimage': 'src'},
      scripts = ["src/pygrub"],
      packages=pkgs,
      ext_modules = [ xenfsimage ]
      )
