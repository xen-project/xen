from distutils.core import setup, Extension
from distutils.ccompiler import new_compiler
import os
import sys

extra_compile_args  = [ "-fno-strict-aliasing", "-Wall", "-Werror" ]

fsys_mods = []
fsys_pkgs = []

if os.path.exists("/usr/include/ext2fs/ext2_fs.h"):
    ext2defines = []
    cc = new_compiler()
    cc.add_library("ext2fs")
    if hasattr(cc, "has_function") and cc.has_function("ext2fs_open2"):
        ext2defines.append( ("HAVE_EXT2FS_OPEN2", None) )
    else:
        sys.stderr.write("WARNING: older version of e2fsprogs installed, not building full\n")
        sys.stderr.write("         disk support for ext2.\n")
        
    ext2 = Extension("grub.fsys.ext2._pyext2",
                     extra_compile_args = extra_compile_args,
                     libraries = ["ext2fs"],
                     define_macros = ext2defines,
                     sources = ["src/fsys/ext2/ext2module.c"])
    fsys_mods.append(ext2)
    fsys_pkgs.append("grub.fsys.ext2")

if os.path.exists("/usr/include/reiserfs/reiserfs.h"):
    reiser = Extension("grub.fsys.reiser._pyreiser",
                     extra_compile_args = extra_compile_args,
                     libraries = ["reiserfs"],
                     sources = ["src/fsys/reiser/reisermodule.c"])
    fsys_mods.append(reiser)
    fsys_pkgs.append("grub.fsys.reiser")

pkgs = ['grub', 'grub.fsys']
pkgs.extend(fsys_pkgs)
setup(name='pygrub',
      version='0.3',
      description='Boot loader that looks a lot like grub for Xen',
      author='Jeremy Katz',
      author_email='katzj@redhat.com',
      license='GPL',
      package_dir={'grub': 'src'},
      scripts = ["src/pygrub"],
      packages=pkgs,
      ext_modules = fsys_mods
      )
               
