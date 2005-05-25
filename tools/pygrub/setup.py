from distutils.core import setup, Extension
import os

extra_compile_args  = [ "-fno-strict-aliasing", "-Wall", "-Werror" ]

fsys_mods = []
fsys_pkgs = []

if os.path.exists("/usr/include/ext2fs/ext2_fs.h"):
    ext2 = Extension("grub.fsys.ext2._pyext2",
                     extra_compile_args = extra_compile_args,
                     libraries = ["ext2fs"],
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

setup(name='pygrub',
      version='0.2',
      description='Boot loader that looks a lot like grub for Xen',
      author='Jeremy Katz',
      author_email='katzj@redhat.com',
      license='GPL',
      package_dir={'grub': 'src'},
      scripts = ["src/pygrub"],
      packages=['grub',
                'grub.fsys'].extend(fsys_pkgs),
      ext_modules = fsys_mods
      )
               
