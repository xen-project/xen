Name: libaio
Version: 0.3.106
Release: 1
Summary: Linux-native asynchronous I/O access library
Copyright: LGPL
Group:  System Environment/Libraries
Source: %{name}-%{version}.tar.gz
BuildRoot: %{_tmppath}/%{name}-root
# Fix ExclusiveArch as we implement this functionality on more architectures
ExclusiveArch: i386 x86_64 ia64 s390 s390x ppc ppc64 ppc64pseries ppc64iseries alpha alphaev6

%description
The Linux-native asynchronous I/O facility ("async I/O", or "aio") has a
richer API and capability set than the simple POSIX async I/O facility.
This library, libaio, provides the Linux-native API for async I/O.
The POSIX async I/O facility requires this library in order to provide
kernel-accelerated async I/O capabilities, as do applications which
require the Linux-native async I/O API.

%package devel
Summary: Development files for Linux-native asynchronous I/O access
Group: Development/System
Requires: libaio
Provides: libaio.so.1

%description devel
This package provides header files to include and libraries to link with
for the Linux-native asynchronous I/O facility ("async I/O", or "aio").

%prep
%setup

%build
make

%install
[ "$RPM_BUILD_ROOT" != "/" ] && rm -rf $RPM_BUILD_ROOT

make install prefix=$RPM_BUILD_ROOT/usr \
 libdir=$RPM_BUILD_ROOT/%{_libdir} \
 root=$RPM_BUILD_ROOT

%clean
[ "$RPM_BUILD_ROOT" != "/" ] && rm -rf $RPM_BUILD_ROOT

%post -p /sbin/ldconfig

%postun -p /sbin/ldconfig

%files
%defattr(-,root,root)
%attr(0755,root,root) %{_libdir}/libaio.so.*
%doc COPYING TODO

%files devel
%defattr(-,root,root)
%attr(0644,root,root) %{_includedir}/*
%attr(0755,root,root) %{_libdir}/libaio.so
%attr(0644,root,root) %{_libdir}/libaio.a

%changelog
* Tue Jan  3 2006 Jeff Moyer <jmoyer@redhat.com> - 0.3.106-1
- Add a .proc directive for the ia64_aio_raw_syscall macro.  This sounds a lot
  like the previous entry, but that one fixed the __ia64_raw_syscall macro,
  located in syscall-ia64.h.  This macro is in raw_syscall.c, which pretty much
  only exists for ia64.  This bug prevented the package from building with
  newer version of gcc.

* Mon Aug  1 2005 Jeff Moyer <jmoyer@redhat.com> - 0.3.105-1
- Add a .proc directive for the ia64 raw syscall macro.

* Fri Apr  1 2005 Jeff Moyer <jmoyer@redhat.com> - 0.3.104-1
- Add Alpha architecture support.  (Sergey Tikhonov <tsv@solvo.ru>)

* Tue Jan 25 2005 Jeff Moyer <jmoyer@redhat.com> - 0.3.103-1
- Fix SONAME breakage.  In changing file names around, I also changed the 
  SONAME, which is a no no.

* Thu Oct 14 2004 Jeff Moyer <jmoyer@redhat.com> - 0.3.102-1
- S390 asm had a bug; I forgot to update the clobber list.  Lucky for me,
  newer compilers complain about such things.
- Also update the s390 asm to look more like the new kernel variants.

* Wed Oct 13 2004 Jeff Moyer <jmoyer@redhat.com> - 0.3.101-1
- Revert syscall return values to be -ERRNO.  This was an inadvertant bug
  introduced when clobber lists changed.
- add ppc64pseries and ppc64iseries to exclusivearch

* Tue Sep 14 2004 Jeff Moyer <jmoyer@redhat.com> - 0.3.100-1
- Switch around the tests for _PPC_ and _powerpc64_ so that the ppc64 
  platforms get the right padding.

* Wed Jul 14 2004 Jeff Moyer <jmoyer@redhat.com> - 0.3.99-4
- Ok, there was a race in moving the cvs module.  Someone rebuild from
  the old cvs into fc3.  *sigh*  bumping rev.

* Wed Jul 14 2004 Jeff Moyer <jmoyer@redhat.com> - 0.3.99-3
- Actually provide libaio.so.1.

* Tue Mar 30 2004 Jeff Moyer <jmoyer@redhat.com> - 0.3.99-2
- Apparently the 0.3.93 patch was not meant for 0.3.96.  Backed it out.

* Tue Mar 30 2004 Jeff Moyer <jmoyer@redhat.com> - 0.3.99-1
- Fix compat calls.
- make library .so.1.0.0 and make symlinks properly.
- Fix header file for inclusion in c++ code.

* Thu Feb 26 2004 Jeff Moyer <jmoyer@redhat.com> 0.3.98-2
- bah.  fix version nr in changelog.

* Thu Feb 26 2004 Jeff Moyer <jmoyer@redhat.com> 0.3.98-1
- fix compiler warnings.

* Thu Feb 26 2004 Jeff Moyer <jmoyer@redhat.com> 0.3.97-2
- make srpm was using rpm to do a build.  changed that to use rpmbuild if
  it exists, and fallback to rpm if it doesn't.

* Tue Feb 24 2004 Jeff Moyer <jmoyer@redhat.com> 0.3.97-1
- Use libc syscall(2) instead of rolling our own calling mechanism.  This 
  change is inspired due to a failure to build with newer gcc, since clobber 
  lists were wrong.
- Add -fpic to the CFLAGS for all architectures.  Should address bz #109457.
- change a #include from <linux/types.h> to <sys/types.h>.  Fixes a build
  issue on s390.

* Wed Jul  7 2003 Bill Nottingham <notting@redhat.com> 0.3.96-3
- fix paths on lib64 arches

* Wed Jun 18 2003 Michael K. Johnson <johnsonm@redhat.com> 0.3.96-2
- optimization in io_getevents from Arjan van de Ven in 0.3.96-1
- deal with ia64 in 0.3.96-2

* Wed May 28 2003 Michael K. Johnson <johnsonm@redhat.com> 0.3.95-1
- ppc bugfix from Julie DeWandel

* Tue May 20 2003 Michael K. Johnson <johnsonm@redhat.com> 0.3.94-1
- symbol versioning fix from Ulrich Drepper

* Mon Jan 27 2003 Benjamin LaHaise <bcrl@redhat.com>
- bump to 0.3.93-3 for rebuild.

* Mon Dec 16 2002 Benjamin LaHaise <bcrl@redhat.com>
- libaio 0.3.93 test release
- add powerpc support from Gianni Tedesco <gianni@ecsc.co.uk>
- add s/390 support from Arnd Bergmann <arnd@bergmann-dalldorf.de>

* Fri Sep 12 2002 Benjamin LaHaise <bcrl@redhat.com>
- libaio 0.3.92 test release
- build on x86-64

* Thu Sep 12 2002 Benjamin LaHaise <bcrl@redhat.com>
- libaio 0.3.91 test release
- build on ia64
- remove libredhat-kernel from the .spec file

* Thu Sep  5 2002 Benjamin LaHaise <bcrl@redhat.com>
- libaio 0.3.90 test release

* Mon Apr 29 2002 Benjamin LaHaise <bcrl@redhat.com>
- add requires initscripts >= 6.47-1 to get boot time libredhat-kernel 
  linkage correct.
- typo fix

* Thu Apr 25 2002 Benjamin LaHaise <bcrl@redhat.com>
- make /usr/lib/libredhat-kernel.so point to /lib/libredhat-kernel.so.1.0.0

* Mon Apr 15 2002 Tim Powers <timp@redhat.com>
- make the post scriptlet not use /bin/sh

* Sat Apr 12 2002 Benjamin LaHaise <bcrl@redhat.com>
- add /lib/libredhat-kernel* to %files.

* Fri Apr 12 2002 Benjamin LaHaise <bcrl@redhat.com>
- make the dummy install as /lib/libredhat-kernel.so.1.0.0 so 
  that ldconfig will link against it if no other is installed.

* Tue Jan 22 2002 Benjamin LaHaise <bcrl@redhat.com>
- add io_getevents

* Tue Jan 22 2002 Michael K. Johnson <johnsonm@redhat.com>
- Make linker happy with /usr/lib symlink for libredhat-kernel.so

* Mon Jan 21 2002 Michael K. Johnson <johnsonm@redhat.com>
- Added stub library

* Sun Jan 20 2002 Michael K. Johnson <johnsonm@redhat.com>
- Initial packaging
