Summary: Xen control interface library
Name: xen-internal-library
Version: 1.2
Release: 1
License: Xen
Group: Xen
BuildRoot: %{staging}
%description
Library to make it easier to access the Xen control interfaces.

%pre
%preun
%install
install -m 0755 -d $RPM_BUILD_ROOT/lib
install -m 0755 libxi.a $RPM_BUILD_ROOT/lib/libxi.a
install -m 0755 libxi.so $RPM_BUILD_ROOT/lib/libxi.so
install -m 0755 -d $RPM_BUILD_ROOT/include
install -m 0644 xi.h $RPM_BUILD_ROOT/include/xi.h
%clean
%post
%postun
%files
%defattr(-,root,root)
%dir /lib
/lib/libxi.a
/lib/libxi.so
%dir /include
/include/xi.h
