Summary: Xen command line tools
Name: xen-internal-tools
Version: 1.0
Release: 1
License: Xen
Group: Xen
BuildRoot: %{staging}
%description
Command line tools for building and managing domains on a system
running the Xen hypervisor.

%pre
%preun
%install
install -m 0755 -d $RPM_BUILD_ROOT/bin
install -m 0755 xi_build $RPM_BUILD_ROOT/bin/xi_build
install -m 0755 xi_create $RPM_BUILD_ROOT/bin/xi_create
install -m 0755 xi_destroy $RPM_BUILD_ROOT/bin/xi_destroy
install -m 0755 xi_helper $RPM_BUILD_ROOT/bin/xi_helper
install -m 0755 xi_list $RPM_BUILD_ROOT/bin/xi_list
install -m 0755 xi_start $RPM_BUILD_ROOT/bin/xi_start
install -m 0755 xi_stop $RPM_BUILD_ROOT/bin/xi_stop
install -m 0755 xi_vifinit $RPM_BUILD_ROOT/bin/xi_vifinit
%clean
%post
%postun
%files
%defattr(-,root,root)
%dir /bin
/bin/xi_build
/bin/xi_create
/bin/xi_destroy
/bin/xi_helper
/bin/xi_list
/bin/xi_start
/bin/xi_stop
/bin/xi_vifinit
