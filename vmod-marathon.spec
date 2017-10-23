Summary: Marathon backend support for Varnish
Name: vmod-marathon
Version: 0.1.1
Release: 1%{?dist}
License: BSD
Group: System Environment/Daemons
Source0: libvmod-marathon.tar.gz
BuildRoot: %{_tmppath}/%{name}-%{version}-%{release}-root-%(%{__id_u} -n)
Requires: varnish >= 5.2.0
BuildRequires: make
BuildRequires: libcurl-devel
BuildRequires: yajl-devel
BuildRequires: varnish >= 5.2.0
BuildRequires: varnish-devel >= 5.2.0

%description
Marathon backend support for Varnish

%prep
%setup -n libvmod-marathon

%build
./autogen.sh
./configure --prefix=/usr/ --libdir=%{_libdir}
make

%install
make install DESTDIR=%{buildroot}
cp LICENSE %{buildroot}/usr/share/doc/%{name}/

%clean
rm -rf %{buildroot}

%files
%defattr(-,root,root,-)
%{_libdir}/varnish/vmods/
%doc /usr/share/doc/%{name}/*
%{_mandir}/man?/*

%changelog
* Mon Oct 23 2017 Ole Fredrik Skudsvik <ole.skudsvik@gmail.com>
- 0.1.1 Added backend_by_label support and improved backend logic.

* Thu Aug 31 2017 Ole Fredrik Skudsvik <ole.skudsvik@gmail.com>
- Initial version.
