Summary: marathon support for Varnish VCL
Name: vmod-marathon
Version: 0.1.0
Release: 1%{?dist}
License: BSD
Group: System Environment/Daemons
Source0: libvmod-marathon.tar.gz
BuildRoot: %{_tmppath}/%{name}-%{version}-%{release}-root-%(%{__id_u} -n)
Requires: varnish >= 4.1.4
BuildRequires: make
BuildRequires: libcurl-devel
BuildRequires: yajl-devel
BuildRequires: varnish >= 5.1.0
BuildRequires: varnish-devel >= 5.1.0

%description
marathon support for Varnish VCL

%prep
%setup -n libvmod-marathon

%build
./autogen.sh
./configure --prefix=/usr --libdir=%{_libdir}
make

%install
make install DESTDIR=%{buildroot}
cp LICENSE %{buildroot}/usr/share/doc/%{name}/

%clean
rm -rf %{buildroot}

%files
%defattr(-,root,root,-)
%{_libdir}/varnish/vmods/
/usr/share/doc/%{name}/*
/usr/share/man/man3/*

%changelog
* Thu Aug 31 2017 Ole Fredrik Skudsvik <ole.skudsvik@gmail.com>
- Initial version.
