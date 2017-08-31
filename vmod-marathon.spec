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
BuildRequires: varnish >= 4.1.4
BuildRequires: varnish-devel >= 4.1.4

%description
marathon support for Varnish VCL

%prep
%setup -n libvmod-marathon

%build
./autogen.sh
./configure --prefix=/usr/
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

%changelog
* Thu Aug 31 2017 Ole Fredrik Skudsvik <ole.skudsvik@gmail.com>
- Initial version.
