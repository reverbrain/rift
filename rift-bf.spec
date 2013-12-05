Summary:	The rift
Name:		rift
Version:	0.6.3
Release:	1%{?dist}

License:	Apache 2.0
Group:		System Environment/Libraries
URL:		https://github.com/reverbrain/rift
Source0:	%{name}-%{version}.tar.bz2
BuildRoot:	%{_tmppath}/%{name}-%{version}-%{release}-root-%(%{__id_u} -n)

%if %{defined rhel} && 0%{?rhel} < 6
BuildRequires:	gcc44 gcc44-c++
%define boost_ver 141
%else
%define boost_ver %{nil}
%endif
BuildRequires:	boost%{boost_ver}-devel, boost%{boost_ver}-program_options, boost%{boost_ver}-system, boost%{boost_ver}-thread
BuildRequires:	elliptics-client-devel >= 2.24.14.26
BuildRequires:  curl-devel libthevoid-devel msgpack-devel
BuildRequires:	cmake

%description
Blah, Blah, minor

%package devel
Summary: Development files for %{name}
Group: Development/Libraries
Requires: %{name} = %{version}-%{release}


%description devel
Rift devel package

%prep
%setup -q

%build
%if %{defined rhel} && 0%{?rhel} < 6
export CC=gcc44
export CXX=g++44
CXXFLAGS="-pthread -I/usr/include/boost141" LDFLAGS="-L/usr/lib64/boost141" %{cmake} -DBoost_LIB_DIR=/usr/lib64/boost141 -DBoost_INCLUDE_DIR=/usr/include/boost141 -DBoost_LIBRARYDIR=/usr/lib64/boost141 -DBOOST_LIBRARYDIR=/usr/lib64/boost141 -DCMAKE_CXX_COMPILER=g++44 -DCMAKE_C_COMPILER=gcc44 -DBUILD_NETWORK_MANAGER=off .
%else
%{cmake} .
%endif

make %{?_smp_mflags}

%install
rm -rf %{buildroot}
make install DESTDIR=%{buildroot}

%post -p /sbin/ldconfig
%postun -p /sbin/ldconfig


%clean
rm -rf %{buildroot}

%files
%defattr(-,root,root,-)
%{_bindir}/*
%{_libdir}/*.so.*

%files devel
%defattr(-,root,root,-)
%{_includedir}/*
%{_libdir}/*.so


%changelog
* Fri Dec 06 2013 Evgeniy Polyakov <zbr@ioremap.net> - 0.6.3
- build: dependencies update
- Example: Added headers support to python auth example
- Signature: Added comment about signature arguments
- Tests: Added tests for get/upload/ping/echo/lookup handlers
- Example: Added initialization script for start/stop daemon

* Fri Dec 06 2013 Evgeniy Polyakov <zbr@ioremap.net> - 0.6.3
- build: dependencies update

* Mon Dec 02 2013 Evgeniy Polyakov <zbr@ioremap.net> - 0.6.2
- rift: made redirect handler a separate option, not either redirect or get
- bucket_meta: fixed memset() ovrwrite
- spec: added rhel/fedora spec file
- config: if bucket section was not specified, set noauth-allowed flag
- rift: made redirect handler a separate option, not either redirect or get

* Tue Nov 19 2013 Ruslan Nigmatullin <euroelessar@yandex.ru> - 0.6.1
- initial build
