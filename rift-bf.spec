Summary:	The rift
Name:		rift
Version:	0.6.9
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
BuildRequires:	boost%{boost_ver}-devel, boost%{boost_ver}-system, boost%{boost_ver}-thread
BuildRequires:	elliptics-client-devel >= 2.24.15.1
BuildRequires:  curl-devel, libthevoid-devel >= 0.6.1.1, msgpack-devel
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
* Sun Feb 02 2014 Evgeniy Polyakov <zbr@ioremap.net> - 0.6.9
- debian: depend on elliptics >= 2.24.15.1 and << 2.25.0.0
- elliptics_base: added read/write timeouts: config options, update IO sessions

* Tue Jan 28 2014 Evgeniy Polyakov <zbr@ioremap.net> - 0.6.8
- package: provide correct package build versions

* Fri Jan 24 2014 Evgeniy Polyakov <zbr@ioremap.net> - 0.6.7
- logger: use swarm's logger as well as its log-level, otherwise default (INFO) was used
- server: elliptics node must be destructed after all threads and sessions are gone
- example-config: updated noauth and redirect-port options

* Thu Jan 16 2014 Evgeniy Polyakov <zbr@ioremap.net> - 0.6.6
- io:upload_base: upload updates indexes in all but cached groups, check meta.groups.size() when updating gropus - metadata can be empty if buckets are not supported. Debug logs added.

* Tue Jan 14 2014 Evgeniy Polyakov <zbr@ioremap.net> - 0.6.5
- extract_key: only set metadata groups and namespace if bucket_meta is not 'empty'

* Tue Jan 14 2014 Evgeniy Polyakov <zbr@ioremap.net> - 0.6.4
- elliptics_base: move elliptics connector wrapper into header file, so it can be reused in external projects like wookie
- index: update/find indexes now support bucket processing and authentification
- Example: Added proper url support for http_auth example
- Debian: Depend on libmsgpack-dev not msgpack-devel
- rhel: compilation fixes

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
