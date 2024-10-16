%define compname xml-security-c
%define libname lib%{compname}30
%define develname lib%{compname}-devel
%define utilname %{compname}-bin

Name: %{libname}
Version: 3.0.0
Release: 1%{?dist}
Summary: XML security C++ library
Group: Development/Libraries/C and C++
License: Apache-2.0
URL: https://shibboleth.net/downloads/xml-security-c
Source0: %{compname}-%{version}.tar.bz2
Provides: %{compname} = %{version}-%{release}
Obsoletes: %{compname} < %{version}-%{release}

BuildRequires: libxerces-c-devel >= 3.2
BuildRequires: openssl-devel gcc-c++ pkgconfig
%if "%{_vendor}" == "redhat"
BuildRequires: redhat-rpm-config
%endif

%if 0%{?rhel} >= 8 || 0%{?centos_version} >= 800
BuildRequires: gdb
%endif

%description
The xml-security-c library is a C++ implementation of the XML Digital Signature
and Encryption specifications. The library makes use of the Apache Xerces-C XML Parser.

The main package contains just the shared library.

%package -n %{utilname}
Summary: Utilities for XML security C++ library
Group: Development/Libraries/C and C++

%description -n %{utilname}
The xml-security-c library is a C++ implementation of the XML Digital Signature
and Encryption specifications. The library makes use of the Apache Xerces-C XML Parser.

This package contains the utility programs.

%package -n %{develname}
Summary: Development files for the C++ XML security library
Group: Development/Libraries/C and C++
Requires: %{libname} = %{version}-%{release}
Requires: openssl-devel
Requires: libxerces-c-devel >= 3.2
Provides: %{compname}-devel = %{version}-%{release}

%description -n %{develname}
The xml-security-c library is a C++ implementation of the XML Digital Signature
and Encryption specifications. The library makes use of the Apache Xerces-C XML Parser.

This package includes files needed for development with xml-security-c.

%prep
%setup -q -n %{compname}-%{version}

%build
%configure --with-openssl
%{__make}

%install
%make_install

%clean
%{__rm} -rf $RPM_BUILD_ROOT


%post -p /sbin/ldconfig

%postun -p /sbin/ldconfig

%files -n %{utilname}
%defattr(-,root,root,-)
%{_bindir}/*

%files
%defattr(-,root,root,-)
%{_libdir}/*.so.*

%files -n %{develname}
%defattr(-,root,root,-)
%{_includedir}/*
%{_libdir}/*.so
%{_libdir}/pkgconfig/xml-security-c.pc
%exclude %{_libdir}/*.la

%changelog
* Wed Oct 16 2024 Scott Cantor <cantor.2@osu.edu> 3.0.0-1
- Update to version 3.0.0
- Sanitize Apache references in metadata
- Remove Xalan/XKMS references in build

* Sat Jun 17 2023 John W. O'Brien <john@saltant.com> 2.0.4-2
- Normalize SPEC file whitespace
- Delete obsolete BuildRoot macro
- Conform License field to SPDX License List
- Ensure Source is valid and fetchable
- Adopt %make_install
- Parameterize (sub-)package names
- Replace empty main package with lib sub-package
- Append %dist to Release

* Mon Nov 13 2017 Scott Cantor <cantor.2@osu.edu> 2.0.0-1
- update to 2.0.0
- exclude libtool archive

* Wed Jan 28 2015 Scott Cantor <cantor.2@osu.edu> 1.7.3-1
- update to 1.7.3
- remove support for dead Xerces versions
- switch to bzipped source to avoid SuSE problems later

* Tue May 13 2014 Ian Young <ian@iay.org.uk> 1.7.2-2.2
- fix package dependencies for RHEL/CentOS 7
- fix bogus dates in changelog

* Mon Jul 30 2012 Scott Cantor <cantor.2@osu.edu> 1.7.0-1
- update to 1.7.0
- update URL and license

* Tue Oct 26 2010 Scott Cantor <cantor.2@osu.edu> 1.6.0-1
- update to 1.6.0
- fix package dependencies for OpenSUSE 11.3+ and Xalan

* Mon Dec 28 2009 Scott Cantor <cantor.2@osu.edu> 1.5.1-2
- Sync package names for side by side installation

* Wed Aug 5 2009   Scott Cantor  <cantor.2@osu.edu> 1.5.1-1
- update to 1.5.1 and add SuSE conventions

* Sat Dec 6 2008   Scott Cantor  <cantor.2@osu.edu> 1.5-1
- update to 1.5
- fix Xerces dependency name on SUSE

* Wed Aug 15 2007   Scott Cantor  <cantor.2@osu.edu> 1.4.0-1
- update to 1.4.0

* Mon Jun 11 2007   Scott Cantor  <cantor.2@osu.edu> 1.3.1-1
- update to 1.3.1

* Thu Mar 23 2006   Ian Young     <ian@iay.org.uk> - 1.2.0-2
- patch to remove extra qualifications for compat with g++ 4.1

* Sun Jul 03 2005   Scott Cantor  <cantor.2@osu.edu> - 1.2.0-1
- Updated version.

* Tue Oct 19 2004   Derek Atkins  <derek@ihtfp.com> - 1.1.1-1
- First Package.
