Name:     tomcatjss
Version:  1.2.1
Release:  1%{?dist}
Summary:  JSSE implementation using JSS for Tomcat
URL:      http://pki.fedoraproject.org/
License:  LGPLv2+
Group:    System Environment/Libraries

BuildArch:      noarch
BuildRoot:      %{_tmppath}/%{name}-%{version}-%{release}-buildroot

Source0:  http://pki.fedoraproject.org/pki/sources/%{name}/%{name}-%{version}.tar.gz

BuildRequires:    ant
BuildRequires:    java-devel >= 1:1.6.0
BuildRequires:    jpackage-utils
BuildRequires:    tomcat5
BuildRequires:    jss >= 4.2.6

Requires:         java >= 1:1.6.0
Requires:         jpackage-utils
Requires:         tomcat5
Requires:         jss >= 4.2.6

# The 'tomcatjss' package conflicts with the 'tomcat-native' package
# because it uses an underlying NSS security model rather than the
# OpenSSL security model, so these two packages may not co-exist.
# (see Bugzilla Bug #441974 for details)
Conflicts:        tomcat-native

%if 0%{?rhel}
# For EPEL, override the '_sharedstatedir' macro on RHEL
%define           _sharedstatedir    /var/lib
%endif

%description
A Java Secure Socket Extension (JSSE) implementation
using Java Security Services (JSS) for Tomcat 5.5.

NOTE:  The 'tomcatjss' package conflicts with the 'tomcat-native' package
       because it uses an underlying NSS security model rather than the
       OpenSSL security model, so these two packages may not co-exist.

%prep

%setup -q

%build

ant -f build.xml
ant -f build.xml dist

%install
rm -rf %{buildroot}

# Unpack the files we just built
cd dist/binary
unzip %{name}-%{version}.zip -d %{buildroot}

# Install our files
cd %{buildroot}%{_javadir}
mv %{name}.jar %{name}-%{version}.jar
ln -s %{name}-%{version}.jar %{name}.jar
mkdir -p %{buildroot}%{_sharedstatedir}/tomcat5/server/lib
cd %{buildroot}%{_sharedstatedir}/tomcat5/server/lib
ln -s ../../../../../usr/share/java/%{name}.jar %{name}.jar
mkdir -p %{buildroot}%{_datadir}/doc/%{name}-%{version}

%clean
rm -rf %{buildroot}

%files
%defattr(-,root,root)
%doc %attr(644,root,root) README LICENSE
%attr(00755,root,root) %{_datadir}/doc/%{name}-%{version}
%{_javadir}/*
%{_sharedstatedir}/tomcat5/server/lib/%{name}.jar

%changelog
* Thu Apr 8 2010 Matthew Harmsen <mharmsen@redhat.com> 1.2.1-1
- Update source tarball

* Tue Apr 6 2010 Matthew Harmsen <mharmsen@redhat.com> 1.2.0-4
- Bugzilla Bug #568787 - pki-ca fails to create SSL connectors
- Bugzilla Bug #573038 - Unable to login on Dogtag EPEL installation

* Thu Jan 14 2010 Matthew Harmsen <mharmsen@redhat.com> 1.2.0-3
- Bugzilla Bug #441974 -  CA Setup Wizard cannot create new Security Domain.
- Added 'Conflicts: tomcat-native' plus descriptive comment
- Updated 'description' section with this information

* Fri Sep 11 2009 Kevin Wright <kwright@redhat.com> 1.2.0-2
- Bugzilla Bug #521979 - Removed references to jre, fedora 8, etc

* Fri Aug 28 2009 Matthew Harmsen <mharmsen@redhat.com> 1.2.0-1
- Bugzilla Bug #521979 -  New Package for Dogtag PKI: tomcatjss

* Thu Jul 16 2009 Matthew Harmsen <mharmsen@redhat.com> 1.1.0-15
- Release Candidate 4 build

* Wed Jun 3 2009 Christina Fu <cfu@redhat.com> 1.1.0-14
- Bugzilla Bug #455305 - CA ECC signing Key Failure
  Bugzilla Bug #223279 - ECC: Ca: unable to perform agent auth on a machine with nCipher ECC HSM
- This log entry does not apply to tomcatjss.  Ignore.

* Fri May 1 2009 Christina Fu <cfu@redhat.com> - 1.1.0-13
- Bugzilla #498652 - SSL handshake Failure on RHCS java subsystems with nethsm2000
 
* Thu Feb  26 2009 Kevin Wright <kwright@redhat.com> - 1.1.0-12
- Updated to release 1.1.0-12 to build with idm extension

* Sat Nov 22 2008 Matthew Harmsen <mharmsen@redhat.com> 1.1.0-11
- Updated to require "java" and "java-devel" >= 1.6.0

* Thu Aug 02 2007 Thomas kwan <nkwan@redhat.com> 1.1.0-10
- Required JSS 4.2.5

* Fri Apr 26 2007 Kevin McCarthy <kmccarth@redhat.com> 1.1.0-9
- Change specfile to RHEL5 dependencies

* Fri Apr 20 2007 Thomas Kwan <nkwan@redhat.com> 1.1.0-8
- Re-integrated Solaris logic into the spec file

* Wed Apr 4 2007 Thomas Kwan <nkwan@redhat.com> 1.1.0-7
- Called new JSS api for client authentication

* Fri Mar 09 2007 Rob Crittenden <rcritten@redhat.com> 1.1.0-6
- Add Solaris directives for building with pkgbuild

* Mon Mar  3 2007 Rob Crittenden <rcritten@redhat.com> 1.1.0-5
- More spec file cleanup

* Fri Jan 26 2007 Rob Crittenden <rcritten@redhat.com> 1.1.0-4
- General spec file cleanup
- Added LGPL license

* Wed Feb 22 2006 Matthew Harmsen <mharmsen@redhat.com> 1.1.0-3
- Renamed "rpm.template" to "pki.template". Filled in Solaris section.

* Mon Feb 20 2006 Matthew Harmsen <mharmsen@redhat.com> 1.1.0-2
- Separated template into Linux, Solaris, and Changelog sections.

* Mon Dec 5 2005 Matthew Harmsen <mharmsen@redhat.com> 1.1.0-1
- Initial RPM template.
