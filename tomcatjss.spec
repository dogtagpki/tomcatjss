Name:     tomcatjss
Version:  7.2.0
Release:  1%{?dist}
Summary:  JSSE implementation using JSS for Tomcat
URL:      http://pki.fedoraproject.org/
License:  LGPLv2+
Group:    System Environment/Libraries

BuildArch:      noarch
BuildRoot:      %{_tmppath}/%{name}-%{version}-%{release}-buildroot

Source0:  http://pki.fedoraproject.org/pki/sources/%{name}/%{name}-%{version}.tar.gz

# jpackage-utils requires versioning to meet both build and runtime requirements
# jss requires versioning to meet both build and runtime requirements
# tomcat requires versioning to meet both build and runtime requirements
BuildRequires:    ant
BuildRequires:    apache-commons-lang
BuildRequires:    java-devel
BuildRequires:    jpackage-utils >= 0:1.7.5-15
BuildRequires:    jss >= 4.2.6-35
%if 0%{?fedora} >= 23
BuildRequires:    tomcat >= 8.0.18
%else
BuildRequires:    tomcat >= 7.0.68
%endif

Requires:         apache-commons-lang
%if 0%{?fedora} >= 21
Requires:         java-headless
%else
Requires:         java
%endif
Requires:         jpackage-utils >= 0:1.7.5-15
Requires:         jss >= 4.2.6-35
%if 0%{?fedora} >= 23
Requires:         tomcat >= 8.0.18
%else
Requires:         tomcat >= 7.0.68
%endif

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
using Java Security Services (JSS) for Tomcat 7.

NOTE:  The 'tomcatjss' package conflicts with the 'tomcat-native' package
       because it uses an underlying NSS security model rather than the
       OpenSSL security model, so these two packages may not co-exist.

%prep

%setup -q
chmod -c -x LICENSE README

%build

ant -f build.xml -Djnidir=%{_jnidir}
ant -f build.xml -Djnidir=%{_jnidir} dist

%install
rm -rf %{buildroot}

# Unpack the files we just built
cd dist/binary
unzip %{name}-%{version}.zip -d %{buildroot}

# Install our files
cd %{buildroot}%{_javadir}
%if 0%{?rhel} || 0%{?fedora} < 21
mv %{name}.jar %{name}-%{version}.jar
ln -s %{name}-%{version}.jar %{name}.jar
%endif

%clean
rm -rf %{buildroot}

%files
%defattr(-,root,root)
%doc README LICENSE
%{_javadir}/*

%changelog
* Sun Mar 12 2017 Matthew Harmsen <mharmsen@redhat.com> 7.2.0-1
- tomcatjss Pagure Issue #6 - Rebase tomcatjss to 7.2.0 in Fedora 25+ (mharmsen)
- Bugzilla Bug #1394416 - Rebase tomcatjss to 7.2.0 in RHEL 7.4 (mharmsen)

* Sat Feb 11 2017 Fedora Release Engineering <releng@fedoraproject.org> - 7.1.4-2
- Rebuilt for https://fedoraproject.org/wiki/Fedora_26_Mass_Rebuild

* Tue Jul 5 2016 Christina Fu <cfu@redhat.com> 7.1.4.1
- Bugzilla Bug #1203407 missing ciphers (cfu)

* Tue Jul 5 2016 Christina Fu <cfu@redhat.com> 7.1.3.3
- Bugzilla Bug #1203407 missing ciphers (cfu)

* Fri Feb 05 2016 Fedora Release Engineering <releng@fedoraproject.org> 7.1.3-2
- Rebuilt for https://fedoraproject.org/wiki/Fedora_24_Mass_Rebuild

* Wed Jul 22 2015 Endi Sukma Dewata <edewata@redhat.com> 7.1.3-1
- Bugzilla Bug #1245786 - Build failure on F23

* Fri Jun 19 2015 Fedora Release Engineering <rel-eng@lists.fedoraproject.org> - 7.1.2-2
- Rebuilt for https://fedoraproject.org/wiki/Fedora_23_Mass_Rebuild

* Wed Mar  4 2015 Endi Sukma Dewata <edewata@redhat.com> 7.1.2-1
- Bugzilla Bug #1198450 - Support for Tomcat 8
- Bugzilla Bug #1214858 - Add nuxwdog support (alee)

* Tue Sep 30 2014 Christina Fu <cfu@redhat.com> 7.1.1-1
- Bugzilla Bug #1058366 NullPointerException in tomcatjss searching
  for attribute "clientauth" (cfu)
- Bugzilla Bug #871171 - Provide Tomcat support for TLS v1.1 and
  TLS v1.2 (cfu)
- Bumped revision to 7.1.1

* Sun Jun 08 2014 Fedora Release Engineering <rel-eng@lists.fedoraproject.org> - 7.1.0-6
- Rebuilt for https://fedoraproject.org/wiki/Fedora_21_Mass_Rebuild

* Tue Mar 25 2014 Mikolaj Izdebski <mizdebsk@redhat.com> - 7.1.0-5
- Move to java-headless
- Resolves: rhbz#1068567

* Tue Jan 07 2014 Michael Simacek <msimacek@redhat.com> - 7.1.0-5
- Remove versioned symlink (rhbz#1022167)

* Fri Aug  2 2013 Ville Skyttä <ville.skytta@iki.fi> - 7.1.0-4
- Simplify installation of docs.

* Thu Jun 13 2013 Matthew Harmsen <mharmsen@redhat.com> 7.1.0-3
- Updated tomcatjss to utilize tomcat-7.0.40.
- Updated JNIDIR to /usr/lib/java.

* Fri Feb 15 2013 Fedora Release Engineering <rel-eng@lists.fedoraproject.org> - 7.1.0-2
- Rebuilt for https://fedoraproject.org/wiki/Fedora_19_Mass_Rebuild

* Wed Dec 19 2012 Christina Fu <cfu@redhat.com> 7.1.0-1
- Bugzila Bug #819554 tomcatjss: Please migrate from tomcat6 to tomcat7

* Thu Aug  2 2012 Matthew Harmsen <mharmsen@redhat.com> 7.0.0-3
- PKI TRAC Ticket #283 - Dogtag 10: Integrate Tomcat 6 'tomcatjss.jar' and
  Tomcat 7 'tomcat7jss.jar' in Fedora 18 tomcatjss package

* Thu Jul 26 2012 Matthew Harmsen <mharmsen@redhat.com> 7.0.0-2
- Fixed runtime 'Requires' cut/paste typos

* Wed Jun 06 2012 Matthew Harmsen <mharmsen@redhat.com> 7.0.0-1
- Bugzilla Bug #819554 - tomcatjss: Please migrate from tomcat6 to tomcat7

* Thu Sep 22 2011 Matthew Harmsen <mharmsen@redhat.com> 6.0.2-1
- Bugzilla Bug #734590 - Refactor JNI libraries for Fedora 16+ . . . (mharmsen)
- Bugzilla Bug #699809 - Convert CS to use systemd (alee)

* Mon Sep 12 2011 Matthew Harmsen <mharmsen@redhat.com> 6.0.1-1
- Bugzilla Bug #734590 - Refactor JNI libraries for Fedora 16+ . . .

* Thu Jul 14 2011 Matthew Harmsen <mharmsen@redhat.com> - 6.0.0-1
- Bugzilla Bug #702716 - rhcs80 cannot do client auth with pkiconsole
  (ok with 7.3) (jmagne)
- Require "jss >= 4.2.6-17" as a build and runtime requirement
- Bump version 2.1.1 --> 6.0.0 (to better coincide with tomcat6)

* Fri Mar 25 2011 Matthew Harmsen <mharmsen@redhat.com> - 2.1.1-1
- Require "jss >= 4.2.6-15" as a build and runtime requirement
- Require "tomcat6 >= 6.0.30-6" as a build and runtime requirement
  for Fedora 15 and later platforms

* Wed Jan 12 2011 John Dennis <jdennis@redhat.com> - 2.1.0-1
- bump version to 2.1.0
  Bug #588323 - Failed to enable cipher 0xc001 (svn rev 105)
  Bug #634375 - Build tomcatjss against tomcat6 (svn rev 106)
  Bug #655915 - Disable socket timeouts when socket is first created. (svn rev 107)

* Tue Dec 14 2010 John Dennis <jdennis@redhat.com> 
- Updated 'tomcatjss' to utilize 'tomcat6'.
