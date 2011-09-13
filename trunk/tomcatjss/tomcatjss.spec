Name:     tomcatjss
Version:  6.0.1
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
%if 0%{?fedora} >= 16
BuildRequires:    jpackage-utils >= 0:1.7.5-10
%else
BuildRequires:    jpackage-utils
%endif
%if 0%{?fedora} >= 15
BuildRequires:    tomcat6 >= 6.0.30-6
%else
BuildRequires:    tomcat6
%endif
BuildRequires:    jss >= 4.2.6-17

Requires:         java >= 1:1.6.0
%if 0%{?fedora} >= 16
Requires:         jpackage-utils >= 0:1.7.5-10
%else
Requires:         jpackage-utils
%endif
%if 0%{?fedora} >= 15
Requires:         tomcat6 >= 6.0.30-6
%else
Requires:         tomcat6
%endif
Requires:         jss >= 4.2.6-17

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
using Java Security Services (JSS) for Tomcat 6.

NOTE:  The 'tomcatjss' package conflicts with the 'tomcat-native' package
       because it uses an underlying NSS security model rather than the
       OpenSSL security model, so these two packages may not co-exist.

%prep

%setup -q

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
mv %{name}.jar %{name}-%{version}.jar
ln -s %{name}-%{version}.jar %{name}.jar
mkdir -p %{buildroot}%{_datadir}/doc/%{name}-%{version}

%clean
rm -rf %{buildroot}

%files
%defattr(-,root,root)
%doc %attr(644,root,root) README LICENSE
%attr(00755,root,root) %{_datadir}/doc/%{name}-%{version}
%{_javadir}/*

%changelog
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
