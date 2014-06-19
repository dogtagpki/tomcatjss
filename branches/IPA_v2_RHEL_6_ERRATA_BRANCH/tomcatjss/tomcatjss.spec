Name:     tomcatjss
Version:  2.1.0
Release:  3%{?dist}
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
BuildRequires:    tomcat6
BuildRequires:    jss >= 4.2.6

Requires:         java >= 1:1.6.0
Requires:         jpackage-utils
Requires:         tomcat6
Requires:         jss >= 4.2.6

Patch1:           tomcatjss-client-auth.patch 
Patch2:           tomcatjss-strict-ciphers.patch

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
%patch1 -p1
%patch2 -p1

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
mkdir -p %{buildroot}%{_datadir}/doc/%{name}-%{version}

%clean
rm -rf %{buildroot}

%files
%defattr(-,root,root)
%doc %attr(644,root,root) README LICENSE
%attr(00755,root,root) %{_datadir}/doc/%{name}-%{version}
%{_javadir}/*

%changelog
* Mon Jun 16 2014 Christina Fu <cfu@redhat.com> - 2.1.0-3
- Resolves: Buzilla Bug #1084224 - Tomcatjss missing strictCiphers implementation

* Fri Aug 05 2011 Jack Magne  <jmagne@redhat.com>  - 2.1.0-2
- Resolves: #75107 - rhch80 cannot do client auth with pkiconsole (ok with 7.3)
* Wed Jan 12 2011 John Dennis <jdennis@redhat.com> - 2.1.0-1
- Resolves: Bug 643544
- bump version to 2.1.0
  Bug #588323 - Failed to enable cipher 0xc001 (svn rev 105)
  Bug #634375 - Build tomcatjss against tomcat6 (svn rev 106)
  Bug #655915 - Disable socket timeouts when socket is first created. (svn rev 107)

* Tue Dec 14 2010 John Dennis <jdennis@redhat.com> 
- Updated 'tomcatjss' to utilize 'tomcat6'.
