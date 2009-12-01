# Don't build the debug packages
%define debug_package %{nil}
# No need to strip
%define __os_install_post %{nil}

%ifos Linux
## A distribution model is required on certain Linux operating systems!
##
## check for a pre-defined distribution model
%define undefined_distro  %(test "%{dist}" = "" && echo 1 || echo 0)
%if %{undefined_distro}
%define is_fedora         %(test -e /etc/fedora-release && echo 1 || echo 0)
%if %{is_fedora}
## define a default distribution model on Fedora Linux
%define dist_prefix       .fc
%define dist_version      %(echo `rpm -qf --qf='%{VERSION}' /etc/fedora-release` | tr -d [A-Za-z])
%define dist              %{dist_prefix}%{dist_version}
%else
%define is_redhat         %(test -e /etc/redhat-release && echo 1 || echo 0)
%if %{is_redhat}
## define a default distribution model on Red Hat Linux
%define dist_prefix       .el
%define dist_version      %(echo `rpm -qf --qf='%{VERSION}' /etc/redhat-release` | tr -d [A-Za-z])
%define dist              %{dist_prefix}%{dist_version}
%endif
%endif
%endif
%endif

Name:     tomcatjss
Version:  1.1.2
Release:  4%{?dist}
Summary:  JSSE implementation using JSS for Tomcat
URL:      http://www.redhat.com/software/rha/certificate
Source0:  %{name}-%{version}.tar.gz
License:  LGPL
Group:    System Environment/Libraries
BuildArch:      noarch
BuildRoot:      %{_tmppath}/%{name}-%{version}-%{release}-buildroot

## Helper Definitions
%define pki_jdk           java-devel >= 1:1.6.0
# Override the default 'pki_jdk' on Fedora 8 platforms
%{?fc8:%define pki_jdk    java-devel >= 1.7.0}

BuildRequires:  %{pki_jdk}
BuildRequires:  jpackage-utils >= 0:1.6.0
BuildRequires:  eclipse-ecj >= 0:3.0.1
BuildRequires:  ant >= 0:1.6.2
BuildRequires:  tomcat5 >= 5.5.9
BuildRequires:  jss >= 4.2.6
BuildRequires:  nuxwdog-client-devel 
Requires:       java >= 1:1.6.0
Requires:       tomcat5 >= 5.5.9
Requires:       jss >= 4.2.6

%description
A JSSE implementation using Java Security Services (JSS) for Tomcat 5.5.

%prep

%setup -q

%build

ant -f build.xml
ant -f build.xml dist

%install
rm -rf $RPM_BUILD_ROOT

# Unpack the files we just built
cd dist/binary
unzip %{name}-%{version}.zip -d $RPM_BUILD_ROOT

# Install our files
cd $RPM_BUILD_ROOT%{_javadir}
mv tomcatjss.jar tomcatjss-%{version}.jar
ln -s tomcatjss-%{version}.jar tomcatjss.jar
mkdir -p $RPM_BUILD_ROOT/var/lib/tomcat5/server/lib
cd $RPM_BUILD_ROOT/var/lib/tomcat5/server/lib
ln -s ../../../../../usr/share/java/tomcatjss.jar tomcatjss.jar

%clean
rm -rf $RPM_BUILD_ROOT

%files
%defattr(-,root,root)
%doc README LICENSE
%{_javadir}/*
/var/lib/tomcat5/server/lib/tomcatjss.jar

%changelog
* Mon Nov 30 2009 Ade Lee <alee@redhat.com> 1.1.2-5
- removed osutil dependency and changed to nuxwdog

* Thu Nov 26 2009 Kevin Wright <kwright@redhat.com> 1.1.2-4
- updated build.xml to match version

* Thu Nov 26 2009 Kevin Wright <kwright@redhat.com> 1.1.2-3
- Added BuildRequires osutil.

* Thu Nov 26 2009 Kevin Wright <kwright@redhat.com> 1.1.2-2
- Added BuildRequires osutil.

* Wed Nov 25 2009 Kevin Wright <kwright@redhat.com> 1.1.2-1
- Bumped the rev to correspond to CS80 errata 3.

* Mon Nov 23 2009 Ade Lee <alee@redhat.com> 1.1.1-3
- Bugzilla Bug #518123 - Prompt for passwords if password.conf is removed

* Mon Nov 10 2009 Christina Fu <cfu@redhat.com> 1.1.1-2
- Bugzilla Bug #529945 - added ocsp cache setting.  Requires new JSS (jss-4.2.6-6) interfaces

* Wed Oct 28 2009 Jack Magne <jmagne@redhat.com> 1.1.1-1
- Bugzilla Bug #529945 -  CS 8,0 GA release -- DRM and TKS do not seem to have CRL checking enabled

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
