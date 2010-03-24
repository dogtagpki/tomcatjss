# Don't build the debug packages
%define debug_package %{nil}
# No need to strip
%define __os_install_post %{nil}
%ifos Solaris
%define _javadir %{_datadir}/java
%endif

Name:     tomcatjss
Version:  1.1.0
Release:  8%{?dist}
Summary:  JSSE implementation using JSS for Tomcat
URL:      http://www.redhat.com/software/rha/certificate
Source0:  %{name}-%{version}.tar.gz
License:  LGPL
Group:    System Environment/Libraries
%ifos Solaris
SUNW_pkg: RHATtomcatjssx
SourcePackage: RHATtomcatjss-src
%endif

BuildArch:      noarch
BuildRoot:      %{_tmppath}/%{name}-%{version}-%{release}-buildroot

%ifos Linux
BuildRequires:  java-devel
BuildRequires:  jpackage-utils >= 0:1.6.0
BuildRequires:  eclipse-ecj >= 0:3.0.1
BuildRequires:  ant >= 0:1.6.2
BuildRequires:  tomcat5 >= 5.5.9
BuildRequires:  dirsec-jss >= 4.2
Requires:       java >= 0:1.4.2
Requires:       tomcat5 >= 5.5.9
Requires:       dirsec-jss >= 4.2
%else
BuildRequires:  RHATdirsec-jssx >= 4.2
Requires:       RHATtomcat5x >= 5.5.9
Requires:       RHATdirsec-jssx >= 4.2
%endif

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