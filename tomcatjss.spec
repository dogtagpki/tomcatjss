################################################################################
Name:             tomcatjss
################################################################################

Summary:          JSS Connector for Apache Tomcat
URL:              http://www.dogtagpki.org/wiki/TomcatJSS
License:          LGPLv2+
BuildArch:        noarch

Version:          7.6.1
Release:          1%{?_timestamp}%{?_commit_id}%{?dist}
#global           _phase -a1

# To generate the source tarball:
# $ git clone https://github.com/dogtagpki/tomcatjss.git
# $ cd tomcatjss
# $ git archive \
#     --format=tar.gz \
#     --prefix tomcatjss-VERSION/ \
#     -o tomcatjss-VERSION.tar.gz \
#     <version tag>
Source:           https://github.com/dogtagpki/tomcatjss/archive/v%{version}%{?_phase}/tomcatjss-%{version}%{?_phase}.tar.gz

# To create a patch for all changes since a version tag:
# $ git format-patch \
#     --stdout \
#     <version tag> \
#     > tomcatjss-VERSION-RELEASE.patch
# Patch: tomcatjss-VERSION-RELEASE.patch

################################################################################
# Build Dependencies
################################################################################

# jpackage-utils requires versioning to meet both build and runtime requirements
# jss requires versioning to meet both build and runtime requirements
# tomcat requires versioning to meet both build and runtime requirements

# Java
BuildRequires:    ant
BuildRequires:    apache-commons-lang3
BuildRequires:    java-devel
BuildRequires:    jpackage-utils >= 0:1.7.5-15

# SLF4J
BuildRequires:    slf4j
BuildRequires:    slf4j-jdk14

# JSS
BuildRequires:    jss >= 4.8.0

# Tomcat
%if 0%{?rhel} && ! 0%{?eln}
BuildRequires:    pki-servlet-engine >= 1:9.0.7
%else
BuildRequires:    tomcat >= 1:9.0.7
%endif

################################################################################
# Runtime Dependencies
################################################################################

# Java
Requires:         apache-commons-lang3
%if 0%{?fedora} >= 21
Requires:         java-headless
%else
Requires:         java
%endif
Requires:         jpackage-utils >= 0:1.7.5-15

# SLF4J
Requires:         slf4j
Requires:         slf4j-jdk14

# JSS
Requires:         jss >= 4.8.0

# Tomcat
%if 0%{?rhel} && ! 0%{?eln}
Requires:         pki-servlet-engine >= 1:9.0.7
%else
Requires:         tomcat >= 1:9.0.7
%endif

# PKI
Conflicts:        pki-base < 10.10.0


%if 0%{?rhel}
# For EPEL, override the '_sharedstatedir' macro on RHEL
%define           _sharedstatedir    /var/lib
%endif

%description
JSS Connector for Apache Tomcat, installed via the tomcatjss package,
is a Java Secure Socket Extension (JSSE) module for Apache Tomcat that
uses Java Security Services (JSS), a Java interface to Network Security
Services (NSS).

################################################################################
%prep
################################################################################

%autosetup -n tomcatjss-%{version}%{?_phase} -p 1

################################################################################
%install
################################################################################

# get Tomcat <major>.<minor> version number
tomcat_version=`/usr/sbin/tomcat version | sed -n 's/Server number: *\([0-9]\+\.[0-9]\+\).*/\1/p'`
app_server=tomcat-$tomcat_version

ant -f build.xml \
    -Dversion=%{version} \
    -Dsrc.dir=$app_server \
    -Djnidir=%{_jnidir} \
    -Dinstall.doc.dir=%{buildroot}%{_docdir}/%{name} \
    -Dinstall.jar.dir=%{buildroot}%{_javadir} \
    install

################################################################################
%files
################################################################################

%license LICENSE

%defattr(-,root,root)
%doc README
%doc LICENSE
%{_javadir}/*

################################################################################
%changelog
* Thu Mar 15 2018 Dogtag PKI Team <pki-devel@redhat.com> 7.3.0-0
- To list changes in <branch> since <tag>:
  $ git log --pretty=oneline --abbrev-commit --no-decorate <tag>..<branch>
