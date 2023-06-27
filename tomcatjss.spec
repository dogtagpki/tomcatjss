################################################################################
Name:             tomcatjss
################################################################################

%global           product_id dogtag-tomcatjss

# Upstream version number:
%global           major_version 8
%global           minor_version 5
%global           update_version 0

# Downstream release number:
# - development/stabilization (unsupported): 0.<n> where n >= 1
# - GA/update (supported): <n> where n >= 1
%global           release_number 0.1

# Development phase:
# - development (unsupported): alpha<n> where n >= 1
# - stabilization (unsupported): beta<n> where n >= 1
# - GA/update (supported): <none>
%global           phase alpha1

%undefine         timestamp
%undefine         commit_id

Summary:          JSS Connector for Apache Tomcat
URL:              https://github.com/dogtagpki/tomcatjss
License:          LGPL-2.1-or-later
Version:          %{major_version}.%{minor_version}.%{update_version}
Release:          %{release_number}%{?phase:.}%{?phase}%{?timestamp:.}%{?timestamp}%{?commit_id:.}%{?commit_id}%{?dist}

# To generate the source tarball:
# $ git clone https://github.com/dogtagpki/tomcatjss.git
# $ cd tomcatjss
# $ git archive \
#     --format=tar.gz \
#     --prefix tomcatjss-VERSION/ \
#     -o tomcatjss-VERSION.tar.gz \
#     <version tag>
Source:           https://github.com/dogtagpki/tomcatjss/archive/v%{version}%{?phase:-}%{?phase}/tomcatjss-%{version}%{?phase:-}%{?phase}.tar.gz

# To create a patch for all changes since a version tag:
# $ git format-patch \
#     --stdout \
#     <version tag> \
#     > tomcatjss-VERSION-RELEASE.patch
# Patch: tomcatjss-VERSION-RELEASE.patch

BuildArch:        noarch
%if 0%{?fedora}
ExclusiveArch:  %{java_arches} noarch
%endif

################################################################################
# Java
################################################################################

%define java_devel java-17-openjdk-devel
%define java_headless java-17-openjdk-headless
%define java_home %{_jvmdir}/jre-17-openjdk

################################################################################
# Build Dependencies
################################################################################

# jpackage-utils requires versioning to meet both build and runtime requirements
# jss requires versioning to meet both build and runtime requirements
# tomcat requires versioning to meet both build and runtime requirements

# Java
BuildRequires:    ant
BuildRequires:    %{java_devel}
BuildRequires:    maven-local

# maven-shade-plugin is not available on CentOS/RHEL
#BuildRequires:    mvn(org.apache.maven.plugins:maven-shade-plugin)

BuildRequires:    mvn(org.apache.commons:commons-lang3)

# SLF4J
BuildRequires:    mvn(org.slf4j:slf4j-api)
BuildRequires:    mvn(org.slf4j:slf4j-jdk14)

# Tomcat
BuildRequires:    mvn(org.apache.tomcat:tomcat-catalina)
BuildRequires:    mvn(org.apache.tomcat:tomcat-coyote)
BuildRequires:    mvn(org.apache.tomcat:tomcat-juli)

# JSS
BuildRequires:    mvn(org.dogtagpki.jss:jss-base) >= 5.5.0

%description
JSS Connector for Apache Tomcat, installed via the tomcatjss package,
is a Java Secure Socket Extension (JSSE) module for Apache Tomcat that
uses Java Security Services (JSS), a Java interface to Network Security
Services (NSS).

################################################################################
%package -n %{product_id}
################################################################################

Summary:          JSS Connector for Apache Tomcat

# Java
Requires:         %{java_headless}
Requires:         mvn(org.apache.commons:commons-lang3)

# SLF4J
Requires:         mvn(org.slf4j:slf4j-api)
Requires:         mvn(org.slf4j:slf4j-jdk14)

# Tomcat
Requires:         mvn(org.apache.tomcat:tomcat-catalina)
Requires:         mvn(org.apache.tomcat:tomcat-coyote)
Requires:         mvn(org.apache.tomcat:tomcat-juli)

# JSS
Requires:         mvn(org.dogtagpki.jss:jss-base) >= 5.5.0

Obsoletes:        tomcatjss < %{version}-%{release}
Provides:         tomcatjss = %{version}-%{release}
Provides:         tomcatjss = %{major_version}.%{minor_version}
Provides:         %{product_id} = %{major_version}.%{minor_version}

# PKI
Conflicts:        pki-base < 10.10.0


%if 0%{?rhel}
# For EPEL, override the '_sharedstatedir' macro on RHEL
%define           _sharedstatedir    /var/lib
%endif

%description -n %{product_id}
JSS Connector for Apache Tomcat, installed via the tomcatjss package,
is a Java Secure Socket Extension (JSSE) module for Apache Tomcat that
uses Java Security Services (JSS), a Java interface to Network Security
Services (NSS).

################################################################################
%prep
################################################################################

%autosetup -n tomcatjss-%{version}%{?phase:-}%{?phase} -p 1

################################################################################
%build
################################################################################

export JAVA_HOME=%{java_home}

# flatten-maven-plugin is not available in RPM
%pom_remove_plugin org.codehaus.mojo:flatten-maven-plugin

# disable main module since maven-shade-plugin is not available on CentOS/RHEL
%pom_disable_module main

# build without Javadoc
%mvn_build -j

# merge JAR files into tomcatjss.jar
mkdir -p main/target/classes

pushd main/target/classes
jar xvf ../../../core/target/tomcatjss-core-%{version}-SNAPSHOT.jar
jar xvf ../../../tomcat-9.0/target/tomcatjss-tomcat-9.0-%{version}-SNAPSHOT.jar
popd

jar cvf main/target/tomcatjss.jar -C main/target/classes .

################################################################################
%install
################################################################################

%mvn_install

install -p main/target/tomcatjss.jar %{buildroot}%{_javadir}/tomcatjss.jar

################################################################################
%files -n %{product_id} -f .mfiles
################################################################################

%license LICENSE
%doc README
%doc LICENSE
%{_javadir}/tomcatjss.jar

################################################################################
%changelog
* Thu Mar 15 2018 Dogtag PKI Team <pki-devel@redhat.com> 7.3.0-0
- To list changes in <branch> since <tag>:
  $ git log --pretty=oneline --abbrev-commit --no-decorate <tag>..<branch>
