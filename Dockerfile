#
# Copyright Red Hat, Inc.
#
# SPDX-License-Identifier: GPL-2.0-or-later
#

ARG BASE_IMAGE="registry.fedoraproject.org/fedora:latest"
ARG COPR_REPO="@pki/master"

################################################################################
FROM $BASE_IMAGE AS tomcatjss-base

RUN dnf install -y systemd \
    && dnf clean all \
    && rm -rf /var/cache/dnf

CMD [ "/usr/sbin/init" ]

################################################################################
FROM tomcatjss-base AS tomcatjss-deps

ARG COPR_REPO

# Enable COPR repo if specified
RUN if [ -n "$COPR_REPO" ]; then dnf install -y dnf-plugins-core; dnf copr enable -y $COPR_REPO; fi

# Install Tomcat JSS runtime dependencies
RUN dnf install -y dogtag-tomcatjss \
    && dnf remove -y dogtag-* --noautoremove \
    && dnf clean all \
    && rm -rf /var/cache/dnf

################################################################################
FROM tomcatjss-deps AS tomcatjss-builder-deps

# Install build tools
RUN dnf install -y rpm-build

# Import Tomcat JSS sources
COPY tomcatjss.spec /root/tomcatjss/
WORKDIR /root/tomcatjss

# Install Tomcat JSS build dependencies
RUN dnf builddep -y --spec tomcatjss.spec

################################################################################
FROM tomcatjss-builder-deps AS tomcatjss-builder

# Import Tomcat JSS source
COPY . /root/tomcatjss/

# Build Tomcat JSS packages
RUN ./build.sh --work-dir=build rpm

################################################################################
FROM tomcatjss-deps AS tomcatjss-runner

# Import Tomcat JSS packages
COPY --from=tomcatjss-builder /root/tomcatjss/build/RPMS /tmp/RPMS/

# Install Tomcat JSS packages
RUN dnf localinstall -y /tmp/RPMS/* \
    && dnf clean all \
    && rm -rf /var/cache/dnf \
    && rm -rf /tmp/RPMS
