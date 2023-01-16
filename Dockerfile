#
# Copyright Red Hat, Inc.
#
# SPDX-License-Identifier: GPL-2.0-or-later
#

ARG BASE_IMAGE="registry.fedoraproject.org/fedora:34"
ARG COPR_REPO=""

################################################################################
FROM $BASE_IMAGE AS tomcatjss-base

RUN dnf install -y dnf-plugins-core systemd \
    && dnf clean all \
    && rm -rf /var/cache/dnf

CMD [ "/usr/sbin/init" ]

################################################################################
FROM tomcatjss-base AS tomcatjss-deps

ARG COPR_REPO

# Enable COPR repo if specified
RUN if [ -n "$COPR_REPO" ]; then dnf copr enable -y $COPR_REPO; fi

# Install Tomcat JSS runtime dependencies
RUN dnf install -y tomcatjss \
    && dnf remove -y jss-* --noautoremove \
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
RUN dnf builddep -y --skip-unavailable --spec tomcatjss.spec

################################################################################
FROM tomcatjss-builder-deps AS tomcatjss-builder

# Import JSS packages
COPY --from=ghcr.io/dogtagpki/jss-dist:4 /root/RPMS /tmp/RPMS/

# Install build dependencies
RUN dnf localinstall -y /tmp/RPMS/* \
    && dnf clean all \
    && rm -rf /var/cache/dnf \
    && rm -rf /tmp/RPMS

# Import Tomcat JSS source
COPY . /root/tomcatjss/

# Build Tomcat JSS packages
RUN ./build.sh --work-dir=build rpm

################################################################################
FROM alpine:latest AS tomcatjss-dist

# Import Tomcat JSS packages
COPY --from=tomcatjss-builder /root/tomcatjss/build/RPMS /root/RPMS/

################################################################################
FROM tomcatjss-deps AS tomcatjss-runner

# Import JSS packages
COPY --from=ghcr.io/dogtagpki/jss-dist:4 /root/RPMS /tmp/RPMS/

# Import Tomcat JSS packages
COPY --from=tomcatjss-dist /root/RPMS /tmp/RPMS/

# Install runtime packages
RUN dnf localinstall -y /tmp/RPMS/* \
    && dnf clean all \
    && rm -rf /var/cache/dnf \
    && rm -rf /tmp/RPMS
