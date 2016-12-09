/* BEGIN COPYRIGHT BLOCK
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301  USA
 *
 * Copyright (C) 2018 Red Hat, Inc.
 * All rights reserved.
 * END COPYRIGHT BLOCK */

package org.apache.tomcat.util.net.jss;

import java.io.IOException;
import java.security.cert.X509Certificate;

import org.apache.tomcat.util.net.SSLSupport;

public class JSSSupport implements SSLSupport {

    @Override
    public String getCipherSuite() throws IOException {
        return null;
    }

    @Override
    public Integer getKeySize() throws IOException {
        return null;
    }

    @Override
    public X509Certificate[] getPeerCertificateChain() throws IOException {
        return null;
    }

    @Override
    public String getProtocol() throws IOException {
        return null;
    }

    @Override
    public String getSessionId() throws IOException {
        return null;
    }

 }
