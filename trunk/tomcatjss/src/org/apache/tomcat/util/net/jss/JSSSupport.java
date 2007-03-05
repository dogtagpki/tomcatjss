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
 * Copyright (C) 2007 Red Hat, Inc.
 * All rights reserved.
 * END COPYRIGHT BLOCK */

package org.apache.tomcat.util.net.jss;

import org.apache.tomcat.util.net.*;
import java.io.*;
import java.net.*;
import org.mozilla.jss.crypto.X509Certificate;
import org.mozilla.jss.ssl.*;
import java.security.cert.*;

class JSSSupport implements SSLSupport{
    private static org.apache.commons.logging.Log log =
        org.apache.commons.logging.LogFactory.getLog(JSSSupport.class);

    private SSLSocket ssl = null;
    private SSLSecurityStatus status = null;

    JSSSupport(SSLSocket sock) {
        ssl = sock;
        try {
            status = ssl.getStatus();
        } catch (IOException e) {
        }
    }

    public Object[] getPeerCertificateChain(boolean force) throws IOException {
        // retrieve the status when we need it. status cache
        // the client certificate which may not be available
        // at the creation of JSSSupport
        status = ssl.getStatus();
        if (status != null) {
            X509Certificate peerCert = status.getPeerCertificate();
       
            if (peerCert == null) {
                ssl.setNeedClientAuth(true);
                try {
                    ssl.redoHandshake();
                    ssl.forceHandshake();
                } catch (Exception e) {
                }
                status = ssl.getStatus();
                peerCert = status.getPeerCertificate();
            }

            if (peerCert != null) {
                java.security.cert.X509Certificate[] certs = 
                  new java.security.cert.X509Certificate[1];
                try {
                    byte[] b = peerCert.getEncoded();
                    CertificateFactory cf = CertificateFactory.getInstance("X.509");
                    ByteArrayInputStream stream =
                      new ByteArrayInputStream(b);
                    certs[0] = (java.security.cert.X509Certificate)cf.generateCertificate(stream);
                } catch (Exception e) {
                }
                return certs;
            }
        }

        return null;
    }

    public Object[] getPeerCertificateChain() throws IOException {
        return getPeerCertificateChain(false);
    }

    public String getCipherSuite() throws IOException {
        if (status != null)
            return status.getCipher();
        return null;
    }

    public Integer getKeySize() throws IOException {
        if (status != null)
            return (new Integer(status.getSessionKeySize()));
        return null;
    }

    public String getSessionId() throws IOException {
        return null;
    }
}


