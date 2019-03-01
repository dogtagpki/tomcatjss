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

package org.dogtagpki.tomcat;

import javax.net.ssl.KeyManager;
import javax.net.ssl.TrustManager;

import org.apache.tomcat.util.net.SSLHostConfigCertificate;
import org.apache.tomcat.util.net.jsse.JSSEKeyManager;
import org.apache.tomcat.util.net.jsse.JSSEUtil;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class JSSUtil extends JSSEUtil {

    public static Logger logger = LoggerFactory.getLogger(JSSUtil.class);

    public JSSUtil(SSLHostConfigCertificate cert) {
        super(cert);
        logger.debug("JSSUtil: instance created");
    }

    @Override
    public KeyManager[] getKeyManagers() throws Exception {
        logger.debug("JSSUtil: getKeyManagers()");
        String keyAlias = certificate.getCertificateKeyAlias();
        KeyManager keyManager = new JSSEKeyManager(new JSSKeyManager(), keyAlias);
        return new KeyManager[] { keyManager };
    }

    @Override
    public TrustManager[] getTrustManagers() throws Exception {
        logger.debug("JSSUtil: getTrustManagers()");
        return new TrustManager[] { new JSSTrustManager() };
    }
}
