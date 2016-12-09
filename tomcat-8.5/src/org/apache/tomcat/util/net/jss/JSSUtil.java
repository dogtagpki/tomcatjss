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

import java.util.List;

import javax.net.ssl.KeyManager;
import javax.net.ssl.SSLSessionContext;
import javax.net.ssl.TrustManager;

import org.apache.tomcat.util.net.SSLContext;
import org.apache.tomcat.util.net.SSLUtil;

public class JSSUtil implements SSLUtil {

    @Override
    public void configureSessionContext(SSLSessionContext arg0) {
    }

    @Override
    public SSLContext createSSLContext(List<String> arg0) throws Exception {
        return null;
    }

    @Override
    public String[] getEnabledCiphers() throws IllegalArgumentException {
        return null;
    }

    @Override
    public String[] getEnabledProtocols() throws IllegalArgumentException {
        return null;
    }

    @Override
    public KeyManager[] getKeyManagers() throws Exception {
        return null;
    }

    @Override
    public TrustManager[] getTrustManagers() throws Exception {
        return null;
    }
}
