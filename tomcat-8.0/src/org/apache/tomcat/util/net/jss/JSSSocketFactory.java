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

import java.io.IOException;
import java.net.InetAddress;
import java.net.ServerSocket;
import java.net.Socket;
import java.net.SocketException;
import java.util.Properties;

import javax.net.ssl.KeyManager;
import javax.net.ssl.SSLContext;
import javax.net.ssl.TrustManager;

// Imports required to "implement" Tomcat 7 Interface
import org.apache.tomcat.util.net.AbstractEndpoint;
import org.mozilla.jss.ssl.SSLServerSocket;
import org.mozilla.jss.ssl.SSLSocket;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class JSSSocketFactory implements
        org.apache.tomcat.util.net.ServerSocketFactory,
        org.apache.tomcat.util.net.SSLUtil {

    public static Logger logger = LoggerFactory.getLogger(JSSSocketFactory.class);

    TomcatJSS tomcatjss = TomcatJSS.getInstance();

    private AbstractEndpoint<?> endpoint;
    private Properties config;

    public JSSSocketFactory(AbstractEndpoint<?> endpoint) {
        this(endpoint, null);
    }

    public JSSSocketFactory(AbstractEndpoint<?> endpoint, Properties config) {
        this.endpoint = endpoint;
        this.config = config;

        try {
            init();
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
    }

    String getProperty(String tag) {

        // check <catalina.base>/conf/server.xml
        String value = (String)endpoint.getAttribute(tag);

        // if not available, check <catalina.base>/conf/tomcatjss.conf
        if (value == null) {
            value = config.getProperty(tag);
        }

        return value;
    }

    String getProperty(String tag, String defaultValue) {
        String value = getProperty(tag);
        if (value == null) {
            return defaultValue;
        }
        return value;
    }

    void init() throws IOException {
        try {
            String certdbDir = getProperty("certdbDir");
            tomcatjss.setCertdbDir(certdbDir);

            String passwordClass = getProperty("passwordClass");
            tomcatjss.setPasswordClass(passwordClass);

            String passwordFile = getProperty("passwordFile");
            tomcatjss.setPasswordFile(passwordFile);

            String serverCertNickFile = getProperty("serverCertNickFile");
            tomcatjss.setServerCertNickFile(serverCertNickFile);

            // MUST look for "clientauth" (ALL lowercase) since "clientAuth"
            // (camel case) has already been processed by Tomcat 7
            String clientAuth = getProperty("clientauth");
            if (clientAuth != null) {
                tomcatjss.setClientAuth(clientAuth);
            }

            String strEnableOCSP = getProperty("enableOCSP");
            boolean enableOCSP = Boolean.parseBoolean(strEnableOCSP);
            tomcatjss.setEnableOCSP(enableOCSP);

            String ocspResponderURL = getProperty("ocspResponderURL");
            tomcatjss.setOcspResponderURL(ocspResponderURL);

            String ocspResponderCertNickname = getProperty("ocspResponderCertNickname");
            tomcatjss.setOcspResponderCertNickname(ocspResponderCertNickname);

            String strOcspCacheSize = getProperty("ocspCacheSize");
            if (strOcspCacheSize != null) {
                int ocspCacheSize = Integer.parseInt(strOcspCacheSize);
                tomcatjss.setOcspCacheSize(ocspCacheSize);
            }

            String strOcspMinCacheEntryDuration = getProperty("ocspMinCacheEntryDuration");
            if (strOcspMinCacheEntryDuration != null) {
                int ocspMinCacheEntryDuration = Integer.parseInt(strOcspMinCacheEntryDuration);
                tomcatjss.setOcspMinCacheEntryDuration(ocspMinCacheEntryDuration);
            }

            String strOcspMaxCacheEntryDuration = getProperty("ocspMaxCacheEntryDuration");
            if (strOcspMaxCacheEntryDuration != null) {
                int ocspMaxCacheEntryDuration = Integer.parseInt(strOcspMaxCacheEntryDuration);
                tomcatjss.setOcspMaxCacheEntryDuration(ocspMaxCacheEntryDuration);
            }

            String strOcspTimeout = getProperty("ocspTimeout");
            if (strOcspTimeout != null) {
                int ocspTimeout = Integer.parseInt(strOcspTimeout);
                tomcatjss.setOcspTimeout(ocspTimeout);
            }

            String strictCiphers = getProperty("strictCiphers");
            tomcatjss.setStrictCiphers(strictCiphers);

            String sslVersionRangeStream = getProperty("sslVersionRangeStream");
            tomcatjss.setSslVersionRangeStream(sslVersionRangeStream);

            String sslVersionRangeDatagram = getProperty("sslVersionRangeDatagram");
            tomcatjss.setSslVersionRangeDatagram(sslVersionRangeDatagram);

            String sslRangeCiphers = getProperty("sslRangeCiphers");
            tomcatjss.setSslRangeCiphers(sslRangeCiphers);

            String sslOptions = getProperty("sslOptions");
            tomcatjss.setSslOptions(sslOptions);

            String ssl2Ciphers = getProperty("ssl2Ciphers");
            tomcatjss.setSsl2Ciphers(ssl2Ciphers);

            String ssl3Ciphers = getProperty("ssl3Ciphers");
            tomcatjss.setSsl3Ciphers(ssl3Ciphers);

            String tlsCiphers = getProperty("tlsCiphers");
            tomcatjss.setTlsCiphers(tlsCiphers);

            tomcatjss.init();

        } catch (Exception ex) {
            logger.error("JSSSocketFactory: " + ex);
            // The idea is, if admin take the trouble to configure the
            // ocsp cache, and made a mistake, we want to make server
            // unavailable until they get it right
            if ((ex instanceof java.security.GeneralSecurityException)
                    || (ex instanceof java.lang.NumberFormatException))
                throw new IOException(ex);
        }
    }

    public Socket acceptSocket(ServerSocket socket) throws IOException {
        SSLSocket asock = null;
        try {
            asock = (SSLSocket) socket.accept();
            asock.addSocketListener(tomcatjss);

            if (tomcatjss.getRequireClientAuth() || tomcatjss.getWantClientAuth()) {
                asock.requestClientAuth(true);
                if (tomcatjss.getRequireClientAuth()) {
                    asock.requireClientAuth(SSLSocket.SSL_REQUIRE_ALWAYS);
                } else {
                    asock.requireClientAuth(SSLSocket.SSL_REQUIRE_NEVER);
                }
            }
        } catch (Exception e) {
            throw new SocketException("SSL handshake error " + e.toString());
        }

        return asock;
    }

    public void handshake(Socket sock) throws IOException {
        // ((SSLSocket)sock).forceHandshake();
    }

    public ServerSocket createSocket(int port) throws IOException {
        return createSocket(port, SSLServerSocket.DEFAULT_BACKLOG, null);
    }

    public ServerSocket createSocket(int port, int backlog) throws IOException {
        return createSocket(port, backlog, null);
    }

    public ServerSocket createSocket(int port, int backlog,
            InetAddress ifAddress) throws IOException {
        return createSocket(port, backlog, ifAddress, true);
    }

    public ServerSocket createSocket(int port, int backlog,
            InetAddress ifAddress, boolean reuseAddr) throws IOException {

        SSLServerSocket socket = null;
        socket = new SSLServerSocket(port, backlog, ifAddress, null, reuseAddr);
        initializeSocket(socket);
        return socket;
    }

    private void initializeSocket(SSLServerSocket s) {
        try {
            /*
             * Timeout's should not be enabled by default. Upper layers will
             * call setSoTimeout() as needed. Zero means disable.
             */
            s.setSoTimeout(0);
            if (tomcatjss.getRequireClientAuth() || tomcatjss.getWantClientAuth()) {
                s.requestClientAuth(true);
                if (tomcatjss.getRequireClientAuth()) {
                    s.requireClientAuth(SSLSocket.SSL_REQUIRE_ALWAYS);
                } else {
                    s.requireClientAuth(SSLSocket.SSL_REQUIRE_NEVER);
                }
            }
            String serverCertNick = tomcatjss.getServerCertNick();
            s.setServerCertNickname(serverCertNick);
        } catch (Exception e) {
        }
    }

    // Methods required to "implement" Tomcat 7 Interface
    public SSLContext createSSLContext() throws Exception {
        return null;
    }

    public KeyManager[] getKeyManagers() throws Exception {
        return null;
    }

    public TrustManager[] getTrustManagers() throws Exception {
        return null;
    }

    public void configureSessionContext(
            javax.net.ssl.SSLSessionContext sslSessionContext) {
        return;
    }

    public String[] getEnableableCiphers(SSLContext context) {
        return null;
    }

    public String[] getEnableableProtocols(SSLContext context) {
        return null;
    }
}
