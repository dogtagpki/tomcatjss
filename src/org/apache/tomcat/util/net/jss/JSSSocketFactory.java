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
import java.util.StringTokenizer;
import java.util.logging.Logger;

import javax.net.ssl.KeyManager;
import javax.net.ssl.SSLContext;
import javax.net.ssl.TrustManager;

import org.apache.commons.lang.StringUtils;
// Imports required to "implement" Tomcat 7 Interface
import org.apache.tomcat.util.net.AbstractEndpoint;
import org.mozilla.jss.ssl.SSLCipher;
import org.mozilla.jss.ssl.SSLServerSocket;
import org.mozilla.jss.ssl.SSLSocket;

public class JSSSocketFactory implements
        org.apache.tomcat.util.net.ServerSocketFactory,
        org.apache.tomcat.util.net.SSLUtil {

    final static Logger logger = Logger.getLogger(JSSSocketFactory.class.getName());

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

    public void setSSLCiphers(String attr, String ciphers) throws SocketException, IOException {

        if (StringUtils.isEmpty(ciphers)) {
            logger.fine("Missing " + attr);
            return;
        }

        logger.fine("Processing " + attr + ":");
        StringTokenizer st = new StringTokenizer(ciphers, ", ");
        while (st.hasMoreTokens()) {
            String cipherstr = st.nextToken();

            int cipherid = 0;
            String text;
            boolean state;

            if (cipherstr.startsWith("+")) {
                state = true;
                text = cipherstr.substring(1);
            } else if (cipherstr.startsWith("-")) {
                state = false;
                text = cipherstr.substring(1);
            } else {
                state = true; // no enable/disable flag, assume enable
                text = cipherstr;
            }

            logger.fine("* " + text + ":");
            logger.fine("  enabled: " + state);

            if (text.startsWith("0x") || text.startsWith("0X")) {
                // this allows us to specify new ciphers
                try {
                    cipherid = Integer.parseInt(text.substring(2), 16);
                } catch (Exception e) {
                    logger.severe("Invalid SSL cipher: " + text);
                    continue;
                }
            } else {
                try {
                    SSLCipher cipher = SSLCipher.valueOf(text);
                    cipherid = cipher.getID();
                } catch (IllegalArgumentException e) {
                    logger.severe("Unknown SSL cipher: " + text);
                    continue;
                }
            }

            logger.fine("  ID: 0x" + Integer.toHexString(cipherid));

            if (cipherid == 0) {
                logger.severe("Unknown SSL cipher: " + text);
                continue;
            }

            try {
                SSLSocket.setCipherPreferenceDefault(cipherid, state);

            } catch (Exception e) {
                logger.warning("Unable to set SSL cipher preference: " + e);
                SSLCipher cipher = SSLCipher.valueOf(cipherid);
                if (cipher != null && cipher.isECC()) {
                    logger.warning("SSL ECC cipher \""
                                    + text
                                    + "\" unsupported by NSS. "
                                    + "This is probably O.K. unless ECC support has been installed.");
                } else {
                    logger.severe("SSL cipher \"" + text
                            + "\" unsupported by NSS");
                }
            }
        }
    }

    /*
     * note: the SSL_OptionSet-based API for controlling the enabled protocol
     * versions are obsolete and replaced by the setSSLVersionRange calls. If
     * the "range" parameters are present in the attributes then the sslOptions
     * parameter is ignored.
     */
    public void setSSLOptions(
            String sslOptions,
            String ssl2Ciphers,
            String ssl3Ciphers,
            String tlsCiphers) throws SocketException, IOException {

        if (StringUtils.isEmpty(sslOptions)) {
            logger.fine("JSSSocketFactory: no sslOptions specified");
            return;
        }

        logger.fine("JSSSocketFactory: Processing sslOptions:");
        StringTokenizer st = new StringTokenizer(sslOptions, ", ");
        while (st.hasMoreTokens()) {
            String option = st.nextToken();
            logger.fine("JSSSocketFactory:  - " + option);

            StringTokenizer st1 = new StringTokenizer(option, "=");
            String name = st1.nextToken();
            String value = st1.nextToken();
            if (name.equals("ssl2")) {
                if (value.equals("true")) {
                    SSLSocket.enableSSL2Default(true);
                    setSSLCiphers("ssl2Ciphers", ssl2Ciphers);
                } else {
                    SSLSocket.enableSSL2Default(false);
                }
            }
            if (name.equals("ssl3")) {
                if (value.equals("true")) {
                    SSLSocket.enableSSL3Default(true);
                    setSSLCiphers("ssl3Ciphers", ssl3Ciphers);
                } else {
                    SSLSocket.enableSSL3Default(false);
                }
            }
            if (name.equals("tls")) {
                if (value.equals("true")) {
                    SSLSocket.enableTLSDefault(true);
                    setSSLCiphers("tlsCiphers", tlsCiphers);
                } else {
                    SSLSocket.enableTLSDefault(false);
                }
            }
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

            /*
             * According to NSS: the SSL_OptionSet-based API for controlling the
             * enabled protocol versions are obsolete and replaced by the
             * setSSLVersionRange calls. Therefore, if the "range" parameters
             * are present in the attributes then the sslOptions parameter is
             * ignored. Using the new version range API in conjunction with the
             * older SSL_OptionSet-based API for controlling the enabled
             * protocol versions may cause unexpected results
             */
            if (((sslVersionRangeStream != null) && !sslVersionRangeStream
                    .equals(""))
                    || ((sslVersionRangeDatagram != null) && !sslVersionRangeDatagram
                            .equals(""))) {
                /* deliberately lose the ssl2 here */
                logger.fine("JSSSocketFactory: init: calling setSSLCiphers() honoring only sslRangeCiphers");
                setSSLCiphers("sslRangeCiphers", sslRangeCiphers);
                logger.fine("JSSSocketFactory: init: after setSSLCiphers() honoring only sslRangeCiphers");
            } else {
                logger.fine("JSSSocketFactory: init: calling setSSLOptions()");
                setSSLOptions(sslOptions, ssl2Ciphers, ssl3Ciphers, tlsCiphers);
                logger.fine("JSSSocketFactory: init: after setSSLOptions()");
            }

        } catch (Exception ex) {
            logger.severe("JSSSocketFactory: " + ex);
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
