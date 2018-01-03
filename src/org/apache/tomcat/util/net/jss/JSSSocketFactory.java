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

    private boolean mStrictCiphers = false;

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

    public void setSSLCiphers(String attr) throws SocketException, IOException {
        String ciphers = getProperty(attr);
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
    public void setSSLOptions() throws SocketException, IOException {
        String options = getProperty("sslOptions");
        if (StringUtils.isEmpty(options)) {
            logger.fine("JSSSocketFactory: no sslOptions specified");
            return;
        }

        logger.fine("JSSSocketFactory: Processing sslOptions:");
        StringTokenizer st = new StringTokenizer(options, ", ");
        while (st.hasMoreTokens()) {
            String option = st.nextToken();
            logger.fine("JSSSocketFactory:  - " + option);

            StringTokenizer st1 = new StringTokenizer(option, "=");
            String name = st1.nextToken();
            String value = st1.nextToken();
            if (name.equals("ssl2")) {
                if (value.equals("true")) {
                    SSLSocket.enableSSL2Default(true);
                    setSSLCiphers("ssl2Ciphers");
                } else {
                    SSLSocket.enableSSL2Default(false);
                }
            }
            if (name.equals("ssl3")) {
                if (value.equals("true")) {
                    SSLSocket.enableSSL3Default(true);
                    setSSLCiphers("ssl3Ciphers");
                } else {
                    SSLSocket.enableSSL3Default(false);
                }
            }
            if (name.equals("tls")) {
                if (value.equals("true")) {
                    SSLSocket.enableTLSDefault(true);
                    setSSLCiphers("tlsCiphers");
                } else {
                    SSLSocket.enableTLSDefault(false);
                }
            }
        }
    }

    // remove all to start with a clean slate
    public void unsetSSLCiphers() throws SocketException {
        int ciphers[] = SSLSocket.getImplementedCipherSuites();
        try {
            for (int i = 0; ciphers != null && i < ciphers.length; i++) {

                logger.fine("JSSSocketFactory: unsetSSLCiphers: turning off '0x"
                        + Integer.toHexString(ciphers[i]) + "'");
                SSLSocket.setCipherPreferenceDefault(ciphers[i], false);
            }
        } catch (Exception e) {
        }
    }

    /*
     * setSSLVersionRangeDefault sets the range of allowed ssl versions. This
     * replaces the obsolete SSL_Option* API
     *
     * @param protoVariant indicates whether this setting is for type "stream"
     * or "datagram"
     *
     * @param sslVersionRange_s takes on the form of "min:max" where min/max
     * values can be "ssl3, tls1_0, tls1_1, or tls1_2" ssl2 is not supported for
     * tomcatjss via this interface The format is "sslVersionRange=min:max"
     */
    public void setSSLVersionRangeDefault(
            org.mozilla.jss.ssl.SSLSocket.SSLProtocolVariant protoVariant,
            String sslVersionRange_s) throws SocketException,
            IllegalArgumentException, IOException {

        // process sslVersionRange_s
        String[] sslVersionRange = sslVersionRange_s.split(":");
        if (sslVersionRange.length != 2) {
            logger.severe("JSSSocketFactory: setSSLversionRangeDefault: SSL Version Range format error: "
                    + sslVersionRange_s);
            throw new SocketException(
                    "tomcatjss: setSSLversionRangeDefault format error");
        }
        String min_s = sslVersionRange[0];
        String max_s = sslVersionRange[1];
        int min = getSSLVersionRangeEnum(min_s);
        int max = getSSLVersionRangeEnum(max_s);
        if ((min == -1) || (max == -1)) {
            logger.severe("JSSSocketFactory: setSSLversionRangeDefault: SSL Version Range format error: "
                    + sslVersionRange_s);
            throw new SocketException(
                    "tomcatjss: setSSLversionRangeDefault format error");
        }

        logger.fine("JSSSocketFactory: setSSLversionRangeDefault: SSL Version Range set to min="
                + min + " max = " + max);
        org.mozilla.jss.ssl.SSLSocket.SSLVersionRange range = new org.mozilla.jss.ssl.SSLSocket.SSLVersionRange(
                min, max);

        SSLSocket.setSSLVersionRangeDefault(protoVariant, range);
        logger.fine("JSSSocketFactory: setSSLversionRangeDefault: variant set");
    }

    int getSSLVersionRangeEnum(String rangeString) {
        if (rangeString == null)
            return -1;
        if (rangeString.equals("ssl3"))
            return org.mozilla.jss.ssl.SSLSocket.SSLVersionRange.ssl3;
        else if (rangeString.equals("tls1_0"))
            return org.mozilla.jss.ssl.SSLSocket.SSLVersionRange.tls1_0;
        else if (rangeString.equals("tls1_1"))
            return org.mozilla.jss.ssl.SSLSocket.SSLVersionRange.tls1_1;
        else if (rangeString.equals("tls1_2"))
            return org.mozilla.jss.ssl.SSLSocket.SSLVersionRange.tls1_2;

        return -1;
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

            tomcatjss.init();

            // 12 hours = 43200 seconds
            SSLServerSocket.configServerSessionIDCache(0, 43200, 43200, null);

            String strictCiphersStr = getProperty("strictCiphers");
            if (StringUtils.equalsIgnoreCase(strictCiphersStr, "true")
                    || StringUtils.equalsIgnoreCase(strictCiphersStr, "yes")) {
                mStrictCiphers = true;
            }
            if (mStrictCiphers == true) {
                // what ciphers do we have to start with? turn them all off
                logger.fine("JSSSocketFactory: init: before setSSLCiphers, strictCiphers is true");
                unsetSSLCiphers();
            } else {
                logger.fine("JSSSocketFactory: init: before setSSLCiphers, strictCiphers is false");
            }

            String sslVersionRangeStream = getProperty("sslVersionRangeStream");
            if ((sslVersionRangeStream != null)
                    && !sslVersionRangeStream.equals("")) {
                logger.fine("JSSSocketFactory: init: calling setSSLVersionRangeDefault() for type STREAM");
                setSSLVersionRangeDefault(
                        org.mozilla.jss.ssl.SSLSocket.SSLProtocolVariant.STREAM,
                        sslVersionRangeStream);
                logger.fine("JSSSocketFactory: init: after setSSLVersionRangeDefault() for type STREAM");
            }

            String sslVersionRangeDatagram = getProperty("sslVersionRangeDatagram");
            if ((sslVersionRangeDatagram != null)
                    && !sslVersionRangeDatagram.equals("")) {
                logger.fine("JSSSocketFactory: init: calling setSSLVersionRangeDefault() for type DATA_GRAM");
                setSSLVersionRangeDefault(
                        org.mozilla.jss.ssl.SSLSocket.SSLProtocolVariant.DATA_GRAM,
                        sslVersionRangeDatagram);
                logger.fine("JSSSocketFactory: init: after setSSLVersionRangeDefault() for type DATA_GRAM");
            }

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
                setSSLCiphers("sslRangeCiphers");
                logger.fine("JSSSocketFactory: init: after setSSLCiphers() honoring only sslRangeCiphers");
            } else {
                logger.fine("JSSSocketFactory: init: calling setSSLOptions()");
                setSSLOptions();
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
