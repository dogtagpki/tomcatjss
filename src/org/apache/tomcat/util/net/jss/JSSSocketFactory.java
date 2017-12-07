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

import java.io.BufferedReader;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.net.InetAddress;
import java.net.ServerSocket;
import java.net.Socket;
import java.net.SocketException;
import java.util.HashMap;
import java.util.Properties;
import java.util.StringTokenizer;
import java.util.logging.Logger;

import javax.net.ssl.KeyManager;
import javax.net.ssl.SSLContext;
import javax.net.ssl.TrustManager;

import org.apache.commons.lang.StringUtils;
// Imports required to "implement" Tomcat 7 Interface
import org.apache.tomcat.util.net.AbstractEndpoint;
import org.mozilla.jss.CryptoManager;
import org.mozilla.jss.ssl.SSLServerSocket;
import org.mozilla.jss.ssl.SSLSocket;

public class JSSSocketFactory implements
        org.apache.tomcat.util.net.ServerSocketFactory,
        org.apache.tomcat.util.net.SSLUtil {

    final static Logger logger = Logger.getLogger(JSSSocketFactory.class.getName());

    private static HashMap<String, Integer> cipherMap = new HashMap<String, Integer>();
    static {
        // SSLv2
        cipherMap.put("SSL2_RC4_128_WITH_MD5", SSLSocket.SSL2_RC4_128_WITH_MD5);
        cipherMap.put("SSL2_RC4_128_EXPORT40_WITH_MD5",
                SSLSocket.SSL2_RC4_128_EXPORT40_WITH_MD5);
        cipherMap.put("SSL2_RC2_128_CBC_WITH_MD5",
                SSLSocket.SSL2_RC2_128_CBC_WITH_MD5);
        cipherMap.put("SSL2_RC2_128_CBC_EXPORT40_WITH_MD5",
                SSLSocket.SSL2_RC2_128_CBC_EXPORT40_WITH_MD5);
        cipherMap.put("SSL2_IDEA_128_CBC_WITH_MD5",
                SSLSocket.SSL2_IDEA_128_CBC_WITH_MD5);
        cipherMap.put("SSL2_DES_64_CBC_WITH_MD5",
                SSLSocket.SSL2_DES_64_CBC_WITH_MD5);
        cipherMap.put("SSL2_DES_192_EDE3_CBC_WITH_MD5",
                SSLSocket.SSL2_DES_192_EDE3_CBC_WITH_MD5);

        // SSLv3
        cipherMap.put("SSL3_RSA_WITH_NULL_MD5",
                SSLSocket.SSL3_RSA_WITH_NULL_MD5);
        cipherMap.put("SSL3_RSA_WITH_NULL_SHA",
                SSLSocket.SSL3_RSA_WITH_NULL_SHA);
        cipherMap.put("SSL3_RSA_EXPORT_WITH_RC4_40_MD5",
                SSLSocket.SSL3_RSA_EXPORT_WITH_RC4_40_MD5);
        cipherMap.put("SSL3_RSA_WITH_RC4_128_MD5",
                SSLSocket.SSL3_RSA_WITH_RC4_128_MD5);
        cipherMap.put("SSL3_RSA_WITH_RC4_128_SHA",
                SSLSocket.SSL3_RSA_WITH_RC4_128_SHA);
        cipherMap.put("SSL3_RSA_EXPORT_WITH_RC2_CBC_40_MD5",
                SSLSocket.SSL3_RSA_EXPORT_WITH_RC2_CBC_40_MD5);
        cipherMap.put("SSL3_RSA_WITH_IDEA_CBC_SHA",
                SSLSocket.SSL3_RSA_WITH_IDEA_CBC_SHA);
        cipherMap.put("SSL3_RSA_EXPORT_WITH_DES40_CBC_SHA",
                SSLSocket.SSL3_RSA_EXPORT_WITH_DES40_CBC_SHA);
        cipherMap.put("SSL3_RSA_WITH_DES_CBC_SHA",
                SSLSocket.SSL3_RSA_WITH_DES_CBC_SHA);

        cipherMap.put("SSL3_RSA_WITH_3DES_EDE_CBC_SHA",
                SSLSocket.SSL3_RSA_WITH_3DES_EDE_CBC_SHA);
        // deprecated SSL3.0 names replaced by IANA-registered TLS names
        cipherMap.put("TLS_RSA_WITH_3DES_EDE_CBC_SHA",
                SSLSocket.SSL3_RSA_WITH_3DES_EDE_CBC_SHA);

        cipherMap.put("SSL3_DH_DSS_EXPORT_WITH_DES40_CBC_SHA",
                SSLSocket.SSL3_DH_DSS_EXPORT_WITH_DES40_CBC_SHA);
        cipherMap.put("SSL3_DH_DSS_WITH_DES_CBC_SHA",
                SSLSocket.SSL3_DH_DSS_WITH_DES_CBC_SHA);
        cipherMap.put("SSL3_DH_DSS_WITH_3DES_EDE_CBC_SHA",
                SSLSocket.SSL3_DH_DSS_WITH_3DES_EDE_CBC_SHA);
        cipherMap.put("SSL3_DH_RSA_EXPORT_WITH_DES40_CBC_SHA",
                SSLSocket.SSL3_DH_RSA_EXPORT_WITH_DES40_CBC_SHA);
        cipherMap.put("SSL3_DH_RSA_WITH_DES_CBC_SHA",
                SSLSocket.SSL3_DH_RSA_WITH_DES_CBC_SHA);
        cipherMap.put("SSL3_DH_RSA_WITH_3DES_EDE_CBC_SHA",
                SSLSocket.SSL3_DH_RSA_WITH_3DES_EDE_CBC_SHA);

        cipherMap.put("SSL3_DHE_DSS_EXPORT_WITH_DES40_CBC_SHA",
                SSLSocket.SSL3_DHE_DSS_EXPORT_WITH_DES40_CBC_SHA);
        cipherMap.put("SSL3_DHE_DSS_WITH_DES_CBC_SHA",
                SSLSocket.SSL3_DHE_DSS_WITH_DES_CBC_SHA);

        cipherMap.put("SSL3_DHE_DSS_WITH_3DES_EDE_CBC_SHA",
                SSLSocket.SSL3_DHE_DSS_WITH_3DES_EDE_CBC_SHA);
        // deprecated SSL3.0 names replaced by IANA-registered TLS names
        cipherMap.put("TLS_DHE_DSS_WITH_3DES_EDE_CBC_SHA",
                SSLSocket.SSL3_DHE_DSS_WITH_3DES_EDE_CBC_SHA);

        cipherMap.put("SSL3_DHE_RSA_EXPORT_WITH_DES40_CBC_SHA",
                SSLSocket.SSL3_DHE_RSA_EXPORT_WITH_DES40_CBC_SHA);
        cipherMap.put("SSL3_DHE_RSA_WITH_DES_CBC_SHA",
                SSLSocket.SSL3_DHE_RSA_WITH_DES_CBC_SHA);

        cipherMap.put("SSL3_DHE_RSA_WITH_3DES_EDE_CBC_SHA",
                SSLSocket.SSL3_DHE_RSA_WITH_3DES_EDE_CBC_SHA);
        // deprecated SSL3.0 names replaced by IANA-registered TLS names
        cipherMap.put("TLS_DHE_RSA_WITH_3DES_EDE_CBC_SHA",
                SSLSocket.SSL3_DHE_RSA_WITH_3DES_EDE_CBC_SHA);

        cipherMap.put("SSL3_DH_ANON_EXPORT_WITH_RC4_40_MD5",
                SSLSocket.SSL3_DH_ANON_EXPORT_WITH_RC4_40_MD5);
        cipherMap.put("SSL3_DH_ANON_WITH_RC4_128_MD5",
                SSLSocket.SSL3_DH_ANON_WITH_RC4_128_MD5);
        cipherMap.put("SSL3_DH_ANON_EXPORT_WITH_DES40_CBC_SHA",
                SSLSocket.SSL3_DH_ANON_EXPORT_WITH_DES40_CBC_SHA);
        cipherMap.put("SSL3_DH_ANON_WITH_DES_CBC_SHA",
                SSLSocket.SSL3_DH_ANON_WITH_DES_CBC_SHA);
        cipherMap.put("SSL3_DH_ANON_WITH_3DES_EDE_CBC_SHA",
                SSLSocket.SSL3_DH_ANON_WITH_3DES_EDE_CBC_SHA);

        cipherMap.put("SSL3_FORTEZZA_DMS_WITH_NULL_SHA",
                SSLSocket.SSL3_FORTEZZA_DMS_WITH_NULL_SHA);
        cipherMap.put("SSL3_FORTEZZA_DMS_WITH_FORTEZZA_CBC_SHA",
                SSLSocket.SSL3_FORTEZZA_DMS_WITH_FORTEZZA_CBC_SHA);
        cipherMap.put("SSL3_FORTEZZA_DMS_WITH_RC4_128_SHA",
                SSLSocket.SSL3_FORTEZZA_DMS_WITH_RC4_128_SHA);

        cipherMap.put("SSL_RSA_FIPS_WITH_3DES_EDE_CBC_SHA",
                SSLSocket.SSL_RSA_FIPS_WITH_3DES_EDE_CBC_SHA);
        cipherMap.put("SSL_RSA_FIPS_WITH_DES_CBC_SHA",
                SSLSocket.SSL_RSA_FIPS_WITH_DES_CBC_SHA);

        // TLS
        cipherMap.put("TLS_RSA_EXPORT1024_WITH_DES_CBC_SHA",
                SSLSocket.TLS_RSA_EXPORT1024_WITH_DES_CBC_SHA);
        cipherMap.put("TLS_RSA_EXPORT1024_WITH_RC4_56_SHA",
                SSLSocket.TLS_RSA_EXPORT1024_WITH_RC4_56_SHA);

        cipherMap.put("TLS_DHE_DSS_EXPORT1024_WITH_DES_CBC_SHA",
                SSLSocket.TLS_DHE_DSS_EXPORT1024_WITH_DES_CBC_SHA);
        cipherMap.put("TLS_DHE_DSS_EXPORT1024_WITH_RC4_56_SHA",
                SSLSocket.TLS_DHE_DSS_EXPORT1024_WITH_RC4_56_SHA);
        cipherMap.put("TLS_DHE_DSS_WITH_RC4_128_SHA",
                SSLSocket.TLS_DHE_DSS_WITH_RC4_128_SHA);

        cipherMap.put("TLS_RSA_WITH_AES_128_CBC_SHA",
                SSLSocket.TLS_RSA_WITH_AES_128_CBC_SHA);
        cipherMap.put("TLS_DH_DSS_WITH_AES_128_CBC_SHA",
                SSLSocket.TLS_DH_DSS_WITH_AES_128_CBC_SHA);
        cipherMap.put("TLS_DH_RSA_WITH_AES_128_CBC_SHA",
                SSLSocket.TLS_DH_RSA_WITH_AES_128_CBC_SHA);
        cipherMap.put("TLS_DHE_DSS_WITH_AES_128_CBC_SHA",
                SSLSocket.TLS_DHE_DSS_WITH_AES_128_CBC_SHA);
        cipherMap.put("TLS_DHE_RSA_WITH_AES_128_CBC_SHA",
                SSLSocket.TLS_DHE_RSA_WITH_AES_128_CBC_SHA);
        cipherMap.put("TLS_DH_ANON_WITH_AES_128_CBC_SHA",
                SSLSocket.TLS_DH_ANON_WITH_AES_128_CBC_SHA);

        cipherMap.put("TLS_RSA_WITH_AES_256_CBC_SHA",
                SSLSocket.TLS_RSA_WITH_AES_256_CBC_SHA);
        cipherMap.put("TLS_DH_DSS_WITH_AES_256_CBC_SHA",
                SSLSocket.TLS_DH_DSS_WITH_AES_256_CBC_SHA);
        cipherMap.put("TLS_DH_RSA_WITH_AES_256_CBC_SHA",
                SSLSocket.TLS_DH_RSA_WITH_AES_256_CBC_SHA);
        cipherMap.put("TLS_DHE_DSS_WITH_AES_256_CBC_SHA",
                SSLSocket.TLS_DHE_DSS_WITH_AES_256_CBC_SHA);
        cipherMap.put("TLS_DHE_RSA_WITH_AES_256_CBC_SHA",
                SSLSocket.TLS_DHE_RSA_WITH_AES_256_CBC_SHA);
        cipherMap.put("TLS_DH_ANON_WITH_AES_256_CBC_SHA",
                SSLSocket.TLS_DH_ANON_WITH_AES_256_CBC_SHA);

        // ECC
        cipherMap.put("TLS_ECDH_ECDSA_WITH_NULL_SHA",
                SSLSocket.TLS_ECDH_ECDSA_WITH_NULL_SHA);
        cipherMap.put("TLS_ECDH_ECDSA_WITH_RC4_128_SHA",
                SSLSocket.TLS_ECDH_ECDSA_WITH_RC4_128_SHA);
        cipherMap.put("TLS_ECDH_ECDSA_WITH_3DES_EDE_CBC_SHA",
                SSLSocket.TLS_ECDH_ECDSA_WITH_3DES_EDE_CBC_SHA);
        cipherMap.put("TLS_ECDH_ECDSA_WITH_AES_128_CBC_SHA",
                SSLSocket.TLS_ECDH_ECDSA_WITH_AES_128_CBC_SHA);
        cipherMap.put("TLS_ECDH_ECDSA_WITH_AES_256_CBC_SHA",
                SSLSocket.TLS_ECDH_ECDSA_WITH_AES_256_CBC_SHA);

        cipherMap.put("TLS_ECDHE_ECDSA_WITH_NULL_SHA",
                SSLSocket.TLS_ECDHE_ECDSA_WITH_NULL_SHA);
        cipherMap.put("TLS_ECDHE_ECDSA_WITH_RC4_128_SHA",
                SSLSocket.TLS_ECDHE_ECDSA_WITH_RC4_128_SHA);
        cipherMap.put("TLS_ECDHE_ECDSA_WITH_3DES_EDE_CBC_SHA",
                SSLSocket.TLS_ECDHE_ECDSA_WITH_3DES_EDE_CBC_SHA);
        cipherMap.put("TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA",
                SSLSocket.TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA);
        cipherMap.put("TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA",
                SSLSocket.TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA);

        cipherMap.put("TLS_ECDHE_RSA_WITH_NULL_SHA",
                SSLSocket.TLS_ECDHE_RSA_WITH_NULL_SHA);
        cipherMap.put("TLS_ECDHE_RSA_WITH_RC4_128_SHA",
                SSLSocket.TLS_ECDHE_RSA_WITH_RC4_128_SHA);
        cipherMap.put("TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA",
                SSLSocket.TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA);
        cipherMap.put("TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA",
                SSLSocket.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA);
        cipherMap.put("TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA",
                SSLSocket.TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA);

        cipherMap.put("TLS_ECDH_anon_WITH_NULL_SHA",
                SSLSocket.TLS_ECDH_anon_WITH_NULL_SHA);
        cipherMap.put("TLS_ECDH_anon_WITH_RC4_128_SHA",
                SSLSocket.TLS_ECDH_anon_WITH_RC4_128_SHA);
        cipherMap.put("TLS_ECDH_anon_WITH_3DES_EDE_CBC_SHA",
                SSLSocket.TLS_ECDH_anon_WITH_3DES_EDE_CBC_SHA);
        cipherMap.put("TLS_ECDH_anon_WITH_AES_128_CBC_SHA",
                SSLSocket.TLS_ECDH_anon_WITH_AES_128_CBC_SHA);
        cipherMap.put("TLS_ECDH_anon_WITH_AES_256_CBC_SHA",
                SSLSocket.TLS_ECDH_anon_WITH_AES_256_CBC_SHA);

        // TLSv1_2
        cipherMap.put("TLS_DHE_RSA_WITH_AES_128_CBC_SHA256",
                SSLSocket.TLS_DHE_RSA_WITH_AES_128_CBC_SHA256);
        cipherMap.put("TLS_DHE_RSA_WITH_AES_256_CBC_SHA256",
                SSLSocket.TLS_DHE_RSA_WITH_AES_256_CBC_SHA256);
        cipherMap.put("TLS_RSA_WITH_NULL_SHA256",
                SSLSocket.TLS_RSA_WITH_NULL_SHA256);
        cipherMap.put("TLS_RSA_WITH_AES_128_CBC_SHA256",
                SSLSocket.TLS_RSA_WITH_AES_128_CBC_SHA256);
        cipherMap.put("TLS_RSA_WITH_AES_256_CBC_SHA256",
                SSLSocket.TLS_RSA_WITH_AES_256_CBC_SHA256);
        cipherMap.put("TLS_RSA_WITH_SEED_CBC_SHA",
                SSLSocket.TLS_RSA_WITH_SEED_CBC_SHA);
        cipherMap.put("TLS_RSA_WITH_AES_128_GCM_SHA256",
                SSLSocket.TLS_RSA_WITH_AES_128_GCM_SHA256);
        cipherMap.put("TLS_DHE_RSA_WITH_AES_128_GCM_SHA256",
                SSLSocket.TLS_DHE_RSA_WITH_AES_128_GCM_SHA256);
        cipherMap.put("TLS_DHE_DSS_WITH_AES_128_GCM_SHA256",
                SSLSocket.TLS_DHE_DSS_WITH_AES_128_GCM_SHA256);
        cipherMap.put("TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256",
                SSLSocket.TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256);
        cipherMap.put("TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256",
                SSLSocket.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256);
        cipherMap.put("TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256",
                SSLSocket.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256);
        cipherMap.put("TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
                SSLSocket.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256);
/* unsupported by nss
        cipherMap.put("TLS_ECDH_ECDSA_WITH_AES_128_GCM_SHA256",
                SSLSocket.TLS_ECDH_ECDSA_WITH_AES_128_GCM_SHA256);
        cipherMap.put("TLS_ECDH_RSA_WITH_AES_128_GCM_SHA256",
                SSLSocket.TLS_ECDH_RSA_WITH_AES_128_GCM_SHA256);
*/

        cipherMap.put("TLS_ECDH_RSA_WITH_AES_256_CBC_SHA",
                SSLSocket.TLS_ECDH_RSA_WITH_AES_256_CBC_SHA);
        cipherMap.put("TLS_ECDH_RSA_WITH_AES_128_CBC_SHA",
                SSLSocket.TLS_ECDH_RSA_WITH_AES_128_CBC_SHA);
        cipherMap.put("TLS_ECDH_RSA_WITH_3DES_EDE_CBC_SHA",
                SSLSocket.TLS_ECDH_RSA_WITH_3DES_EDE_CBC_SHA);
    }

    private static HashMap<Integer, String> eccCipherMap = new HashMap<Integer, String>();
    static {
        eccCipherMap.put(SSLSocket.TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA,
                "TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA");
        eccCipherMap.put(SSLSocket.TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA,
                "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA");
        eccCipherMap.put(SSLSocket.TLS_ECDH_RSA_WITH_AES_256_CBC_SHA,
                "TLS_ECDH_RSA_WITH_AES_256_CBC_SHA");
        eccCipherMap.put(SSLSocket.TLS_ECDH_ECDSA_WITH_AES_256_CBC_SHA,
                "TLS_ECDH_ECDSA_WITH_AES_256_CBC_SHA");
        eccCipherMap.put(SSLSocket.TLS_ECDHE_ECDSA_WITH_RC4_128_SHA,
                "TLS_ECDHE_ECDSA_WITH_RC4_128_SHA");
        eccCipherMap.put(SSLSocket.TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA,
                "TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA");
        eccCipherMap.put(SSLSocket.TLS_ECDHE_RSA_WITH_RC4_128_SHA,
                "TLS_ECDHE_RSA_WITH_RC4_128_SHA");
        eccCipherMap.put(SSLSocket.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA,
                "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA");
        eccCipherMap.put(SSLSocket.TLS_ECDH_RSA_WITH_RC4_128_SHA,
                "TLS_ECDH_RSA_WITH_RC4_128_SHA");
        eccCipherMap.put(SSLSocket.TLS_ECDH_RSA_WITH_AES_128_CBC_SHA,
                "TLS_ECDH_RSA_WITH_AES_128_CBC_SHA");
        eccCipherMap.put(SSLSocket.TLS_ECDH_ECDSA_WITH_RC4_128_SHA,
                "TLS_ECDH_ECDSA_WITH_RC4_128_SHA");
        eccCipherMap.put(SSLSocket.TLS_ECDH_ECDSA_WITH_AES_128_CBC_SHA,
                "TLS_ECDH_ECDSA_WITH_AES_128_CBC_SHA");
        eccCipherMap.put(SSLSocket.TLS_ECDHE_ECDSA_WITH_3DES_EDE_CBC_SHA,
                "TLS_ECDHE_ECDSA_WITH_3DES_EDE_CBC_SHA");
        eccCipherMap.put(SSLSocket.TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA,
                "TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA");
        eccCipherMap.put(SSLSocket.TLS_ECDH_RSA_WITH_3DES_EDE_CBC_SHA,
                "TLS_ECDH_RSA_WITH_3DES_EDE_CBC_SHA");
        eccCipherMap.put(SSLSocket.TLS_ECDH_ECDSA_WITH_3DES_EDE_CBC_SHA,
                "TLS_ECDH_ECDSA_WITH_3DES_EDE_CBC_SHA");
        eccCipherMap.put(SSLSocket.TLS_ECDHE_ECDSA_WITH_NULL_SHA,
                "TLS_ECDHE_ECDSA_WITH_NULL_SHA");
        eccCipherMap.put(SSLSocket.TLS_ECDHE_RSA_WITH_NULL_SHA,
                "TLS_ECDHE_RSA_WITH_NULL_SHA");
        eccCipherMap.put(SSLSocket.TLS_ECDH_RSA_WITH_NULL_SHA,
                "TLS_ECDH_RSA_WITH_NULL_SHA");
        eccCipherMap.put(SSLSocket.TLS_ECDH_ECDSA_WITH_NULL_SHA,
                "TLS_ECDH_ECDSA_WITH_NULL_SHA");
/* unsupported by nss
        eccCipherMap.put(SSLSocket.TLS_ECDH_ECDSA_WITH_AES_128_GCM_SHA256,
                "TLS_ECDH_ECDSA_WITH_AES_128_GCM_SHA256");
*/
    }

    TomcatJSS tomcatjss = TomcatJSS.getInstance();

    private AbstractEndpoint<?> endpoint;
    private Properties config;

    protected static boolean ocspConfigured = false;
    protected boolean requireClientAuth = false;
    protected boolean wantClientAuth = false;
    private boolean initialized = false;
    private String serverCertNick = "";

    private boolean mStrictCiphers = false;

    public JSSSocketFactory(AbstractEndpoint<?> endpoint) {
        this.endpoint = endpoint;
    }

    public JSSSocketFactory(AbstractEndpoint<?> endpoint, Properties config) {
        this.endpoint = endpoint;
        this.config = config;
    }

    public void setSSLCiphers(String attr) throws SocketException, IOException {
        String ciphers = getProperty(attr);
        if (StringUtils.isEmpty(ciphers)) {
            logger.fine("JSSSocketFactory: setSSLCiphers: " + attr + " not found");
            return;
        }

        logger.fine("JSSSocketFactory: Processing " + attr + ":");
        StringTokenizer st = new StringTokenizer(ciphers, ", ");
        while (st.hasMoreTokens()) {
            String cipherstr = st.nextToken();
            logger.fine("JSSSocketFactory:  - " + cipherstr);

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

            if (text.startsWith("0x") || text.startsWith("0X")) {
                // this allows us to specify new ciphers
                try {
                    cipherid = Integer.parseInt(text.substring(2), 16);
                } catch (Exception e) {
                    logger.severe("Error: SSL cipher \"" + text
                            + "\" cannot be read as an integer");
                    continue;
                }
            } else {
                Object mapValue;

                mapValue = cipherMap.get(text);
                if (mapValue == null) {
                    cipherid = 0;
                } else {
                    cipherid = (Integer) mapValue;
                }
            }
            if (cipherid != 0) {
                try {
                    logger.fine("JSSSocketFactory: setCipherPreferenceDefault:  " + cipherstr
                            + ": 0x" + Integer.toHexString(cipherid));
                    SSLSocket.setCipherPreferenceDefault(cipherid, state);
                } catch (Exception e) {
                    logger.warning("JSSSocketFactory: SSLSocket.setCipherPreferenceDefault exception:" +e);
                    if (eccCipherMap.containsKey(cipherid)) {
                        logger.warning("Warning: SSL ECC cipher \""
                                        + text
                                        + "\" unsupported by NSS. "
                                        + "This is probably O.K. unless ECC support has been installed.");
                    } else {
                        logger.severe("Error: SSL cipher \"" + text
                                + "\" unsupported by NSS");
                    }
                }
            } else {
                logger.severe("Error: SSL cipher \"" + text
                        + "\" not recognized by tomcatjss");
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

            tomcatjss.init();
            logger.fine("JSSSocketFactory: init: tokens initialized/logged in");

            CryptoManager manager = CryptoManager.getInstance();

            // MUST look for "clientauth" (ALL lowercase) since "clientAuth"
            // (camel case) has already been processed by Tomcat 7
            String clientAuthStr = getProperty("clientauth");
            if (clientAuthStr == null) {
                logger.fine("JSSSocketFactory: init: \"clientauth\" not found, default to want.");
                clientAuthStr = "want";
            }
            File file = null;
            try {
                String serverCertNickFile = getProperty("serverCertNickFile");
                if (serverCertNickFile == null) {
                    throw new IOException("serverCertNickFile not specified");
                }
                tomcatjss.setServerCertNickFile(serverCertNickFile);

                logger.fine("JSSSocketFactory: init: got serverCertNickFile"
                        + serverCertNickFile);
                file = new File(serverCertNickFile);
                FileInputStream in = new FileInputStream(file);
                BufferedReader d = new BufferedReader(new InputStreamReader(in));
                do {
                    serverCertNick = d.readLine();
                    logger.fine("JSSSocketFactory: init: got line " + serverCertNick);
                    if (serverCertNick == null) {
                        in.close();
                        d.close();
                        throw new IOException(
                                "JSSSocketFactory: error loading serverCertNickFile");
                    }
                    // handle comments or blank lines
                    if (serverCertNick.trim().startsWith("#")
                            || serverCertNick.trim().equals("")) {
                        serverCertNick = null;
                    }
                } while (serverCertNick == null);
                logger.fine("JSSSocketFactory: init: found nickname=" + serverCertNick);
                in.close();
                d.close();
            } catch (Exception e) {
                logger.severe("JSSSocketFactory: init: Exception caught: " + e);
                throw new IOException(
                        "JSSSocketFactory: no serverCertNickFile defined");
            }

            // serverCertNick = (String)getProperty("serverCert");
            if (clientAuthStr.equalsIgnoreCase("true")
                    || clientAuthStr.equalsIgnoreCase("yes")) {
                requireClientAuth = true;
            } else if (clientAuthStr.equalsIgnoreCase("want")) {
                wantClientAuth = true;
            }
            logger.fine("JSSSocketFActory: init: requireClientAuth "
                    + requireClientAuth + " wantClientAuth " + wantClientAuth
                    + " ocspConfigured " + ocspConfigured);
            if (requireClientAuth == true || wantClientAuth == true
                    && ocspConfigured == false) {
                logger.fine("JSSSocketFactory: init: checking for OCSP settings.");
                boolean enableOCSP = false;
                String doOCSP = getProperty("enableOCSP");

                logger.fine("JSSSocketFactory: init: doOCSP flag:" + doOCSP);

                if (doOCSP != null && doOCSP.equalsIgnoreCase("true")) {
                    enableOCSP = true;
                }

                logger.fine("JSSSocketFactory: init: enableOCSP " + enableOCSP);

                if (enableOCSP == true) {
                    String ocspResponderURL = getProperty("ocspResponderURL");
                    logger.fine("JSSSocketFactory: init: ocspResponderURL " + ocspResponderURL);
                    String ocspResponderCertNickname = getProperty(
                            "ocspResponderCertNickname");
                    logger.fine("JSSSocketFactory: init: ocspResponderCertNickname " + ocspResponderCertNickname);
                    if (StringUtils.isNotEmpty(ocspResponderURL) &&
                            StringUtils.isNotEmpty(ocspResponderCertNickname)) {

                        ocspConfigured = true;
                        try {
                            manager.configureOCSP(true, ocspResponderURL,
                                    ocspResponderCertNickname);
                            int ocspCacheSize_i = 1000;
                            int ocspMinCacheEntryDuration_i = 3600;
                            int ocspMaxCacheEntryDuration_i = 86400;

                            String ocspCacheSize = getProperty("ocspCacheSize");
                            String ocspMinCacheEntryDuration = getProperty("ocspMinCacheEntryDuration");
                            String ocspMaxCacheEntryDuration = getProperty("ocspMaxCacheEntryDuration");

                            if (ocspCacheSize != null
                                    || ocspMinCacheEntryDuration != null
                                    || ocspMaxCacheEntryDuration != null) {
                                // not specified then takes the default
                                if (ocspCacheSize != null) {
                                    logger.fine("JSSSocketFactory: init: ocspCacheSize= "
                                            + ocspCacheSize);
                                    ocspCacheSize_i = Integer.parseInt(ocspCacheSize);
                                }
                                if (ocspMinCacheEntryDuration != null) {
                                    logger.fine("JSSSocketFactory: init: ocspMinCacheEntryDuration= "
                                            + ocspMinCacheEntryDuration);
                                    ocspMinCacheEntryDuration_i = Integer.parseInt(ocspMinCacheEntryDuration);
                                }
                                if (ocspMaxCacheEntryDuration != null) {
                                    logger.fine("JSSSocketFactory: init: ocspMaxCacheEntryDuration= "
                                            + ocspMaxCacheEntryDuration);
                                    ocspMaxCacheEntryDuration_i = Integer.parseInt(ocspMaxCacheEntryDuration);
                                }
                                manager.OCSPCacheSettings(ocspCacheSize_i,
                                        ocspMinCacheEntryDuration_i,
                                        ocspMaxCacheEntryDuration_i);
                            }

                            // defualt to 60 seconds;
                            String ocspTimeout = getProperty("ocspTimeout");
                            if (ocspTimeout != null) {
                                logger.fine("JSSSocketFactory: init: ocspTimeout=" + ocspTimeout);
                                int ocspTimeout_i = Integer.parseInt(ocspTimeout);
                                if (ocspTimeout_i < 0)
                                    ocspTimeout_i = 60;
                                manager.setOCSPTimeout(ocspTimeout_i);
                            }
                        } catch (java.security.GeneralSecurityException e) {
                            ocspConfigured = false;
                            logger.severe("JSSSocketFactory: init: error initializing OCSP e: " + e);
                            throw new java.security.GeneralSecurityException(
                                    "Error setting up OCSP. Check configuraion!");
                        } catch (java.lang.NumberFormatException e) {
                            logger.severe("JSSSocketFactory: init: error setting OCSP cache e: " + e);
                            throw new java.lang.NumberFormatException(
                                    "Error setting OCSP cache. Check configuraion!");
                        }
                    } else {
                        logger.severe("JSSSocketFactory: init: error ocsp misconfigured!");
                        throw new java.security.GeneralSecurityException(
                                "Error setting up OCSP. Check configuration!");
                    }
                }
            }
            // serverCertNick = "Server-Cert cert-tks";
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

            TomcatJSS tomcatjss = TomcatJSS.getInstance();
            asock.addSocketListener(tomcatjss);

            if (wantClientAuth || requireClientAuth) {
                asock.requestClientAuth(true);
                if (requireClientAuth == true) {
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
        if (!initialized)
            init();
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
            if (wantClientAuth || requireClientAuth) {
                s.requestClientAuth(true);
                if (requireClientAuth == true) {
                    s.requireClientAuth(SSLSocket.SSL_REQUIRE_ALWAYS);
                } else {
                    s.requireClientAuth(SSLSocket.SSL_REQUIRE_NEVER);
                }
            }
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
