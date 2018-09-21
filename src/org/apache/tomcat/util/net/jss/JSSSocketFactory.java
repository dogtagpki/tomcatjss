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
import java.io.FileWriter;
import java.io.IOException;
import java.io.InputStreamReader;
import java.net.InetAddress;
import java.net.ServerSocket;
import java.net.Socket;
import java.net.SocketException;
import java.security.GeneralSecurityException;
import java.text.SimpleDateFormat;
import java.util.Date;
import java.util.Enumeration;
import java.util.HashMap;
import java.util.Properties;
import java.util.StringTokenizer;

import javax.net.ssl.KeyManager;
import javax.net.ssl.SSLContext;
import javax.net.ssl.TrustManager;

import org.apache.commons.lang.StringUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
// Imports required to "implement" Tomcat 7 Interface
import org.apache.tomcat.util.net.AbstractEndpoint;
import org.mozilla.jss.CertDatabaseException;
import org.mozilla.jss.CryptoManager;
import org.mozilla.jss.CryptoManager.NotInitializedException;
import org.mozilla.jss.KeyDatabaseException;
import org.mozilla.jss.NoSuchTokenException;
import org.mozilla.jss.crypto.AlreadyInitializedException;
import org.mozilla.jss.crypto.CryptoToken;
import org.mozilla.jss.crypto.TokenException;
import org.mozilla.jss.ssl.SSLServerSocket;
import org.mozilla.jss.ssl.SSLSocket;
import org.mozilla.jss.util.IncorrectPasswordException;
import org.mozilla.jss.util.Password;

public class JSSSocketFactory implements
        org.apache.tomcat.util.net.ServerSocketFactory,
        org.apache.tomcat.util.net.SSLUtil {

    static Log logger = LogFactory.getLog(JSSSocketFactory.class);

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

        // TLS_*_SHA384
        cipherMap.put("TLS_RSA_WITH_AES_256_GCM_SHA384",
                SSLSocket.TLS_RSA_WITH_AES_256_GCM_SHA384);
        cipherMap.put("TLS_DHE_RSA_WITH_AES_256_GCM_SHA384",
                SSLSocket.TLS_DHE_RSA_WITH_AES_256_GCM_SHA384);
        cipherMap.put("TLS_DHE_DSS_WITH_AES_256_GCM_SHA384",
                SSLSocket.TLS_DHE_DSS_WITH_AES_256_GCM_SHA384);
        cipherMap.put("TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384",
                SSLSocket.TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384);
        cipherMap.put("TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384",
                SSLSocket.TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384);
        cipherMap.put("TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384",
                SSLSocket.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384);
        cipherMap.put("TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384",
                SSLSocket.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384);
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

        // TLS_*_SHA384
        eccCipherMap.put(SSLSocket.TLS_RSA_WITH_AES_256_GCM_SHA384,
                "TLS_RSA_WITH_AES_256_GCM_SHA384");
        eccCipherMap.put(SSLSocket.TLS_DHE_RSA_WITH_AES_256_GCM_SHA384,
                "TLS_DHE_RSA_WITH_AES_256_GCM_SHA384");
        eccCipherMap.put(SSLSocket.TLS_DHE_DSS_WITH_AES_256_GCM_SHA384,
                "TLS_DHE_DSS_WITH_AES_256_GCM_SHA384");
        eccCipherMap.put(SSLSocket.TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384,
                "TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384");
        eccCipherMap.put(SSLSocket.TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384,
                "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384");
        eccCipherMap.put(SSLSocket.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
                "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384");
        eccCipherMap.put(SSLSocket.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
                "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384");
    }

    private AbstractEndpoint endpoint;
    private Properties config;

    static org.apache.commons.logging.Log log = org.apache.commons.logging.LogFactory
            .getLog(JSSSocketFactory.class);

    protected static boolean ocspConfigured = false;
    protected boolean requireClientAuth = false;
    protected boolean wantClientAuth = false;
    private boolean initialized = false;
    private String serverCertNick = "";
    private String mServerCertNickPath = "";
    private String mPwdPath = "";
    private String mPwdClass = "";
    private static final String DATE_PATTERN = "dd/MMM/yyyy:HH:mm:ss";
    private static SimpleDateFormat timeStampFormat = new SimpleDateFormat(
            DATE_PATTERN);
    FileWriter debugFile = null;
    boolean debug = false;
    private IPasswordStore mPasswordStore = null;
    private boolean mStrictCiphers = false;
    private static final int MAX_PW_ATTEMPTS = 3;

    public JSSSocketFactory(AbstractEndpoint endpoint) {
        this.endpoint = endpoint;
    }

    public JSSSocketFactory(AbstractEndpoint endpoint, Properties config) {
        this.endpoint = endpoint;
        this.config = config;
    }

    private void debugWrite(String m) throws IOException {
        if (debug) {
            String timeStamp = timeStampFormat.format(new Date());
            String threadName = Thread.currentThread().getName();
            debugFile.write("[" + timeStamp + "][" + threadName + "]: " + m);
        }
    }

    public void setSSLCiphers(String attr) throws SocketException, IOException {
        String ciphers = getProperty(attr);
        if (StringUtils.isEmpty(ciphers)) {
            debugWrite("JSSSocketFactory setSSLCiphers: " + attr + " not found");
            return;
        }

        logger.debug("Processing " + attr + ":");
        StringTokenizer st = new StringTokenizer(ciphers, ", ");
        while (st.hasMoreTokens()) {
            String cipherstr = st.nextToken();
            logger.debug(" - " + cipherstr);

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
                    System.err.println("Error: SSL cipher \"\"" + text
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
                    debugWrite("JSSSocketFactory setSSLCiphers: setting: " + cipherstr
                            + ": 0x" + Integer.toHexString(cipherid) + "\n");
                    SSLSocket.setCipherPreferenceDefault(cipherid, state);
                    debugWrite("JSSSocketFactory setSSLCiphers: done setting: " + cipherstr
                            + ": 0x" + Integer.toHexString(cipherid) + "\n");
                } catch (Exception e) {
                    String errMsg = "SSLSocket.setCipherPreferenceDefault exception on: " + cipherstr + " : " +e;
                    System.err.println(errMsg);
                    debugWrite("JSSSocketFactory setSSLCiphers: " + errMsg);
                    if (eccCipherMap.containsKey(cipherid)) {
                        debugWrite("JSSSocketFactory setSSLCiphers: Warning: cipher exists in eccCipherMap");
                        System.err
                                .println("Warning: SSL ECC cipher \""
                                        + text
                                        + "\" unsupported by NSS. "
                                        + "This is probably O.K. unless ECC support has been installed.");
                    } else {
                        debugWrite("JSSSocketFactory setSSLCiphers: Error: cipher does not exist in eccCipherMap");
                        System.err.println("Error: SSL cipher \"" + text
                                + "\" unsupported by NSS");
                    }
                }
            } else {
                debugWrite("JSSSocketFactory setSSLCiphers: Error: cipher not recognized by tomcatjss");
                System.err.println("Error: SSL cipher \"" + text
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
            debugWrite("no sslOptions specified");
            return;
        }

        logger.debug("Processing sslOptions:");
        StringTokenizer st = new StringTokenizer(options, ", ");
        while (st.hasMoreTokens()) {
            String option = st.nextToken();
            logger.debug(" - " + option);

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

                debugWrite("JSSSocketFactory unsetSSLCiphers - turning off '0x"
                        + Integer.toHexString(ciphers[i]) + "'\n");
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
            debugWrite("JSSSocketFactory setSSLversionRangeDefault- SSL Version Range format error: "
                    + sslVersionRange_s + "\n");
            throw new SocketException(
                    "tomcatjss: setSSLversionRangeDefault format error");
        }
        String min_s = sslVersionRange[0];
        String max_s = sslVersionRange[1];
        int min = getSSLVersionRangeEnum(min_s);
        int max = getSSLVersionRangeEnum(max_s);
        if ((min == -1) || (max == -1)) {
            debugWrite("JSSSocketFactory setSSLversionRangeDefault- SSL Version Range format error: "
                    + sslVersionRange_s + "\n");
            throw new SocketException(
                    "tomcatjss: setSSLversionRangeDefault format error");
        }

        debugWrite("JSSSocketFactory setSSLversionRangeDefault- SSL Version Range set to min="
                + min + " max = " + max + "\n");
        org.mozilla.jss.ssl.SSLSocket.SSLVersionRange range = new org.mozilla.jss.ssl.SSLSocket.SSLVersionRange(
                min, max);

        SSLSocket.setSSLVersionRangeDefault(protoVariant, range);
        debugWrite("JSSSocketFactory setSSLversionRangeDefault- variant set\n");
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
        // debug enabled?
        String deb = getProperty("debug");
        if (StringUtils.equals(deb, "true")) {
            debug = true;
            debugFile = new FileWriter("/tmp/tomcatjss.log", true);
            debugWrite("JSSSocketFactory init - debug is on\n");
        }

        try {
            initializePasswordStore();

            CryptoManager manager = getCryptoManager();

            // JSSSocketFactory init - handle crypto tokens
            debugWrite("JSSSocketFactory init - about to handle crypto unit logins\n");

            //log into tokens
            Enumeration<String> tags = mPasswordStore.getTags();
            while (tags.hasMoreElements()) {
                String tag = tags.nextElement();
                if (tag.equals("internal") || (tag.startsWith("hardware-"))) {
                    debugWrite("JSSSocketFactory init - tag name=" + tag + "\n");
                    logIntoToken(manager, tag);
                }
            }
            debugWrite("JSSSocketFactory init - tokens initialized/logged in\n");

            // MUST look for "clientauth" (ALL lowercase) since "clientAuth"
            // (camel case) has already been processed by Tomcat 7
            String clientAuthStr = getProperty("clientauth");
            if (clientAuthStr == null) {
                debugWrite("JSSSocketFactory init - \"clientauth\" not found, default to want.");
                clientAuthStr = "want";
            }
            File file = null;
            try {
                mServerCertNickPath = getProperty("serverCertNickFile");
                if (mServerCertNickPath == null) {
                    throw new IOException("serverCertNickFile not specified");
                }
                debugWrite("JSSSocketFactory init - got serverCertNickFile"
                        + mServerCertNickPath + "\n");
                file = new File(mServerCertNickPath);
                FileInputStream in = new FileInputStream(mServerCertNickPath);
                BufferedReader d = new BufferedReader(new InputStreamReader(in));
                do {
                    serverCertNick = d.readLine();
                    debugWrite("JSSSocketFactory init - got line "
                            + serverCertNick + "\n");
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
                debugWrite("JSSSocketFactory init - found nickname="
                        + serverCertNick + "\n");
                in.close();
                d.close();
            } catch (Exception e) {
                debugWrite("JSSSocketFactory init - Exception caught: "
                        + e.toString() + "\n");
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
            debugWrite("JSSSocketFActory init - requireClientAuth "
                    + requireClientAuth + " wantClientAuth " + wantClientAuth
                    + " ocspConfigured " + ocspConfigured);
            if (requireClientAuth == true || wantClientAuth == true
                    && ocspConfigured == false) {
                debugWrite("JSSSocketFactory init - checking for OCSP settings. \n");
                boolean enableOCSP = false;
                String doOCSP = getProperty("enableOCSP");

                debugWrite("JSSSocketFactory init - doOCSP flag:" + doOCSP + " \n");

                if (doOCSP != null && doOCSP.equalsIgnoreCase("true")) {
                    enableOCSP = true;
                }

                debugWrite("JSSSocketFactory init - enableOCSP " + enableOCSP
                        + "\n");

                if (enableOCSP == true) {
                    String ocspResponderURL = getProperty("ocspResponderURL");
                    debugWrite("JSSSocketFactory init - ocspResponderURL "
                            + ocspResponderURL + "\n");
                    String ocspResponderCertNickname = getProperty(
                            "ocspResponderCertNickname");
                    debugWrite("JSSSocketFactory init - ocspResponderCertNickname"
                            + ocspResponderCertNickname + "\n");

                    if ((StringUtils.isNotEmpty(ocspResponderURL) &&
                         	StringUtils.isNotEmpty(ocspResponderCertNickname))  ||
                        	(StringUtils.isEmpty(ocspResponderURL)
                            	&& StringUtils.isEmpty(ocspResponderCertNickname))) {

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
                                    debugWrite("JSSSocketFactory init - ocspCacheSize= "
                                            + ocspCacheSize + "\n");
                                    ocspCacheSize_i = Integer.parseInt(ocspCacheSize);
                                }
                                if (ocspMinCacheEntryDuration != null) {
                                    debugWrite("JSSSocketFactory init - ocspMinCacheEntryDuration= "
                                            + ocspMinCacheEntryDuration + "\n");
                                    ocspMinCacheEntryDuration_i = Integer.parseInt(ocspMinCacheEntryDuration);
                                }
                                if (ocspMaxCacheEntryDuration != null) {
                                    debugWrite("JSSSocketFactory init - ocspMaxCacheEntryDuration= "
                                            + ocspMaxCacheEntryDuration + "\n");
                                    ocspMaxCacheEntryDuration_i = Integer.parseInt(ocspMaxCacheEntryDuration);
                                }
                                manager.OCSPCacheSettings(ocspCacheSize_i,
                                        ocspMinCacheEntryDuration_i,
                                        ocspMaxCacheEntryDuration_i);
                            }

                            // defualt to 60 seconds;
                            String ocspTimeout = getProperty("ocspTimeout");
                            if (ocspTimeout != null) {
                                debugWrite("JSSSocketFactory init - ocspTimeout= \n" + ocspTimeout);
                                int ocspTimeout_i = Integer.parseInt(ocspTimeout);
                                if (ocspTimeout_i < 0)
                                    ocspTimeout_i = 60;
                                manager.setOCSPTimeout(ocspTimeout_i);
                            }
                        } catch (java.security.GeneralSecurityException e) {
                            ocspConfigured = false;
                            debugWrite("JSSSocketFactory init - error initializing OCSP e: "
                                    + e.toString() + "\n");
                            throw new java.security.GeneralSecurityException(
                                    "Error setting up OCSP. Check configuraion!");
                        } catch (java.lang.NumberFormatException e) {
                            debugWrite("JSSSocketFactory init - error setting OCSP cache e: "
                                    + e.toString() + "\n");
                            throw new java.lang.NumberFormatException(
                                    "Error setting OCSP cache. Check configuraion!");
                        }
                    } else {
                        debugWrite("JSSSocketFactory init - error ocsp misconfigured! \n");
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
                debugWrite("SSSocketFactory init - before setSSLCiphers, strictCiphers is true\n");
                unsetSSLCiphers();
            } else {
                debugWrite("SSSocketFactory init - before setSSLCiphers, strictCiphers is false\n");
            }

            String sslVersionRangeStream = getProperty("sslVersionRangeStream");
            if ((sslVersionRangeStream != null)
                    && !sslVersionRangeStream.equals("")) {
                debugWrite("SSSocketFactory init - calling setSSLVersionRangeDefault() for type STREAM\n");
                setSSLVersionRangeDefault(
                        org.mozilla.jss.ssl.SSLSocket.SSLProtocolVariant.STREAM,
                        sslVersionRangeStream);
                debugWrite("SSSocketFactory init - after setSSLVersionRangeDefault() for type STREAM\n");
            }

            String sslVersionRangeDatagram = getProperty("sslVersionRangeDatagram");
            if ((sslVersionRangeDatagram != null)
                    && !sslVersionRangeDatagram.equals("")) {
                debugWrite("SSSocketFactory init - calling setSSLVersionRangeDefault() for type DATA_GRAM\n");
                setSSLVersionRangeDefault(
                        org.mozilla.jss.ssl.SSLSocket.SSLProtocolVariant.DATA_GRAM,
                        sslVersionRangeDatagram);
                debugWrite("SSSocketFactory init - after setSSLVersionRangeDefault() for type DATA_GRAM\n");
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
                debugWrite("SSSocketFactory init - calling setSSLCiphers() honoring only sslRangeCiphers\n");
                setSSLCiphers("sslRangeCiphers");
                debugWrite("SSSocketFactory init - after setSSLCiphers() honoring only sslRangeCiphers\n");
            } else {
                debugWrite("SSSocketFactory init - calling setSSLOptions()\n");
                setSSLOptions();
                debugWrite("SSSocketFactory init - after setSSLOptions()\n");
            }

        } catch (Exception ex) {
            debugWrite("JSSSocketFactory init - exception thrown:"
                    + ex.toString() + "\n");
            System.err.println("JSSSocketFactory init - exception thrown:"
                    + ex.toString() + "\n");
            // The idea is, if admin take the trouble to configure the
            // ocsp cache, and made a mistake, we want to make server
            // unavailable until they get it right
            if ((ex instanceof java.security.GeneralSecurityException)
                    || (ex instanceof java.lang.NumberFormatException))
                throw new IOException(ex.toString());
        } finally {
            if (debugFile != null)
                debugFile.close();
        }
    }

    private CryptoToken getToken(String tag, CryptoManager manager) throws IOException, NoSuchTokenException {
        CryptoToken token = null;
        if (tag.equals("internal")) {
            debugWrite("JSSSocketFactory init - got internal software token\n");
            token = manager.getInternalKeyStorageToken();
        } else if (tag.startsWith("hardware-")) {
            debugWrite("JSSSocketFactory init - got hardware\n");

            String tokenName = tag.substring(9);
            debugWrite("JSSSocketFactory init - tokenName=" + tokenName + "\n");

            // find the hsm and log in
            token = manager.getTokenByName(tokenName);
        } else {
            // non-token password entry
        }
        return token;
    }

    private void initializePasswordStore() throws InstantiationException, IllegalAccessException,
            ClassNotFoundException, IOException {
        mPwdClass = getProperty("passwordClass");
        if (mPwdClass == null) {
            throw new IOException("Misconfiguration: passwordClass is not defined");
        }
        mPwdPath = getProperty("passwordFile");

        mPasswordStore = (IPasswordStore) Class.forName(mPwdClass).newInstance();
        debugWrite("JSSSocketFactory init - password reader initialized\n");

        // initialize the password store
        mPasswordStore.init(mPwdPath);
    }

    private CryptoManager getCryptoManager() throws KeyDatabaseException, CertDatabaseException,
            GeneralSecurityException, NotInitializedException, IOException {
        String certDir = getProperty("certdbDir");
        if (certDir == null) {
            throw new IOException("Misconfiguration: certdir not defined");
        }
        CryptoManager.InitializationValues vals = new CryptoManager.InitializationValues(
                certDir, "", "", "secmod.db");

        vals.removeSunProvider = false;
        vals.installJSSProvider = true;
        try {
            CryptoManager.initialize(vals);
        } catch (AlreadyInitializedException ee) {
            // do nothing
        }
        CryptoManager manager = CryptoManager.getInstance();
        return manager;
    }

    private void logIntoToken(CryptoManager manager, String tag) throws IOException,
            TokenException {
        String pwd;
        Password pw = null;
        int iteration = 0;

        CryptoToken token = null;
        try {
            token = getToken(tag, manager);
        } catch (NoSuchTokenException e) {
            debugWrite("token for " + tag + " not found by CryptoManager. Not logging in.");
            return;
        }

        do {
            debugWrite("JSSSocketFactory init - iteration=" + iteration + "\n");
            pwd = mPasswordStore.getPassword(tag, iteration);
            if (pwd == null) {
                debugWrite("JSSSocketFactory init - no pwd gotten\n");
                return;
            }

            pw = new Password(pwd.toCharArray());

            if (!token.isLoggedIn()) {
                debugWrite("JSSSocketFactory init -not logged in...about to log in\n");
                try {
                    token.login(pw);
                    break;
                } catch (IncorrectPasswordException e) {
                    debugWrite("Incorrect password received");
                    iteration ++;
                    if (iteration == MAX_PW_ATTEMPTS) {
                        debugWrite("Failed to log into token:" + tag);
                    }
                }
            } else {
                debugWrite("JSSSocketFactory init - already logged in\n");
                break;
            }
        } while (iteration < MAX_PW_ATTEMPTS);
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
