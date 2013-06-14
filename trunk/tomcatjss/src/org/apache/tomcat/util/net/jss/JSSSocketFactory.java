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

import java.util.*;
import java.text.SimpleDateFormat;
import java.lang.Thread;
import java.lang.NumberFormatException;
import org.mozilla.jss.ssl.*;
import org.mozilla.jss.crypto.*;
import org.mozilla.jss.CryptoManager;
import org.mozilla.jss.util.*;
import org.mozilla.jss.pkcs11.*;
import java.net.*;
import java.io.*;

// Imports required to "implement" Tomcat 7 Interface
import org.apache.tomcat.util.net.AbstractEndpoint;
import javax.net.ssl.KeyManager;
import javax.net.ssl.SSLContext;
import javax.net.ssl.TrustManager;

public class JSSSocketFactory
  implements org.apache.tomcat.util.net.ServerSocketFactory,
             org.apache.tomcat.util.net.SSLUtil {

    private static HashMap cipherMap = new HashMap();
    static {
        // SSLv2
        cipherMap.put("SSL2_RC4_128_WITH_MD5",                   SSLSocket.SSL2_RC4_128_WITH_MD5);
        cipherMap.put("SSL2_RC4_128_EXPORT40_WITH_MD5",          SSLSocket.SSL2_RC4_128_EXPORT40_WITH_MD5);
        cipherMap.put("SSL2_RC2_128_CBC_WITH_MD5",               SSLSocket.SSL2_RC2_128_CBC_WITH_MD5);
        cipherMap.put("SSL2_RC2_128_CBC_EXPORT40_WITH_MD5",      SSLSocket.SSL2_RC2_128_CBC_EXPORT40_WITH_MD5);
        cipherMap.put("SSL2_IDEA_128_CBC_WITH_MD5",              SSLSocket.SSL2_IDEA_128_CBC_WITH_MD5);
        cipherMap.put("SSL2_DES_64_CBC_WITH_MD5",                SSLSocket.SSL2_DES_64_CBC_WITH_MD5);
        cipherMap.put("SSL2_DES_192_EDE3_CBC_WITH_MD5",          SSLSocket.SSL2_DES_192_EDE3_CBC_WITH_MD5);

        // SSLv3
        cipherMap.put("SSL3_RSA_WITH_NULL_MD5",                  SSLSocket.SSL3_RSA_WITH_NULL_MD5);
        cipherMap.put("SSL3_RSA_WITH_NULL_SHA",                  SSLSocket.SSL3_RSA_WITH_NULL_SHA);
        cipherMap.put("SSL3_RSA_EXPORT_WITH_RC4_40_MD5",         SSLSocket.SSL3_RSA_EXPORT_WITH_RC4_40_MD5);
        cipherMap.put("SSL3_RSA_WITH_RC4_128_MD5",               SSLSocket.SSL3_RSA_WITH_RC4_128_MD5);
        cipherMap.put("SSL3_RSA_WITH_RC4_128_SHA",               SSLSocket.SSL3_RSA_WITH_RC4_128_SHA);
        cipherMap.put("SSL3_RSA_EXPORT_WITH_RC2_CBC_40_MD5",     SSLSocket.SSL3_RSA_EXPORT_WITH_RC2_CBC_40_MD5);
        cipherMap.put("SSL3_RSA_WITH_IDEA_CBC_SHA",              SSLSocket.SSL3_RSA_WITH_IDEA_CBC_SHA);
        cipherMap.put("SSL3_RSA_EXPORT_WITH_DES40_CBC_SHA",      SSLSocket.SSL3_RSA_EXPORT_WITH_DES40_CBC_SHA);
        cipherMap.put("SSL3_RSA_WITH_DES_CBC_SHA",               SSLSocket.SSL3_RSA_WITH_DES_CBC_SHA);
        cipherMap.put("SSL3_RSA_WITH_3DES_EDE_CBC_SHA",          SSLSocket.SSL3_RSA_WITH_3DES_EDE_CBC_SHA);
                                                                                
        cipherMap.put("SSL3_DH_DSS_EXPORT_WITH_DES40_CBC_SHA",   SSLSocket.SSL3_DH_DSS_EXPORT_WITH_DES40_CBC_SHA);
        cipherMap.put("SSL3_DH_DSS_WITH_DES_CBC_SHA",            SSLSocket.SSL3_DH_DSS_WITH_DES_CBC_SHA);
        cipherMap.put("SSL3_DH_DSS_WITH_3DES_EDE_CBC_SHA",       SSLSocket.SSL3_DH_DSS_WITH_3DES_EDE_CBC_SHA);
        cipherMap.put("SSL3_DH_RSA_EXPORT_WITH_DES40_CBC_SHA",   SSLSocket.SSL3_DH_RSA_EXPORT_WITH_DES40_CBC_SHA);
        cipherMap.put("SSL3_DH_RSA_WITH_DES_CBC_SHA",            SSLSocket.SSL3_DH_RSA_WITH_DES_CBC_SHA);
        cipherMap.put("SSL3_DH_RSA_WITH_3DES_EDE_CBC_SHA",       SSLSocket.SSL3_DH_RSA_WITH_3DES_EDE_CBC_SHA);
                                                        
        cipherMap.put("SSL3_DHE_DSS_EXPORT_WITH_DES40_CBC_SHA",  SSLSocket.SSL3_DHE_DSS_EXPORT_WITH_DES40_CBC_SHA);
        cipherMap.put("SSL3_DHE_DSS_WITH_DES_CBC_SHA",           SSLSocket.SSL3_DHE_DSS_WITH_DES_CBC_SHA);
        cipherMap.put("SSL3_DHE_DSS_WITH_3DES_EDE_CBC_SHA",      SSLSocket.SSL3_DHE_DSS_WITH_3DES_EDE_CBC_SHA);
        cipherMap.put("SSL3_DHE_RSA_EXPORT_WITH_DES40_CBC_SHA",  SSLSocket.SSL3_DHE_RSA_EXPORT_WITH_DES40_CBC_SHA);
        cipherMap.put("SSL3_DHE_RSA_WITH_DES_CBC_SHA",           SSLSocket.SSL3_DHE_RSA_WITH_DES_CBC_SHA);
        cipherMap.put("SSL3_DHE_RSA_WITH_3DES_EDE_CBC_SHA",      SSLSocket.SSL3_DHE_RSA_WITH_3DES_EDE_CBC_SHA);
                                                                                
        cipherMap.put("SSL3_DH_ANON_EXPORT_WITH_RC4_40_MD5",     SSLSocket.SSL3_DH_ANON_EXPORT_WITH_RC4_40_MD5);
        cipherMap.put("SSL3_DH_ANON_WITH_RC4_128_MD5",           SSLSocket.SSL3_DH_ANON_WITH_RC4_128_MD5);
        cipherMap.put("SSL3_DH_ANON_EXPORT_WITH_DES40_CBC_SHA",  SSLSocket.SSL3_DH_ANON_EXPORT_WITH_DES40_CBC_SHA);
        cipherMap.put("SSL3_DH_ANON_WITH_DES_CBC_SHA",           SSLSocket.SSL3_DH_ANON_WITH_DES_CBC_SHA);
        cipherMap.put("SSL3_DH_ANON_WITH_3DES_EDE_CBC_SHA",      SSLSocket.SSL3_DH_ANON_WITH_3DES_EDE_CBC_SHA);
                                                                                
        cipherMap.put("SSL3_FORTEZZA_DMS_WITH_NULL_SHA",         SSLSocket.SSL3_FORTEZZA_DMS_WITH_NULL_SHA);
        cipherMap.put("SSL3_FORTEZZA_DMS_WITH_FORTEZZA_CBC_SHA", SSLSocket.SSL3_FORTEZZA_DMS_WITH_FORTEZZA_CBC_SHA);
        cipherMap.put("SSL3_FORTEZZA_DMS_WITH_RC4_128_SHA",      SSLSocket.SSL3_FORTEZZA_DMS_WITH_RC4_128_SHA);
                                                                                
        cipherMap.put("SSL_RSA_FIPS_WITH_3DES_EDE_CBC_SHA",      SSLSocket.SSL_RSA_FIPS_WITH_3DES_EDE_CBC_SHA);
        cipherMap.put("SSL_RSA_FIPS_WITH_DES_CBC_SHA",           SSLSocket.SSL_RSA_FIPS_WITH_DES_CBC_SHA);
                                                                                
        // TLS
        cipherMap.put("TLS_RSA_EXPORT1024_WITH_DES_CBC_SHA",     SSLSocket.TLS_RSA_EXPORT1024_WITH_DES_CBC_SHA);
        cipherMap.put("TLS_RSA_EXPORT1024_WITH_RC4_56_SHA",      SSLSocket.TLS_RSA_EXPORT1024_WITH_RC4_56_SHA);
                                                                                
        cipherMap.put("TLS_DHE_DSS_EXPORT1024_WITH_DES_CBC_SHA", SSLSocket.TLS_DHE_DSS_EXPORT1024_WITH_DES_CBC_SHA);
        cipherMap.put("TLS_DHE_DSS_EXPORT1024_WITH_RC4_56_SHA",  SSLSocket.TLS_DHE_DSS_EXPORT1024_WITH_RC4_56_SHA);
        cipherMap.put("TLS_DHE_DSS_WITH_RC4_128_SHA",            SSLSocket.TLS_DHE_DSS_WITH_RC4_128_SHA);
                                                                                
        cipherMap.put("TLS_RSA_WITH_AES_128_CBC_SHA",            SSLSocket.TLS_RSA_WITH_AES_128_CBC_SHA);
        cipherMap.put("TLS_DH_DSS_WITH_AES_128_CBC_SHA",         SSLSocket.TLS_DH_DSS_WITH_AES_128_CBC_SHA);
        cipherMap.put("TLS_DH_RSA_WITH_AES_128_CBC_SHA",         SSLSocket.TLS_DH_RSA_WITH_AES_128_CBC_SHA);
        cipherMap.put("TLS_DHE_DSS_WITH_AES_128_CBC_SHA",        SSLSocket.TLS_DHE_DSS_WITH_AES_128_CBC_SHA);
        cipherMap.put("TLS_DHE_RSA_WITH_AES_128_CBC_SHA",        SSLSocket.TLS_DHE_RSA_WITH_AES_128_CBC_SHA);
        cipherMap.put("TLS_DH_ANON_WITH_AES_128_CBC_SHA",        SSLSocket.TLS_DH_ANON_WITH_AES_128_CBC_SHA);
                                                                                
        cipherMap.put("TLS_RSA_WITH_AES_256_CBC_SHA",            SSLSocket.TLS_RSA_WITH_AES_256_CBC_SHA);
        cipherMap.put("TLS_DH_DSS_WITH_AES_256_CBC_SHA",         SSLSocket.TLS_DH_DSS_WITH_AES_256_CBC_SHA);
        cipherMap.put("TLS_DH_RSA_WITH_AES_256_CBC_SHA",         SSLSocket.TLS_DH_RSA_WITH_AES_256_CBC_SHA);
        cipherMap.put("TLS_DHE_DSS_WITH_AES_256_CBC_SHA",        SSLSocket.TLS_DHE_DSS_WITH_AES_256_CBC_SHA);
        cipherMap.put("TLS_DHE_RSA_WITH_AES_256_CBC_SHA",        SSLSocket.TLS_DHE_RSA_WITH_AES_256_CBC_SHA);
        cipherMap.put("TLS_DH_ANON_WITH_AES_256_CBC_SHA",        SSLSocket.TLS_DH_ANON_WITH_AES_256_CBC_SHA);

        // ECC
        cipherMap.put("TLS_ECDH_ECDSA_WITH_NULL_SHA",            SSLSocket.TLS_ECDH_ECDSA_WITH_NULL_SHA);
        cipherMap.put("TLS_ECDH_ECDSA_WITH_RC4_128_SHA",         SSLSocket.TLS_ECDH_ECDSA_WITH_RC4_128_SHA);
        cipherMap.put("TLS_ECDH_ECDSA_WITH_3DES_EDE_CBC_SHA",    SSLSocket.TLS_ECDH_ECDSA_WITH_3DES_EDE_CBC_SHA);
        cipherMap.put("TLS_ECDH_ECDSA_WITH_AES_128_CBC_SHA",     SSLSocket.TLS_ECDH_ECDSA_WITH_AES_128_CBC_SHA);
        cipherMap.put("TLS_ECDH_ECDSA_WITH_AES_256_CBC_SHA",     SSLSocket.TLS_ECDH_ECDSA_WITH_AES_256_CBC_SHA);
                                                                               
        cipherMap.put("TLS_ECDHE_ECDSA_WITH_NULL_SHA",           SSLSocket.TLS_ECDHE_ECDSA_WITH_NULL_SHA);
        cipherMap.put("TLS_ECDHE_ECDSA_WITH_RC4_128_SHA",        SSLSocket.TLS_ECDHE_ECDSA_WITH_RC4_128_SHA);
        cipherMap.put("TLS_ECDHE_ECDSA_WITH_3DES_EDE_CBC_SHA",   SSLSocket.TLS_ECDHE_ECDSA_WITH_3DES_EDE_CBC_SHA);
        cipherMap.put("TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA",    SSLSocket.TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA);
        cipherMap.put("TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA",    SSLSocket.TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA);

        cipherMap.put("TLS_ECDHE_RSA_WITH_NULL_SHA",             SSLSocket.TLS_ECDHE_RSA_WITH_NULL_SHA);
        cipherMap.put("TLS_ECDHE_RSA_WITH_RC4_128_SHA",          SSLSocket.TLS_ECDHE_RSA_WITH_RC4_128_SHA);
        cipherMap.put("TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA",     SSLSocket.TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA);
        cipherMap.put("TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA",      SSLSocket.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA);
        cipherMap.put("TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA",      SSLSocket.TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA);
                                                                                
        cipherMap.put("TLS_ECDH_anon_WITH_NULL_SHA",             SSLSocket.TLS_ECDH_anon_WITH_NULL_SHA);
        cipherMap.put("TLS_ECDH_anon_WITH_RC4_128_SHA",          SSLSocket.TLS_ECDH_anon_WITH_RC4_128_SHA);
        cipherMap.put("TLS_ECDH_anon_WITH_3DES_EDE_CBC_SHA",     SSLSocket.TLS_ECDH_anon_WITH_3DES_EDE_CBC_SHA);
        cipherMap.put("TLS_ECDH_anon_WITH_AES_128_CBC_SHA",      SSLSocket.TLS_ECDH_anon_WITH_AES_128_CBC_SHA);
        cipherMap.put("TLS_ECDH_anon_WITH_AES_256_CBC_SHA",      SSLSocket.TLS_ECDH_anon_WITH_AES_256_CBC_SHA);

    }

    private static HashMap eccCipherMap = new HashMap();
    static {
        eccCipherMap.put(SSLSocket.TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA,  "TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA");
        eccCipherMap.put(SSLSocket.TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA,    "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA");
        eccCipherMap.put(SSLSocket.TLS_ECDH_RSA_WITH_AES_256_CBC_SHA,     "TLS_ECDH_RSA_WITH_AES_256_CBC_SHA");
        eccCipherMap.put(SSLSocket.TLS_ECDH_ECDSA_WITH_AES_256_CBC_SHA,   "TLS_ECDH_ECDSA_WITH_AES_256_CBC_SHA");
        eccCipherMap.put(SSLSocket.TLS_ECDHE_ECDSA_WITH_RC4_128_SHA,      "TLS_ECDHE_ECDSA_WITH_RC4_128_SHA");
        eccCipherMap.put(SSLSocket.TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA,  "TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA");
        eccCipherMap.put(SSLSocket.TLS_ECDHE_RSA_WITH_RC4_128_SHA,        "TLS_ECDHE_RSA_WITH_RC4_128_SHA");
        eccCipherMap.put(SSLSocket.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA,    "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA");
        eccCipherMap.put(SSLSocket.TLS_ECDH_RSA_WITH_RC4_128_SHA,         "TLS_ECDH_RSA_WITH_RC4_128_SHA");
        eccCipherMap.put(SSLSocket.TLS_ECDH_RSA_WITH_AES_128_CBC_SHA,     "TLS_ECDH_RSA_WITH_AES_128_CBC_SHA");
        eccCipherMap.put(SSLSocket.TLS_ECDH_ECDSA_WITH_RC4_128_SHA,       "TLS_ECDH_ECDSA_WITH_RC4_128_SHA");
        eccCipherMap.put(SSLSocket.TLS_ECDH_ECDSA_WITH_AES_128_CBC_SHA,   "TLS_ECDH_ECDSA_WITH_AES_128_CBC_SHA");
        eccCipherMap.put(SSLSocket.TLS_ECDHE_ECDSA_WITH_3DES_EDE_CBC_SHA, "TLS_ECDHE_ECDSA_WITH_3DES_EDE_CBC_SHA");
        eccCipherMap.put(SSLSocket.TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA,   "TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA");
        eccCipherMap.put(SSLSocket.TLS_ECDH_RSA_WITH_3DES_EDE_CBC_SHA,    "TLS_ECDH_RSA_WITH_3DES_EDE_CBC_SHA");
        eccCipherMap.put(SSLSocket.TLS_ECDH_ECDSA_WITH_3DES_EDE_CBC_SHA,  "TLS_ECDH_ECDSA_WITH_3DES_EDE_CBC_SHA");
        eccCipherMap.put(SSLSocket.TLS_ECDHE_ECDSA_WITH_NULL_SHA,         "TLS_ECDHE_ECDSA_WITH_NULL_SHA");
        eccCipherMap.put(SSLSocket.TLS_ECDHE_RSA_WITH_NULL_SHA,           "TLS_ECDHE_RSA_WITH_NULL_SHA");
        eccCipherMap.put(SSLSocket.TLS_ECDH_RSA_WITH_NULL_SHA,            "TLS_ECDH_RSA_WITH_NULL_SHA");
        eccCipherMap.put(SSLSocket.TLS_ECDH_ECDSA_WITH_NULL_SHA,          "TLS_ECDH_ECDSA_WITH_NULL_SHA");
    }

    private AbstractEndpoint endpoint;

    static org.apache.commons.logging.Log log = 
      org.apache.commons.logging.LogFactory.getLog(JSSSocketFactory.class);

    protected static boolean ocspConfigured = false;
    protected boolean requireClientAuth = false;
    protected boolean wantClientAuth = false;
    private Vector enabledCiphers = new Vector(); 
    private boolean initialized = false;
    private String serverCertNick = "";
    private String mServerCertNickPath ="";
    private String mPwdPath ="";
    private String mPwdClass ="";
    private static final String DATE_PATTERN = "dd/MMM/yyyy:HH:mm:ss";
    private static SimpleDateFormat timeStampFormat = new SimpleDateFormat(DATE_PATTERN);
    FileWriter debugFile = null;
    boolean debug = false;
    private IPasswordStore mPasswordStore = null;
    private boolean mStrictCiphers = false;

    public JSSSocketFactory (AbstractEndpoint endpoint) {
        this.endpoint = endpoint;
    }

    private void debugWrite(String m) throws IOException {
	if (debug) {
            String timeStamp = timeStampFormat.format(new Date());
            String threadName = Thread.currentThread().getName();
	    debugFile.write("[" + timeStamp + "][" + threadName + "]: " + m);
        }
    }

    public void setSSLCiphers(String attr) throws SocketException
    {
      String ciphers = (String)endpoint.getAttribute(attr);
      StringTokenizer st = new StringTokenizer(ciphers, ",");
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
            state = true;       // no enable/disable flag, assume enable
            text = cipherstr;
        }

        if (text.startsWith("0x") || text.startsWith("0X")) {
            // this allows us to specify new ciphers
            try {
                cipherid = Integer.parseInt(text.substring(2), 16);
            }
            catch (Exception e) {
                System.err.println("Error: SSL cipher \"\""+text+"\" cannot be read as an integer");
                continue;
            }
        } else {
            Object mapValue;

            mapValue = cipherMap.get(text);
            if (mapValue == null) {
                cipherid = 0;
            } else {
                cipherid = (Integer)mapValue;
            }
        }
        if (cipherid != 0) {
            try {
                debugWrite("JSSSocketFactory setSSLCiphers:  "+
                    cipherstr+": 0x"+Integer.toHexString(cipherid) +"\n");
                SSLSocket.setCipherPreferenceDefault(cipherid, state);
            }
            catch (Exception e) {
                if (eccCipherMap.containsKey(cipherid)) {
                    System.err.println("Warning: SSL ECC cipher \""+text+"\" unsupported by NSS. "+
                                       "This is probably O.K. unless ECC support has been installed.");
                } else {
                    System.err.println("Error: SSL cipher \""+text+"\" unsupported by NSS");
                }
            }
        } else {
            System.err.println("Error: SSL cipher \""+text+"\" not recognized by tomcatjss");
        }
      }
    }

    public void setSSLOptions() throws SocketException
    {
      String options = (String)endpoint.getAttribute("sslOptions");
      StringTokenizer st = new StringTokenizer(options, ",");
      while (st.hasMoreTokens()) {
        String option = st.nextToken();
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
    public void unsetSSLCiphers() throws SocketException
    {
        int ciphers[] = SSLSocket.getImplementedCipherSuites();
        try {
          for (int i = 0; ciphers != null && i < ciphers.length; i++) {

            debugWrite("JSSSocketFactory unsetSSLCiphers - turning off '0x"+
               Integer.toHexString(ciphers[i]) + "'\n");
            SSLSocket.setCipherPreferenceDefault(ciphers[i], false);
          }
        } catch (Exception e) {
        }
    }

    void init() throws IOException {
        try {
            String deb = (String)endpoint.getAttribute("debug");
            if (deb.equals("true")) {
            debug = true;
            debugFile =  new FileWriter("/tmp/tomcatjss.log", true);
            debugWrite("JSSSocketFactory init - debug is on\n");
            }
        } catch (Exception e) {
	    //	    System.out.println("no tomcatjss debugging");
        }

        try {
            try {
                mPwdPath = (String)endpoint.getAttribute("passwordFile");
		mPwdClass = (String)endpoint.getAttribute("passwordClass");
		if (mPwdClass != null) {
		    mPasswordStore = (IPasswordStore)Class.forName(mPwdClass).newInstance();
                    mPasswordStore.init(mPwdPath);
                    debugWrite("JSSSocketFactory init - password reader initialized\n");
		}
             } catch (Exception e) {
                debugWrite("JSSSocketFactory init - Exception caught: "
                   +e.toString() + "\n");
                if (debugFile != null)
                    debugFile.close();
                throw new IOException("JSSSocketFactory: no passwordFilePath defined");
            }

            String certDir = (String)endpoint.getAttribute("certdbDir");
   
            CryptoManager.InitializationValues vals = 
              new CryptoManager.InitializationValues(certDir,
              "", "", "secmod.db");

            vals.removeSunProvider = false;
            vals.installJSSProvider = true;
            try {
                CryptoManager.initialize(vals);
            } catch (AlreadyInitializedException ee) {
                // do nothing
            }
            CryptoManager manager = CryptoManager.getInstance();

            //JSSSocketFactory init - handle crypto tokens
            debugWrite("JSSSocketFactory init - about to handle crypto unit logins\n");

            if (mPasswordStore != null) {
                Enumeration en = mPasswordStore.getTags();
                while (en.hasMoreElements()){
                    String pwd = "";
                    Password pw = null;
                    String tokenName = "";
                    String st = (String) en.nextElement();
                    debugWrite("JSSSocketFactory init - tag name="+st+"\n");
                    pwd = mPasswordStore.getPassword(st);

                    if (pwd != null) {
                        debugWrite("JSSSocketFactory init - got password\n");
                        pw = new Password(pwd.toCharArray()); 
                    } else {
                        debugWrite("JSSSocketFactory init - no pwd found in password.conf\n");
                        continue;
                    }

                    CryptoToken token = null;
                    if (st.equals("internal")) {
                        debugWrite("JSSSocketFactory init - got internal software token\n");
                        token = manager.getInternalKeyStorageToken();
                    } else if (st.startsWith("hardware-")) {
                        debugWrite("JSSSocketFactory init - got hardware\n");

                        tokenName = st.substring(9);
                        debugWrite("JSSSocketFactory init - tokenName="+tokenName+"\n");

                        // find the hsm and log in
                        token = manager.getTokenByName(tokenName);
                    } else {
                        //non-token entries
                    }
                    if (token != null) {
                        if (!token.isLoggedIn()) {
                            debugWrite("JSSSocketFactory init -not logged in...about to log in\n");
                            token.login(pw);
                        } else {
                            debugWrite("JSSSocketFactory init - already logged in\n");
                        }
                    }
                } //while
                debugWrite("JSSSocketFactory init - tokens initialized/logged in\n");
            } else {
                debugWrite("JSSSocketFactory init - no login done\n");
            } //mPasswordStore not null

            // MUST look for "clientauth" (ALL lowercase) since "clientAuth"
            // (camel case) has already been processed by Tomcat 7
            String clientAuthStr = (String)endpoint.getAttribute("clientauth");
            File file = null;
            try {
                mServerCertNickPath = (String)endpoint.getAttribute("serverCertNickFile");
                debugWrite("JSSSocketFactory init - got serverCertNickFile"+
                            mServerCertNickPath+"\n");
                file = new File(mServerCertNickPath);
                Long l = new Long(file.length());
                FileInputStream in = new FileInputStream(mServerCertNickPath);
                BufferedReader d =
                            new BufferedReader(new InputStreamReader(in));
                do {
                  serverCertNick = d.readLine();
                  debugWrite("JSSSocketFactory init - got line "+
                            serverCertNick +"\n");
                  if (serverCertNick == null) {
                      in.close();
                      d.close();
                      throw new IOException("JSSSocketFactory: error loading serverCertNickFile");
                  }
                  // handle comments or blank lines
                  if (serverCertNick.trim().startsWith("#") ||
                         serverCertNick.trim().equals("")) { 
                    serverCertNick = null;
                  }
                } while (serverCertNick == null);
                debugWrite("JSSSocketFactory init - found nickname=" + serverCertNick + "\n");
                in.close();
                d.close();
            } catch (Exception e) {
                debugWrite("JSSSocketFactory init - Exception caught: "
                   +e.toString() + "\n");
                if (debugFile != null)
                    debugFile.close();
                throw new IOException("JSSSocketFactory: no serverCertNickFile defined");
            }

            //serverCertNick = (String)endpoint.getAttribute("serverCert");
            if (clientAuthStr.equalsIgnoreCase("true") ||
              clientAuthStr.equalsIgnoreCase("yes")) {
                requireClientAuth = true;
            } else if (clientAuthStr.equalsIgnoreCase("want")) {
                wantClientAuth = true;
            }
            debugWrite("JSSSocketFActory init - requireClientAuth " + requireClientAuth +
                          " wantClientAuth " + wantClientAuth + " ocspConfigured " 
                          + ocspConfigured);
            if (requireClientAuth == true || wantClientAuth == true 
                   && ocspConfigured == false ) {
                debugWrite("JSSSocketFactory init - checking for OCSP settings. \n" ); 
                boolean enableOCSP = false; 
                String doOCSP = (String) endpoint.getAttribute("enableOCSP");

                debugWrite("JSSSocketFactory init - doOCSP flag:"+
                          doOCSP+ " \n");

                if (doOCSP != null &&  doOCSP.equalsIgnoreCase("true"))  {
                   enableOCSP = true;
                } 
               
                debugWrite("JSSSocketFactory init - enableOCSP "+
                             enableOCSP+ "\n"); 
                
                if( enableOCSP == true ) {
                    String ocspResponderURL = (String) endpoint.getAttribute("ocspResponderURL");
                    debugWrite("JSSSocketFactory init - ocspResponderURL "+
                             ocspResponderURL+ "\n");
                    String ocspResponderCertNickname = (String) endpoint.getAttribute("ocspResponderCertNickname");
		    debugWrite("JSSSocketFactory init - ocspResponderCertNickname" + ocspResponderCertNickname + "\n");
                    if( (ocspResponderURL != null && ocspResponderURL.length() > 0) && 
                        (ocspResponderCertNickname != null && 
                         ocspResponderCertNickname.length() > 0 ))   {

                       ocspConfigured = true;
                       try {
                           manager.configureOCSP(true,ocspResponderURL,ocspResponderCertNickname);
                           int ocspCacheSize_i = 1000;
                           int ocspMinCacheEntryDuration_i = 3600;
                           int ocspMaxCacheEntryDuration_i = 86400;

                           String ocspCacheSize = (String) endpoint.getAttribute("ocspCacheSize");
                           String ocspMinCacheEntryDuration = (String) endpoint.getAttribute("ocspMinCacheEntryDuration");
                           String ocspMaxCacheEntryDuration = (String) endpoint.getAttribute("ocspMaxCacheEntryDuration");

                           if (ocspCacheSize != null ||
                             ocspMinCacheEntryDuration != null ||
                             ocspMaxCacheEntryDuration != null) {
                             // not specified then takes the default
                             if (ocspCacheSize != null) {
		    debugWrite("JSSSocketFactory init - ocspCacheSize= " + ocspCacheSize+"\n");
                               ocspCacheSize_i = Integer.parseInt(ocspCacheSize);
                             }
                             if (ocspMinCacheEntryDuration != null) {
		    debugWrite("JSSSocketFactory init - ocspMinCacheEntryDuration= " + ocspMinCacheEntryDuration+"\n");
                               ocspMinCacheEntryDuration_i = Integer.parseInt(ocspMinCacheEntryDuration);
                             }
                             if (ocspMaxCacheEntryDuration != null) {
		    debugWrite("JSSSocketFactory init - ocspMaxCacheEntryDuration= " + ocspMaxCacheEntryDuration+"\n");
                               ocspMaxCacheEntryDuration_i = Integer.parseInt(ocspMaxCacheEntryDuration);
                             }
                             manager.OCSPCacheSettings(ocspCacheSize_i,
                               ocspMinCacheEntryDuration_i, ocspMaxCacheEntryDuration_i);
                           }

                           // defualt to 60 seconds;
                           String ocspTimeout = (String) endpoint.getAttribute("ocspTimeout");
                           if (ocspTimeout != null) {
		    debugWrite("JSSSocketFactory init - ocspTimeout= \n" + ocspTimeout);
                               int ocspTimeout_i = Integer.parseInt(ocspTimeout);
                               if (ocspTimeout_i < 0)
                                  ocspTimeout_i = 60; 
                               manager.setOCSPTimeout(ocspTimeout_i);
                           }

                       } catch(java.security.GeneralSecurityException e) {
                          ocspConfigured = false;
                          debugWrite("JSSSocketFactory init - error initializing OCSP e: " + e.toString()+"\n");
                          throw new  java.security.GeneralSecurityException("Error setting up OCSP. Check configuraion!");
                       } catch (java.lang.NumberFormatException e) {
                          debugWrite("JSSSocketFactory init - error setting OCSP cache e: " + e.toString()+"\n");
                          throw new  java.lang.NumberFormatException("Error setting OCSP cache. Check configuraion!");
                       }
                    }  else  {
                        debugWrite("JSSSocketFactory init - error ocsp misconfigured! \n");
                        throw new java.security.GeneralSecurityException("Error setting up OCSP. Check configuration!");
                    } 
                }
            }
            //serverCertNick = "Server-Cert cert-tks";
            // 12 hours = 43200 seconds
            SSLServerSocket.configServerSessionIDCache(0, 43200, 43200, null);

            String strictCiphersStr = (String)endpoint.getAttribute("strictCiphers");
            if (strictCiphersStr.equalsIgnoreCase("true") ||
              strictCiphersStr.equalsIgnoreCase("yes")) {
                mStrictCiphers = true;
            }
            if (mStrictCiphers == true) {
                // what ciphers do we have to start with? turn them all off
                 debugWrite("SSSocketFactory init - before setSSLOptions, strictCiphers is true\n");
                 unsetSSLCiphers();
            } else {
                 debugWrite("SSSocketFactory init - before setSSLOptions, strictCiphers is false\n");
            }

            setSSLOptions();
            debugWrite("SSSocketFactory init - after setSSLOptions\n");
        } catch (Exception ex) {
            debugWrite("JSSSocketFactory init - exception thrown:"+
                   ex.toString()+"\n");
	        System.err.println("JSSSocketFactory init - exception thrown:"+
                   ex.toString()+"\n");
            if (debugFile != null)
                debugFile.close();
            // The idea is, if admin take the trouble to configure the
            // ocsp cache, and made a mistake, we want to make server
            // unavailable until they get it right
            if((ex instanceof java.security.GeneralSecurityException) ||
               (ex instanceof java.lang.NumberFormatException))
              throw  new IOException(ex.toString());
        }
        if (debugFile != null)
            debugFile.close();
    }

    public Socket acceptSocket(ServerSocket socket) throws IOException {
        SSLSocket asock = null;
        try {
            asock = (SSLSocket)socket.accept();
            if (wantClientAuth || requireClientAuth) {
                asock.requestClientAuth(true);
                if (requireClientAuth == true) {
                    asock.requireClientAuth(SSLSocket.SSL_REQUIRE_ALWAYS);
                } else {
                    asock.requireClientAuth(SSLSocket.SSL_REQUIRE_NEVER);
                }
            }
        } catch (Exception e) {
            throw new SocketException("SSL handshake error "+e.toString());
        } 

        return asock;
    }

    public void handshake(Socket sock) throws IOException {
        //((SSLSocket)sock).forceHandshake();
    }

    public ServerSocket createSocket(int port) throws IOException {
        return createSocket(port, SSLServerSocket.DEFAULT_BACKLOG, null);
    }

    public ServerSocket createSocket(int port, int backlog)
      throws IOException {
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
        socket = (SSLServerSocket)(new SSLServerSocket(port, backlog,
          ifAddress, null, reuseAddr));
        initializeSocket(socket);
        return (ServerSocket)socket;
    }

    private void initializeSocket(SSLServerSocket s) {
        try {
            /*
             * Timeout's should not be enabled by default.
             * Upper layers will call setSoTimeout() as needed.
             * Zero means disable.
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

    public void configureSessionContext(javax.net.ssl.SSLSessionContext sslSessionContext) {
        return;
    }

    public String[] getEnableableCiphers(SSLContext context) {
        return null;
    }

    public String[] getEnableableProtocols(SSLContext context) {
        return null;
    }
}
