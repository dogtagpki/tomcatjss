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
import org.mozilla.jss.ssl.*;
import org.mozilla.jss.crypto.*;
import org.mozilla.jss.CryptoManager;
import org.mozilla.jss.util.*;
import org.mozilla.jss.pkcs11.*;
import java.net.*;
import java.io.*;

public class JSSSocketFactory
  extends org.apache.tomcat.util.net.ServerSocketFactory {

    static org.apache.commons.logging.Log log = 
      org.apache.commons.logging.LogFactory.getLog(JSSSocketFactory.class);
    private static int jssCipherSuites[] = {
        SSLSocket.SSL3_RSA_WITH_NULL_MD5,
        SSLSocket.SSL3_RSA_WITH_NULL_SHA,
        SSLSocket.SSL3_RSA_EXPORT_WITH_RC4_40_MD5,
        SSLSocket.SSL3_RSA_WITH_RC4_128_MD5,
        SSLSocket.SSL3_RSA_WITH_RC4_128_SHA,
        SSLSocket.SSL3_RSA_EXPORT_WITH_RC2_CBC_40_MD5,
        SSLSocket.SSL3_RSA_WITH_IDEA_CBC_SHA,
        SSLSocket.SSL3_RSA_EXPORT_WITH_DES40_CBC_SHA,
        SSLSocket.SSL3_RSA_WITH_DES_CBC_SHA,
        SSLSocket.SSL3_RSA_WITH_3DES_EDE_CBC_SHA,
        // DH and DHE Ciphers are client only.
        SSLSocket.SSL3_DH_DSS_EXPORT_WITH_DES40_CBC_SHA,
        SSLSocket.SSL3_DH_DSS_WITH_DES_CBC_SHA,
        SSLSocket.SSL3_DH_DSS_WITH_3DES_EDE_CBC_SHA,
        SSLSocket.SSL3_DH_RSA_EXPORT_WITH_DES40_CBC_SHA,
        SSLSocket.SSL3_DH_RSA_WITH_DES_CBC_SHA,
        SSLSocket.SSL3_DH_RSA_WITH_3DES_EDE_CBC_SHA,
        SSLSocket.SSL3_DHE_DSS_EXPORT_WITH_DES40_CBC_SHA,
        SSLSocket.SSL3_DHE_DSS_WITH_DES_CBC_SHA,
        SSLSocket.SSL3_DHE_DSS_WITH_3DES_EDE_CBC_SHA,
        SSLSocket.SSL3_DHE_RSA_EXPORT_WITH_DES40_CBC_SHA,
        SSLSocket.SSL3_DHE_RSA_WITH_DES_CBC_SHA,
        SSLSocket.SSL3_DHE_RSA_WITH_3DES_EDE_CBC_SHA,
        SSLSocket.SSL3_DH_ANON_EXPORT_WITH_RC4_40_MD5,
        SSLSocket.SSL3_DH_ANON_WITH_RC4_128_MD5,
        SSLSocket.SSL3_DH_ANON_EXPORT_WITH_DES40_CBC_SHA,
        SSLSocket.SSL3_DH_ANON_WITH_DES_CBC_SHA,
        SSLSocket.SSL3_DH_ANON_WITH_3DES_EDE_CBC_SHA,
        // Don't bother with FORTEZZA Ciphers.
        SSLSocket.SSL3_FORTEZZA_DMS_WITH_NULL_SHA,
        SSLSocket.SSL3_FORTEZZA_DMS_WITH_FORTEZZA_CBC_SHA,
        SSLSocket.SSL3_FORTEZZA_DMS_WITH_RC4_128_SHA,
        SSLSocket.SSL_RSA_FIPS_WITH_3DES_EDE_CBC_SHA,
        SSLSocket.SSL_RSA_FIPS_WITH_DES_CBC_SHA,
        // These are TLS Ciphers.
        SSLSocket.TLS_RSA_EXPORT1024_WITH_DES_CBC_SHA,
        SSLSocket.TLS_RSA_EXPORT1024_WITH_RC4_56_SHA,
        // DH and DHE Ciphers are client only.
        SSLSocket.TLS_DHE_DSS_EXPORT1024_WITH_DES_CBC_SHA,
        SSLSocket.TLS_DHE_DSS_EXPORT1024_WITH_RC4_56_SHA,
        SSLSocket.TLS_DHE_DSS_WITH_RC4_128_SHA,
        SSLSocket.TLS_RSA_WITH_AES_128_CBC_SHA,
        SSLSocket.TLS_DH_DSS_WITH_AES_128_CBC_SHA,
        SSLSocket.TLS_DH_RSA_WITH_AES_128_CBC_SHA,
        SSLSocket.TLS_DHE_DSS_WITH_AES_128_CBC_SHA,
        SSLSocket.TLS_DHE_RSA_WITH_AES_128_CBC_SHA,
        SSLSocket.TLS_DH_ANON_WITH_AES_128_CBC_SHA,
        SSLSocket.TLS_RSA_WITH_AES_256_CBC_SHA,
        SSLSocket.TLS_DH_DSS_WITH_AES_256_CBC_SHA,
        SSLSocket.TLS_DH_RSA_WITH_AES_256_CBC_SHA,
        SSLSocket.TLS_DHE_DSS_WITH_AES_256_CBC_SHA,
        SSLSocket.TLS_DHE_RSA_WITH_AES_256_CBC_SHA,
        SSLSocket.TLS_DH_ANON_WITH_AES_256_CBC_SHA,
        0
    };

    /* Temporarily define here, later on, we should extract them 
       from SSLSocket */
    public final static int TLS_ECDH_ECDSA_WITH_NULL_SHA = 0xC001;
    public final static int TLS_ECDH_ECDSA_WITH_RC4_128_SHA = 0xC002;
    public final static int TLS_ECDH_ECDSA_WITH_3DES_EDE_CBC_SHA = 0xC003;
    public final static int TLS_ECDH_ECDSA_WITH_AES_128_CBC_SHA = 0xC004;
    public final static int TLS_ECDH_ECDSA_WITH_AES_256_CBC_SHA = 0xC005;
                                                                               
    public final static int TLS_ECDHE_ECDSA_WITH_NULL_SHA = 0xC006;
    public final static int TLS_ECDHE_ECDSA_WITH_RC4_128_SHA = 0xC007;
    public final static int TLS_ECDHE_ECDSA_WITH_3DES_EDE_CBC_SHA = 0xC008;
    public final static int TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA = 0xC009;
    public final static int TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA = 0xC00A;
                                                                                
    public final static int TLS_ECDH_RSA_WITH_NULL_SHA = 0xC00B;
    public final static int TLS_ECDH_RSA_WITH_RC4_128_SHA = 0xC00C;
    public final static int TLS_ECDH_RSA_WITH_3DES_EDE_CBC_SHA = 0xC00D;
    public final static int TLS_ECDH_RSA_WITH_AES_128_CBC_SHA = 0xC00E;
    public final static int TLS_ECDH_RSA_WITH_AES_256_CBC_SHA = 0xC00F;
                                                                                
    public final static int TLS_ECDHE_RSA_WITH_NULL_SHA = 0xC010;
    public final static int TLS_ECDHE_RSA_WITH_RC4_128_SHA = 0xC011;
    public final static int TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA = 0xC012;
    public final static int TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA = 0xC013;
    public final static int TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA = 0xC014;
                                                                                
    public final static int TLS_ECDH_anon_WITH_NULL_SHA = 0xC015;
    public final static int TLS_ECDH_anon_WITH_RC4_128_SHA = 0xC016;
    public final static int TLS_ECDH_anon_WITH_3DES_EDE_CBC_SHA = 0xC017;
    public final static int TLS_ECDH_anon_WITH_AES_128_CBC_SHA = 0xC018;
    public final static int TLS_ECDH_anon_WITH_AES_256_CBC_SHA = 0xC019;


    protected boolean requireClientAuth = false;
    protected boolean wantClientAuth = false;
    private Vector enabledCiphers = new Vector(); 
    private boolean initialized = false;
    private String serverCertNick = "";
    private String mServerCertNickPath ="";
    private String mPwdPath ="";
    private String mPwdClass ="";
    FileWriter debugFile = null;
    boolean debug = false;
    private IPasswordStore mPasswordStore = null;

    public JSSSocketFactory() {
        super();
    }

    private void debugWrite(String m) throws IOException {
	if (debug)
	    debugFile.write(m);
	    //	    System.out.println(m);
    }

    public int toCipherId(String str)
    {
      // SSLv2
      if (str.equals("SSL2_RC4_128_WITH_MD5"))
        return SSLSocket.SSL2_RC4_128_WITH_MD5;
      if (str.equals("SSL2_RC4_128_EXPORT40_WITH_MD5"))
        return SSLSocket.SSL2_RC4_128_EXPORT40_WITH_MD5;
      if (str.equals("SSL2_RC2_128_CBC_WITH_MD5"))
        return SSLSocket.SSL2_RC2_128_CBC_WITH_MD5;
      if (str.equals("SSL2_RC2_128_CBC_EXPORT40_WITH_MD5"))
        return SSLSocket.SSL2_RC2_128_CBC_EXPORT40_WITH_MD5;
      if (str.equals("SSL2_IDEA_128_CBC_WITH_MD5"))
        return SSLSocket.SSL2_IDEA_128_CBC_WITH_MD5;
      if (str.equals("SSL2_DES_64_CBC_WITH_MD5"))
        return SSLSocket.SSL2_DES_64_CBC_WITH_MD5;
      if (str.equals("SSL2_DES_192_EDE3_CBC_WITH_MD5"))
        return SSLSocket.SSL2_DES_192_EDE3_CBC_WITH_MD5;

      // SSLv3
      if (str.equals("SSL3_RSA_WITH_NULL_MD5"))
        return SSLSocket.SSL3_RSA_WITH_NULL_MD5;
      if (str.equals("SSL3_RSA_WITH_NULL_SHA"))
        return SSLSocket.SSL3_RSA_WITH_NULL_SHA;
      if (str.equals("SSL3_RSA_EXPORT_WITH_RC4_40_MD5"))
        return SSLSocket.SSL3_RSA_EXPORT_WITH_RC4_40_MD5;
      if (str.equals("SSL3_RSA_WITH_RC4_128_MD5"))
        return SSLSocket.SSL3_RSA_WITH_RC4_128_MD5;
      if (str.equals("SSL3_RSA_WITH_RC4_128_SHA"))
        return SSLSocket.SSL3_RSA_WITH_RC4_128_SHA;
      if (str.equals("SSL3_RSA_EXPORT_WITH_RC2_CBC_40_MD5"))
        return SSLSocket.SSL3_RSA_EXPORT_WITH_RC2_CBC_40_MD5;
      if (str.equals("SSL3_RSA_WITH_IDEA_CBC_SHA"))
        return SSLSocket.SSL3_RSA_WITH_IDEA_CBC_SHA;
      if (str.equals("SSL3_RSA_EXPORT_WITH_DES40_CBC_SHA"))
        return SSLSocket.SSL3_RSA_EXPORT_WITH_DES40_CBC_SHA;
      if (str.equals("SSL3_RSA_WITH_DES_CBC_SHA"))
        return SSLSocket.SSL3_RSA_WITH_DES_CBC_SHA;
      if (str.equals("SSL3_RSA_WITH_3DES_EDE_CBC_SHA"))
        return SSLSocket.SSL3_RSA_WITH_3DES_EDE_CBC_SHA;
                                                                                
      if (str.equals("SSL3_DH_DSS_EXPORT_WITH_DES40_CBC_SHA"))
        return SSLSocket.SSL3_DH_DSS_EXPORT_WITH_DES40_CBC_SHA;
      if (str.equals("SSL3_DH_DSS_WITH_DES_CBC_SHA"))
        return SSLSocket.SSL3_DH_DSS_WITH_DES_CBC_SHA;
      if (str.equals("SSL3_DH_DSS_WITH_3DES_EDE_CBC_SHA"))
        return SSLSocket.SSL3_DH_DSS_WITH_3DES_EDE_CBC_SHA;
      if (str.equals("SSL3_DH_RSA_EXPORT_WITH_DES40_CBC_SHA"))
        return SSLSocket.SSL3_DH_RSA_EXPORT_WITH_DES40_CBC_SHA;
      if (str.equals("SSL3_DH_RSA_WITH_DES_CBC_SHA"))
        return SSLSocket.SSL3_DH_RSA_WITH_DES_CBC_SHA;
      if (str.equals("SSL3_DH_RSA_WITH_3DES_EDE_CBC_SHA"))
        return SSLSocket.SSL3_DH_RSA_WITH_3DES_EDE_CBC_SHA;
                                                        
      if (str.equals("SSL3_DHE_DSS_EXPORT_WITH_DES40_CBC_SHA"))
        return SSLSocket.SSL3_DHE_DSS_EXPORT_WITH_DES40_CBC_SHA;
      if (str.equals("SSL3_DHE_DSS_WITH_DES_CBC_SHA"))
        return SSLSocket.SSL3_DHE_DSS_WITH_DES_CBC_SHA;
      if (str.equals("SSL3_DHE_DSS_WITH_3DES_EDE_CBC_SHA"))
        return SSLSocket.SSL3_DHE_DSS_WITH_3DES_EDE_CBC_SHA;
      if (str.equals("SSL3_DHE_RSA_EXPORT_WITH_DES40_CBC_SHA"))
        return SSLSocket.SSL3_DHE_RSA_EXPORT_WITH_DES40_CBC_SHA;
      if (str.equals("SSL3_DHE_RSA_WITH_DES_CBC_SHA"))
        return SSLSocket.SSL3_DHE_RSA_WITH_DES_CBC_SHA;
      if (str.equals("SSL3_DHE_RSA_WITH_3DES_EDE_CBC_SHA"))
        return SSLSocket.SSL3_DHE_RSA_WITH_3DES_EDE_CBC_SHA;
                                                                                
      if (str.equals("SSL3_DH_ANON_EXPORT_WITH_RC4_40_MD5"))
        return SSLSocket.SSL3_DH_ANON_EXPORT_WITH_RC4_40_MD5;
      if (str.equals("SSL3_DH_ANON_WITH_RC4_128_MD5"))
        return SSLSocket.SSL3_DH_ANON_WITH_RC4_128_MD5;
      if (str.equals("SSL3_DH_ANON_EXPORT_WITH_DES40_CBC_SHA"))
        return SSLSocket.SSL3_DH_ANON_EXPORT_WITH_DES40_CBC_SHA;
      if (str.equals("SSL3_DH_ANON_WITH_DES_CBC_SHA"))
        return SSLSocket.SSL3_DH_ANON_WITH_DES_CBC_SHA;
      if (str.equals("SSL3_DH_ANON_WITH_3DES_EDE_CBC_SHA"))
        return SSLSocket.SSL3_DH_ANON_WITH_3DES_EDE_CBC_SHA;
                                                                                
      if (str.equals("SSL3_FORTEZZA_DMS_WITH_NULL_SHA"))
        return SSLSocket.SSL3_FORTEZZA_DMS_WITH_NULL_SHA;
      if (str.equals("SSL3_FORTEZZA_DMS_WITH_FORTEZZA_CBC_SHA"))
        return SSLSocket.SSL3_FORTEZZA_DMS_WITH_FORTEZZA_CBC_SHA;
      if (str.equals("SSL3_FORTEZZA_DMS_WITH_RC4_128_SHA"))
        return SSLSocket.SSL3_FORTEZZA_DMS_WITH_RC4_128_SHA;
                                                                                
      if (str.equals("SSL_RSA_FIPS_WITH_3DES_EDE_CBC_SHA"))
        return SSLSocket.SSL_RSA_FIPS_WITH_3DES_EDE_CBC_SHA;
      if (str.equals("SSL_RSA_FIPS_WITH_DES_CBC_SHA"))
        return SSLSocket.SSL_RSA_FIPS_WITH_DES_CBC_SHA;
                                                                                
      // TLS
      if (str.equals("TLS_RSA_EXPORT1024_WITH_DES_CBC_SHA"))
        return SSLSocket.TLS_RSA_EXPORT1024_WITH_DES_CBC_SHA;
      if (str.equals("TLS_RSA_EXPORT1024_WITH_RC4_56_SHA"))
        return SSLSocket.TLS_RSA_EXPORT1024_WITH_RC4_56_SHA;
                                                                                
      if (str.equals("TLS_DHE_DSS_EXPORT1024_WITH_DES_CBC_SHA"))
        return SSLSocket.TLS_DHE_DSS_EXPORT1024_WITH_DES_CBC_SHA;
      if (str.equals("TLS_DHE_DSS_EXPORT1024_WITH_RC4_56_SHA"))
        return SSLSocket.TLS_DHE_DSS_EXPORT1024_WITH_RC4_56_SHA;
      if (str.equals("TLS_DHE_DSS_WITH_RC4_128_SHA"))
        return SSLSocket.TLS_DHE_DSS_WITH_RC4_128_SHA;
                                                                                
      if (str.equals("TLS_RSA_WITH_AES_128_CBC_SHA"))
        return SSLSocket.TLS_RSA_WITH_AES_128_CBC_SHA;
      if (str.equals("TLS_DH_DSS_WITH_AES_128_CBC_SHA"))
        return SSLSocket.TLS_DH_DSS_WITH_AES_128_CBC_SHA;
      if (str.equals("TLS_DH_RSA_WITH_AES_128_CBC_SHA"))
        return SSLSocket.TLS_DH_RSA_WITH_AES_128_CBC_SHA;
      if (str.equals("TLS_DHE_DSS_WITH_AES_128_CBC_SHA"))
        return SSLSocket.TLS_DHE_DSS_WITH_AES_128_CBC_SHA;
      if (str.equals("TLS_DHE_RSA_WITH_AES_128_CBC_SHA"))
        return SSLSocket.TLS_DHE_RSA_WITH_AES_128_CBC_SHA;
      if (str.equals("TLS_DH_ANON_WITH_AES_128_CBC_SHA"))
        return SSLSocket.TLS_DH_ANON_WITH_AES_128_CBC_SHA;
                                                                                
      if (str.equals("TLS_RSA_WITH_AES_256_CBC_SHA"))
        return SSLSocket.TLS_RSA_WITH_AES_256_CBC_SHA;
      if (str.equals("TLS_DH_DSS_WITH_AES_256_CBC_SHA"))
        return SSLSocket.TLS_DH_DSS_WITH_AES_256_CBC_SHA;
      if (str.equals("TLS_DH_RSA_WITH_AES_256_CBC_SHA"))
        return SSLSocket.TLS_DH_RSA_WITH_AES_256_CBC_SHA;
      if (str.equals("TLS_DHE_DSS_WITH_AES_256_CBC_SHA"))
        return SSLSocket.TLS_DHE_DSS_WITH_AES_256_CBC_SHA;
      if (str.equals("TLS_DHE_RSA_WITH_AES_256_CBC_SHA"))
        return SSLSocket.TLS_DHE_RSA_WITH_AES_256_CBC_SHA;
      if (str.equals("TLS_DH_ANON_WITH_AES_256_CBC_SHA"))
        return SSLSocket.TLS_DH_ANON_WITH_AES_256_CBC_SHA;

      // ECC
      if (str.equals("TLS_ECDH_ECDSA_WITH_NULL_SHA"))
        return TLS_ECDH_ECDSA_WITH_NULL_SHA;
      if (str.equals("TLS_ECDH_ECDSA_WITH_RC4_128_SHA"))
        return TLS_ECDH_ECDSA_WITH_RC4_128_SHA;
      if (str.equals("TLS_ECDH_ECDSA_WITH_3DES_EDE_CBC_SHA"))
        return TLS_ECDH_ECDSA_WITH_3DES_EDE_CBC_SHA;
      if (str.equals("TLS_ECDH_ECDSA_WITH_AES_128_CBC_SHA"))
        return TLS_ECDH_ECDSA_WITH_AES_128_CBC_SHA;
      if (str.equals("TLS_ECDH_ECDSA_WITH_AES_256_CBC_SHA"))
        return TLS_ECDH_ECDSA_WITH_AES_256_CBC_SHA;
                                                                               
      if (str.equals("TLS_ECDHE_ECDSA_WITH_NULL_SHA"))
        return TLS_ECDHE_ECDSA_WITH_NULL_SHA;
      if (str.equals("TLS_ECDHE_ECDSA_WITH_RC4_128_SHA"))
        return TLS_ECDHE_ECDSA_WITH_RC4_128_SHA;
      if (str.equals("TLS_ECDHE_ECDSA_WITH_3DES_EDE_CBC_SHA"))
        return TLS_ECDHE_ECDSA_WITH_3DES_EDE_CBC_SHA;
      if (str.equals("TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA"))
        return TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA;
      if (str.equals("TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA"))
        return TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA;

      if (str.equals("TLS_ECDHE_RSA_WITH_NULL_SHA"))
        return TLS_ECDHE_RSA_WITH_NULL_SHA;
      if (str.equals("TLS_ECDHE_RSA_WITH_RC4_128_SHA"))
        return TLS_ECDHE_RSA_WITH_RC4_128_SHA;
      if (str.equals("TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA"))
        return TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA;
      if (str.equals("TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA"))
        return TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA;
      if (str.equals("TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA"))
        return TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA;
                                                                                
      if (str.equals("TLS_ECDH_anon_WITH_NULL_SHA"))
        return TLS_ECDH_anon_WITH_NULL_SHA;
      if (str.equals("TLS_ECDH_anon_WITH_RC4_128_SHA"))
        return TLS_ECDH_anon_WITH_RC4_128_SHA;
      if (str.equals("TLS_ECDH_anon_WITH_3DES_EDE_CBC_SHA"))
        return TLS_ECDH_anon_WITH_3DES_EDE_CBC_SHA;
      if (str.equals("TLS_ECDH_anon_WITH_AES_128_CBC_SHA"))
        return TLS_ECDH_anon_WITH_AES_128_CBC_SHA;
      if (str.equals("TLS_ECDH_anon_WITH_AES_256_CBC_SHA"))
        return TLS_ECDH_anon_WITH_AES_256_CBC_SHA;

      return -1;
    }

    public void setSSLCiphers(String attr) throws SocketException
    {
      String ciphers = (String)attributes.get(attr);
      StringTokenizer st = new StringTokenizer(ciphers, ",");
      while (st.hasMoreTokens()) {
        String cipherstr = st.nextToken();
        String text = cipherstr.substring(1);
        int cipherid = 0;
        if (text.startsWith("0x")) {
          // this allows us to specify new ciphers
          cipherid = Integer.parseInt(text.substring(2));
        } else {
          cipherid = toCipherId(text);
        }
        boolean state = true;
        if (cipherstr.startsWith("+")) {
          state = true;
        } else {
          state = false;
        }
        if (cipherid >= 0) {
          SSLSocket.setCipherPreferenceDefault(cipherid, state);
        }
      }
    }

    public void setSSLOptions() throws SocketException
    {
      String options = (String)attributes.get("sslOptions");
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
          // JSS does not have a way to enable TLS
        }
      }
    }

    void init() throws IOException {
        try {
            String deb = (String)attributes.get("debug");
            if (deb.equals("true")) {
            debug = true;
            debugFile =  new FileWriter("/tmp/tomcatjss.log");
            debugWrite("JSSSocketFactory init - debug is on\n");
            }
        } catch (Exception e) {
	    //	    System.out.println("no tomcatjss debugging");
        }

        try {
            try {
                mPwdPath = (String)attributes.get("passwordFile");
		mPwdClass = (String)attributes.get("passwordClass");
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

            String certDir = (String)attributes.get("certdbDir");
   
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

            String clientAuthStr = (String)attributes.get("clientauth");
            File file = null;
            try {
                mServerCertNickPath = (String)attributes.get("serverCertNickFile");
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

            //serverCertNick = (String)attributes.get("serverCert");
            if (clientAuthStr.equalsIgnoreCase("true") ||
              clientAuthStr.equalsIgnoreCase("yes")) {
                requireClientAuth = true;
            } else if (clientAuthStr.equalsIgnoreCase("want")) {
                wantClientAuth = true;
            }
            //serverCertNick = "Server-Cert cert-tks";
            // 12 hours = 43200 seconds
            SSLServerSocket.configServerSessionIDCache(0, 43200, 43200, null);

            setSSLOptions();
        } catch (Exception ex) {
        }
        if (debugFile != null)
            debugFile.close();
    }

    public Socket acceptSocket(ServerSocket socket) throws IOException {
        SSLSocket asock = null;
        try {
            asock = (SSLSocket)socket.accept();
            if (wantClientAuth || requireClientAuth) {
                asock.requestClientAuth(requireClientAuth);
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
            s.setSoTimeout(120*1000);
            if (wantClientAuth || requireClientAuth) {
                s.requestClientAuth(requireClientAuth);
            } 
            s.setServerCertNickname(serverCertNick);
        } catch (Exception e) {
        }
    }
}
