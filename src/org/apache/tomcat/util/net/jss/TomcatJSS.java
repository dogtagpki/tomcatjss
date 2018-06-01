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
 * Copyright (C) 2017 Red Hat, Inc.
 * All rights reserved.
 * END COPYRIGHT BLOCK */

package org.apache.tomcat.util.net.jss;

import java.io.IOException;
import java.net.SocketException;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Enumeration;
import java.util.StringTokenizer;

import org.apache.commons.lang.StringUtils;
import org.mozilla.jss.CryptoManager;
import org.mozilla.jss.NoSuchTokenException;
import org.mozilla.jss.crypto.AlreadyInitializedException;
import org.mozilla.jss.crypto.CryptoToken;
import org.mozilla.jss.ssl.SSLAlertEvent;
import org.mozilla.jss.ssl.SSLCipher;
import org.mozilla.jss.ssl.SSLHandshakeCompletedEvent;
import org.mozilla.jss.ssl.SSLServerSocket;
import org.mozilla.jss.ssl.SSLSocket;
import org.mozilla.jss.ssl.SSLSocket.SSLProtocolVariant;
import org.mozilla.jss.ssl.SSLSocket.SSLVersionRange;
import org.mozilla.jss.ssl.SSLSocketListener;
import org.mozilla.jss.util.IncorrectPasswordException;
import org.mozilla.jss.util.Password;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class TomcatJSS implements SSLSocketListener {

    public static Logger logger = LoggerFactory.getLogger(TomcatJSS.class);

    public final static TomcatJSS INSTANCE = new TomcatJSS();
    public static final int MAX_LOGIN_ATTEMPTS = 3;

    public static TomcatJSS getInstance() { return INSTANCE; }

    Collection<SSLSocketListener> socketListeners = new ArrayList<SSLSocketListener>();

    String certdbDir;
    CryptoManager manager;

    String passwordClass;
    String passwordFile;
    IPasswordStore passwordStore;

    String serverCertNickFile;
    String serverCertNick;

    String clientAuth = "want";
    boolean requireClientAuth;
    boolean wantClientAuth;

    boolean enableOCSP;
    String ocspResponderURL;
    String ocspResponderCertNickname;
    int ocspCacheSize = 1000; // entries
    int ocspMinCacheEntryDuration = 3600; // seconds (default: 1 hour)
    int ocspMaxCacheEntryDuration = 86400; // seconds (default: 24 hours)
    int ocspTimeout = 60; // seconds (default: 1 minute)

    String strictCiphers;
    boolean boolStrictCiphers;
    String sslVersionRangeStream;
    String sslVersionRangeDatagram;

    String sslRangeCiphers;
    String sslOptions;
    String ssl2Ciphers;
    String ssl3Ciphers;
    String tlsCiphers;

    boolean initialized;

    public void addSocketListener(SSLSocketListener listener) {
        socketListeners.add(listener);
    }

    public void removeSocketListener(SSLSocketListener listener) {
        socketListeners.remove(listener);
    }

    public Collection<SSLSocketListener> getSocketListeners() {
        return socketListeners;
    }

    public String getCertdbDir() {
        return certdbDir;
    }

    public void setCertdbDir(String certdbDir) {
        this.certdbDir = certdbDir;
    }

    public String getPasswordClass() {
        return passwordClass;
    }

    public void setPasswordClass(String passwordClass) {
        this.passwordClass = passwordClass;
    }

    public String getPasswordFile() {
        return passwordFile;
    }

    public void setPasswordFile(String passwordFile) {
        this.passwordFile = passwordFile;
    }

    public String getServerCertNickFile() {
        return serverCertNickFile;
    }

    public IPasswordStore getPasswordStore() {
        return passwordStore;
    }

    public void setPasswordStore(IPasswordStore passwordStore) {
        this.passwordStore = passwordStore;
    }

    public void setServerCertNickFile(String serverCertNickFile) {
        this.serverCertNickFile = serverCertNickFile;
    }

    public String getServerCertNick() {
        return serverCertNick;
    }

    public void setServerCertNick(String serverCertNick) {
        this.serverCertNick = serverCertNick;
    }

    public String getClientAuth() {
        return clientAuth;
    }

    public void setClientAuth(String clientAuth) {
        this.clientAuth = clientAuth;
    }

    public boolean getRequireClientAuth() {
        return requireClientAuth;
    }

    public boolean getWantClientAuth() {
        return wantClientAuth;
    }

    public boolean getEnableOCSP() {
        return enableOCSP;
    }

    public void setEnableOCSP(boolean enableOCSP) {
        this.enableOCSP = enableOCSP;
    }

    public String getOcspResponderURL() {
        return ocspResponderURL;
    }

    public void setOcspResponderURL(String ocspResponderURL) {
        this.ocspResponderURL = ocspResponderURL;
    }

    public String getOcspResponderCertNickname() {
        return ocspResponderCertNickname;
    }

    public void setOcspResponderCertNickname(String ocspResponderCertNickname) {
        this.ocspResponderCertNickname = ocspResponderCertNickname;
    }

    public int getOcspCacheSize() {
        return ocspCacheSize;
    }

    public void setOcspCacheSize(int ocspCacheSize) {
        this.ocspCacheSize = ocspCacheSize;
    }

    public int getOcspMinCacheEntryDuration() {
        return ocspMinCacheEntryDuration;
    }

    public void setOcspMinCacheEntryDuration(int ocspMinCacheEntryDuration) {
        this.ocspMinCacheEntryDuration = ocspMinCacheEntryDuration;
    }

    public int getOcspMaxCacheEntryDuration() {
        return ocspMaxCacheEntryDuration;
    }

    public void setOcspMaxCacheEntryDuration(int ocspMaxCacheEntryDuration) {
        this.ocspMaxCacheEntryDuration = ocspMaxCacheEntryDuration;
    }

    public int getOcspTimeout() {
        return ocspTimeout;
    }

    public void setOcspTimeout(int ocspTimeout) {
        this.ocspTimeout = ocspTimeout;
    }

    public String getStrictCiphers() {
        return strictCiphers;
    }

    public void setStrictCiphers(String strictCiphers) {
        this.strictCiphers = strictCiphers;
    }

    public String getSslVersionRangeStream() {
        return sslVersionRangeStream;
    }

    public void setSslVersionRangeStream(String sslVersionRangeStream) {
        this.sslVersionRangeStream = sslVersionRangeStream;
    }

    public String getSslVersionRangeDatagram() {
        return sslVersionRangeDatagram;
    }

    public void setSslVersionRangeDatagram(String sslVersionRangeDatagram) {
        this.sslVersionRangeDatagram = sslVersionRangeDatagram;
    }

    public String getSslRangeCiphers() {
        return sslRangeCiphers;
    }

    public void setSslRangeCiphers(String sslRangeCiphers) {
        this.sslRangeCiphers = sslRangeCiphers;
    }

    public String getSslOptions() {
        return sslOptions;
    }

    public void setSslOptions(String sslOptions) {
        this.sslOptions = sslOptions;
    }

    public String getSsl2Ciphers() {
        return ssl2Ciphers;
    }

    public void setSsl2Ciphers(String ssl2Ciphers) {
        this.ssl2Ciphers = ssl2Ciphers;
    }

    public String getSsl3Ciphers() {
        return ssl3Ciphers;
    }

    public void setSsl3Ciphers(String ssl3Ciphers) {
        this.ssl3Ciphers = ssl3Ciphers;
    }

    public String getTlsCiphers() {
        return tlsCiphers;
    }

    public void setTlsCiphers(String tlsCiphers) {
        this.tlsCiphers = tlsCiphers;
    }

    public void init() throws Exception {

        if (initialized) {
            return;
        }

        logger.info("TomcatJSS: initialization");

        logger.debug("certdbDir: " + certdbDir);
        logger.debug("passwordClass: " + passwordClass);
        logger.debug("passwordFile: " + passwordFile);
        logger.debug("serverCertNickFile: " + serverCertNickFile);

        if (certdbDir == null) {
            throw new Exception("Missing certdbDir");
        }

        if (passwordClass == null) {
            throw new Exception("Missing passwordClass");
        }

        if (serverCertNickFile == null) {
            throw new Exception("Missing serverCertNickFile");
        }

        CryptoManager.InitializationValues vals = new CryptoManager.InitializationValues(
                certdbDir, "", "", "secmod.db");

        vals.removeSunProvider = false;
        vals.installJSSProvider = true;

        try {
            CryptoManager.initialize(vals);

        } catch (AlreadyInitializedException e) {
            logger.warn("TomcatJSS: " + e);
        }

        manager = CryptoManager.getInstance();

        passwordStore = (IPasswordStore) Class.forName(passwordClass).newInstance();
        passwordStore.init(passwordFile);

        login();

        serverCertNick = new String(Files.readAllBytes(Paths.get(serverCertNickFile))).trim();
        logger.debug("serverCertNick: " + serverCertNick);

        logger.debug("clientAuth: " + clientAuth);
        if (clientAuth.equalsIgnoreCase("true")) {
            requireClientAuth = true;

        } else if (clientAuth.equalsIgnoreCase("yes")) {
            requireClientAuth = true;
            logger.warn("The \"yes\" value for clientAuth has been deprecated. Use \"true\" instead.");

        } else if (clientAuth.equalsIgnoreCase("want")) {
            wantClientAuth = true;
        }

        logger.debug("requireClientAuth: " + requireClientAuth);
        logger.debug("wantClientAuth: " + wantClientAuth);

        if (requireClientAuth || wantClientAuth) {
            configureOCSP();
        }

        // 12 hours = 43200 seconds
        SSLServerSocket.configServerSessionIDCache(0, 43200, 43200, null);

        logger.debug("strictCiphers: " + strictCiphers);
        if ("true".equalsIgnoreCase(strictCiphers)) {
            boolStrictCiphers = true;

        } else if ("yes".equalsIgnoreCase(strictCiphers)) {
            boolStrictCiphers = true;
            logger.warn("The \"yes\" value for strictCiphers has been deprecated. Use \"true\" instead.");
        }

        if (boolStrictCiphers) {
            // what ciphers do we have to start with? turn them all off
            unsetSSLCiphers();
        }

        logger.debug("sslVersionRangeStream: " + sslVersionRangeStream);
        if (StringUtils.isNotEmpty(sslVersionRangeStream)) {
            setSSLVersionRangeDefault(
                    "STREAM",
                    SSLProtocolVariant.STREAM,
                    sslVersionRangeStream);
        }

        logger.debug("sslVersionRangeDatagram: " + sslVersionRangeDatagram);
        if (StringUtils.isNotEmpty(sslVersionRangeDatagram)) {
            setSSLVersionRangeDefault(
                    "DATA_GRAM",
                    SSLProtocolVariant.DATA_GRAM,
                    sslVersionRangeDatagram);
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
        if (StringUtils.isNotEmpty(sslVersionRangeStream)
                || StringUtils.isNotEmpty(sslVersionRangeDatagram)) {
            /* deliberately lose the ssl2 here */
            setSSLCiphers("sslRangeCiphers", sslRangeCiphers);

        } else {
            setSSLOptions();
        }

        logger.info("TomcatJSS: initialization complete");

        initialized = true;
    }

    public void login() throws Exception {

        logger.debug("TomcatJSS: logging into tokens");

        Enumeration<String> tags = passwordStore.getTags();

        while (tags.hasMoreElements()) {

            String tag = tags.nextElement();
            if (!tag.equals("internal") && !tag.startsWith("hardware-")) {
                continue;
            }

            login(tag);
        }
    }

    public void login(String tag) throws Exception {

        CryptoToken token;
        try {
            token = getToken(tag);
        } catch (NoSuchTokenException e) {
            logger.warn("TomcatJSS: token for " + tag + " not found");
            return;
        }

        int iteration = 0;
        do {
            String strPassword = passwordStore.getPassword(tag, iteration);

            if (strPassword == null) {
                logger.debug("TomcatJSS: no password for " + tag);
                return;
            }

            Password password = new Password(strPassword.toCharArray());

            if (token.isLoggedIn()) {
                logger.debug("TomcatJSS: already logged into " + tag);
                return;
            }

            logger.debug("TomcatJSS: logging into " + tag);
            try {
                token.login(password);
                return;

            } catch (IncorrectPasswordException e) {
                logger.warn("TomcatJSS: incorrect password");
                iteration ++;
            }

        } while (iteration < MAX_LOGIN_ATTEMPTS);

        logger.error("TomcatJSS: failed to log into " + tag);
    }

    public CryptoToken getToken(String tag) throws Exception {

        if (tag.equals("internal")) {
            return manager.getInternalKeyStorageToken();
        }

        if (tag.startsWith("hardware-")) {
            String tokenName = tag.substring(9);
            return manager.getTokenByName(tokenName);
        }

        // non-token password entry
        return null;
    }

    public void configureOCSP() throws Exception {

        logger.info("configuring OCSP");

        logger.debug("enableOCSP: " + enableOCSP);
        if (!enableOCSP) {
            return;
        }

        logger.debug("ocspResponderURL: " + ocspResponderURL);
        if (StringUtils.isEmpty(ocspResponderURL)) {
            throw new Exception("Missing ocspResponderURL");
        }

        logger.debug("ocspResponderCertNickname: " + ocspResponderCertNickname);
        if (StringUtils.isEmpty(ocspResponderCertNickname)) {
            throw new Exception("Missing ocspResponderCertNickname");
        }

        manager.configureOCSP(
                true,
                ocspResponderURL,
                ocspResponderCertNickname);

        logger.debug("ocspCacheSize: " + ocspCacheSize);
        logger.debug("ocspMinCacheEntryDuration: " + ocspMinCacheEntryDuration);
        logger.debug("ocspMaxCacheEntryDuration: " + ocspMaxCacheEntryDuration);

        manager.OCSPCacheSettings(ocspCacheSize,
                ocspMinCacheEntryDuration,
                ocspMaxCacheEntryDuration);

        logger.debug("ocspTimeout: " + ocspTimeout);

        manager.setOCSPTimeout(ocspTimeout);
    }

    /**
     * Disables all SSL ciphers to start with a clean slate.
     */
    public void unsetSSLCiphers() throws SocketException {

        logger.debug("Disabling SSL ciphers:");

        int[] cipherIDs = SSLSocket.getImplementedCipherSuites();
        if (cipherIDs == null) return;

        for (int cipherID : cipherIDs) {

            StringBuilder sb = new StringBuilder();
            sb.append("* 0x");
            sb.append(Integer.toHexString(cipherID));

            SSLCipher cipher = SSLCipher.valueOf(cipherID);
            if (cipher != null) {
                sb.append(": ");
                sb.append(cipher.name());
            }

            logger.debug(sb.toString());

            SSLSocket.setCipherPreferenceDefault(cipherID, false);
        }
    }

    /**
     * setSSLVersionRangeDefault sets the range of allowed SSL versions. This
     * replaces the obsolete SSL_Option* API.
     *
     * @param protoVariant indicates whether this setting is for type "stream"
     * or "datagram".
     *
     * @param sslVersionRange_s takes on the form of "min:max" where min/max
     * values can be "ssl3, tls1_0, tls1_1, or tls1_2". ssl2 is not supported for
     * tomcatjss via this interface. The format is "sslVersionRange=min:max".
     */
    public void setSSLVersionRangeDefault(
            String type,
            SSLProtocolVariant protoVariant,
            String sslVersionRange_s) throws SocketException,
            IllegalArgumentException, IOException {

        String[] sslVersionRange = sslVersionRange_s.split(":");
        if (sslVersionRange.length != 2) {
            throw new SocketException("SSL version range format error: " + sslVersionRange_s);
        }

        String min_s = sslVersionRange[0];
        String max_s = sslVersionRange[1];

        logger.debug("Setting SSL version range for " + type + ":");
        logger.debug("* min: " + min_s);
        logger.debug("* max: " + max_s);

        int min = getSSLVersionRangeEnum(min_s);
        int max = getSSLVersionRangeEnum(max_s);

        if (min == -1 || max == -1) {
            throw new SocketException("SSL version range format error: " + sslVersionRange_s);
        }

        SSLVersionRange range = new SSLVersionRange(min, max);
        SSLSocket.setSSLVersionRangeDefault(protoVariant, range);
    }

    int getSSLVersionRangeEnum(String range) {

        if (range == null) {
            return -1;
        }

        if (range.equals("ssl3")) {
            return SSLVersionRange.ssl3;
        }

        if (range.equals("tls1_0")) {
            return SSLVersionRange.tls1_0;
        }

        if (range.equals("tls1_1")) {
            return SSLVersionRange.tls1_1;
        }

        if (range.equals("tls1_2")) {
            return SSLVersionRange.tls1_2;
        }

        return -1;
    }

    public void setSSLCiphers(String attr, String ciphers) throws SocketException, IOException {

        if (StringUtils.isEmpty(ciphers)) {
            logger.debug("Missing " + attr);
            return;
        }

        logger.debug("Processing " + attr + ":");
        StringTokenizer st = new StringTokenizer(ciphers, ", ");
        while (st.hasMoreTokens()) {
            String cipherStr = st.nextToken();

            String name;
            boolean enabled;

            if (cipherStr.startsWith("+")) {
                enabled = true;
                name = cipherStr.substring(1);
            } else if (cipherStr.startsWith("-")) {
                enabled = false;
                name = cipherStr.substring(1);
            } else {
                enabled = true; // no enable/disable flag, assume enable
                name = cipherStr;
            }

            logger.debug("* " + name);
            logger.debug("  enabled: " + enabled);

            int cipherID;

            if (name.startsWith("0x") || name.startsWith("0X")) {
                // this allows us to specify new ciphers
                try {
                    cipherID = Integer.parseInt(name.substring(2), 16);
                } catch (Exception e) {
                    logger.error("Invalid SSL cipher: " + name);
                    continue;
                }
            } else {
                try {
                    SSLCipher cipher = SSLCipher.valueOf(name);
                    cipherID = cipher.getID();
                } catch (IllegalArgumentException e) {
                    logger.error("Unknown SSL cipher: " + name);
                    continue;
                }
            }

            logger.debug("  ID: 0x" + Integer.toHexString(cipherID));

            try {
                SSLSocket.setCipherPreferenceDefault(cipherID, enabled);

            } catch (Exception e) {
                logger.warn("Unable to set SSL cipher preference: " + e);
                SSLCipher cipher = SSLCipher.valueOf(cipherID);
                if (cipher != null && cipher.isECC()) {
                    logger.warn("SSL ECC cipher \""
                                    + name
                                    + "\" unsupported by NSS. "
                                    + "This is probably O.K. unless ECC support has been installed.");
                } else {
                    logger.error("SSL cipher \"" + name
                            + "\" unsupported by NSS");
                }
            }
        }
    }

    /**
     * note: the SSL_OptionSet-based API for controlling the enabled protocol
     * versions are obsolete and replaced by the setSSLVersionRange calls. If
     * the "range" parameters are present in the attributes then the sslOptions
     * parameter is ignored.
     */
    public void setSSLOptions() throws SocketException, IOException {

        if (StringUtils.isEmpty(sslOptions)) {
            logger.debug("JSSSocketFactory: no sslOptions specified");
            return;
        }

        logger.debug("JSSSocketFactory: Processing sslOptions:");
        StringTokenizer st = new StringTokenizer(sslOptions, ", ");
        while (st.hasMoreTokens()) {
            String option = st.nextToken();
            logger.debug("JSSSocketFactory:  - " + option);

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

    @Override
    public void alertReceived(SSLAlertEvent event) {
        for (SSLSocketListener listener : socketListeners) {
            listener.alertReceived(event);
        }
    }

    @Override
    public void alertSent(SSLAlertEvent event) {
        for (SSLSocketListener listener : socketListeners) {
            listener.alertSent(event);
        }
    }

    @Override
    public void handshakeCompleted(SSLHandshakeCompletedEvent event) {
        for (SSLSocketListener listener : socketListeners) {
            listener.handshakeCompleted(event);
        }
    }
}
