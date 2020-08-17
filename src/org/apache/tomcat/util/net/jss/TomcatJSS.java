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

import java.io.File;
import java.io.FileReader;
import java.io.IOException;
import java.net.SocketException;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Enumeration;
import java.util.Properties;
import java.util.StringTokenizer;

import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.xpath.XPath;
import javax.xml.xpath.XPathConstants;
import javax.xml.xpath.XPathFactory;

import org.apache.commons.lang3.StringUtils;
import org.mozilla.jss.CryptoManager;
import org.mozilla.jss.InitializationValues;
import org.mozilla.jss.NoSuchTokenException;
import org.mozilla.jss.crypto.AlreadyInitializedException;
import org.mozilla.jss.crypto.CryptoToken;
import org.mozilla.jss.ssl.SSLAlertEvent;
import org.mozilla.jss.ssl.SSLHandshakeCompletedEvent;
import org.mozilla.jss.ssl.SSLProtocolVariant;
import org.mozilla.jss.ssl.SSLServerSocket;
import org.mozilla.jss.ssl.SSLSocket;
import org.mozilla.jss.ssl.SSLSocketListener;
import org.mozilla.jss.util.IncorrectPasswordException;
import org.mozilla.jss.util.Password;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.w3c.dom.Document;
import org.w3c.dom.Element;

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

    public void loadJSSConfig(String jssConf) throws Exception {
        File configFile = new File(jssConf);
        loadJSSConfig(configFile);
    }

    public void loadJSSConfig(File configFile) throws Exception {

        Properties config = new Properties();
        config.load(new FileReader(configFile));

        loadJSSConfig(config);
    }

    public void loadJSSConfig(Properties config) throws Exception {

        String certDb = config.getProperty("certdbDir");
        if (certDb != null)
            setCertdbDir(certDb);

        String passwordClass = config.getProperty("passwordClass");
        if (passwordClass != null)
            setPasswordClass(passwordClass);

        String passwordFile = config.getProperty("passwordFile");
        if (passwordFile != null)
            setPasswordFile(passwordFile);

        String enableOCSP = config.getProperty("enableOCSP");
        if (enableOCSP != null)
            setEnableOCSP(Boolean.parseBoolean(enableOCSP));

        String ocspResponderURL = config.getProperty("ocspResponderURL");
        if (ocspResponderURL != null)
            setOcspResponderURL(ocspResponderURL);

        String ocspResponderCertNickname = config.getProperty("ocspResponderCertNickname");
        if (ocspResponderCertNickname != null)
            setOcspResponderCertNickname(ocspResponderCertNickname);

        String ocspCacheSize = config.getProperty("ocspCacheSize");
        if (StringUtils.isNotEmpty(ocspCacheSize))
            setOcspCacheSize(Integer.parseInt(ocspCacheSize));

        String ocspMinCacheEntryDuration = config.getProperty("ocspMinCacheEntryDuration");
        if (StringUtils.isNotEmpty(ocspMinCacheEntryDuration))
            setOcspMinCacheEntryDuration(Integer.parseInt(ocspMinCacheEntryDuration));

        String ocspMaxCacheEntryDuration = config.getProperty("ocspMaxCacheEntryDuration");
        if (StringUtils.isNotEmpty(ocspMaxCacheEntryDuration))
            setOcspMaxCacheEntryDuration(Integer.parseInt(ocspMaxCacheEntryDuration));

        String ocspTimeout = config.getProperty("ocspTimeout");
        if (StringUtils.isNotEmpty(ocspTimeout))
            setOcspTimeout(Integer.parseInt(ocspTimeout));
    }

    public void loadTomcatConfig(String serverXml) throws Exception {
        File configFile = new File(serverXml);
        loadTomcatConfig(configFile);
    }

    public void loadTomcatConfig(File configFile) throws Exception {

        DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
        DocumentBuilder builder = factory.newDocumentBuilder();
        Document document = builder.parse(configFile);

        loadTomcatConfig(document);
    }

    public void loadTomcatConfig(Document document) throws Exception {

        XPathFactory xPathfactory = XPathFactory.newInstance();
        XPath xpath = xPathfactory.newXPath();

        Element connector = (Element) xpath.evaluate(
                "/Server/Service[@name='Catalina']/Connector[@SSLEnabled='true']",
                document, XPathConstants.NODE);

        String certDb = connector.getAttribute("certdbDir");
        if (certDb != null)
            setCertdbDir(certDb);

        String passwordClass = connector.getAttribute("passwordClass");
        if (passwordClass != null)
            setPasswordClass(passwordClass);

        String passwordFile = connector.getAttribute("passwordFile");
        if (passwordFile != null)
            setPasswordFile(passwordFile);

        String serverCertNickFile = connector.getAttribute("serverCertNickFile");
        if (serverCertNickFile != null)
            setServerCertNickFile(serverCertNickFile);

        String enableOCSP = connector.getAttribute("enableOCSP");
        if (enableOCSP != null)
            setEnableOCSP(Boolean.parseBoolean(enableOCSP));

        String ocspResponderURL = connector.getAttribute("ocspResponderURL");
        if (ocspResponderURL != null)
            setOcspResponderURL(ocspResponderURL);

        String ocspResponderCertNickname = connector.getAttribute("ocspResponderCertNickname");
        if (ocspResponderCertNickname != null)
            setOcspResponderCertNickname(ocspResponderCertNickname);

        String ocspCacheSize = connector.getAttribute("ocspCacheSize");
        if (StringUtils.isNotEmpty(ocspCacheSize))
            setOcspCacheSize(Integer.parseInt(ocspCacheSize));

        String ocspMinCacheEntryDuration = connector.getAttribute("ocspMinCacheEntryDuration");
        if (StringUtils.isNotEmpty(ocspMinCacheEntryDuration))
            setOcspMinCacheEntryDuration(Integer.parseInt(ocspMinCacheEntryDuration));

        String ocspMaxCacheEntryDuration = connector.getAttribute("ocspMaxCacheEntryDuration");
        if (StringUtils.isNotEmpty(ocspMaxCacheEntryDuration))
            setOcspMaxCacheEntryDuration(Integer.parseInt(ocspMaxCacheEntryDuration));

        String ocspTimeout = connector.getAttribute("ocspTimeout");
        if (StringUtils.isNotEmpty(ocspTimeout))
            setOcspTimeout(Integer.parseInt(ocspTimeout));
    }

    public void init() throws Exception {

        if (initialized) {
            return;
        }

        logger.info("TomcatJSS: initialization");

        if (certdbDir == null) {
            certdbDir = System.getProperty("catalina.base") + File.separator + "alias";
        }

        logger.debug("TomcatJSS: certdbDir: " + certdbDir);

        if (passwordClass == null) {
            passwordClass = PlainPasswordFile.class.getName();
        }

        logger.debug("TomcatJSS: passwordClass: " + passwordClass);

        if (passwordFile == null) {
            passwordFile = System.getProperty("catalina.base") + File.separator +
                    "conf" + File.separator + "password.conf";
        }

        logger.debug("TomcatJSS: passwordFile: " + passwordFile);

        if (serverCertNickFile != null) {
            logger.debug("TomcatJSS: serverCertNickFile: " + serverCertNickFile);
        }

        InitializationValues vals = new InitializationValues(certdbDir);

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

        if (serverCertNickFile != null) {
            serverCertNick = new String(Files.readAllBytes(Paths.get(serverCertNickFile))).trim();
            logger.debug("serverCertNick: " + serverCertNick);
        }

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

        if (token.isLoggedIn()) {
            logger.debug("TomcatJSS: already logged into " + tag);
            return;
        }

        logger.debug("TomcatJSS: logging into " + tag);

        int iteration = 0;
        do {
            String strPassword = passwordStore.getPassword(tag, iteration);

            if (strPassword == null) {
                logger.debug("TomcatJSS: no password for " + tag);
                return;
            }

            Password password = new Password(strPassword.toCharArray());

            try {
                token.login(password);
                return;

            } catch (IncorrectPasswordException e) {
                logger.warn("TomcatJSS: incorrect password");
                iteration ++;

            } finally {
                password.clear();
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
            ocspResponderURL = null;
        }

        logger.debug("ocspResponderCertNickname: " + ocspResponderCertNickname);
        if (StringUtils.isEmpty(ocspResponderCertNickname)) {
            ocspResponderCertNickname = null;
        }

        // Check to see if the ocsp url and nickname are both set or not set

        if (ocspResponderURL == null && ocspResponderCertNickname != null) {
            throw new Exception("Missing OCSP responder URL");
        }

        if (ocspResponderURL != null && ocspResponderCertNickname == null) {
            throw new Exception("Missing OCSP responder certificate nickname");
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
