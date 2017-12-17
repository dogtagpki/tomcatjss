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

import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Enumeration;
import java.util.logging.Logger;

import org.mozilla.jss.CryptoManager;
import org.mozilla.jss.NoSuchTokenException;
import org.mozilla.jss.crypto.AlreadyInitializedException;
import org.mozilla.jss.crypto.CryptoToken;
import org.mozilla.jss.ssl.SSLAlertEvent;
import org.mozilla.jss.ssl.SSLHandshakeCompletedEvent;
import org.mozilla.jss.ssl.SSLSocketListener;
import org.mozilla.jss.util.IncorrectPasswordException;
import org.mozilla.jss.util.Password;

public class TomcatJSS implements SSLSocketListener {

    final static Logger logger = Logger.getLogger(TomcatJSS.class.getName());

    public final static TomcatJSS INSTANCE = new TomcatJSS();
    public static final int MAX_LOGIN_ATTEMPTS = 3;

    public static TomcatJSS getInstance() { return INSTANCE; }

    String certdbDir;
    String passwordClass;
    String passwordFile;
    String serverCertNickFile;
    String serverCertNick;

    IPasswordStore passwordStore;

    Collection<SSLSocketListener> socketListeners = new ArrayList<SSLSocketListener>();

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

    public void setServerCertNickFile(String serverCertNickFile) {
        this.serverCertNickFile = serverCertNickFile;
    }

    public void setServerCertNick(String serverCertNick) {
        this.serverCertNick = serverCertNick;
    }

    public String getServerCertNick() {
        return serverCertNick;
    }

    public IPasswordStore getPasswordStore() {
        return passwordStore;
    }

    public void setPasswordStore(IPasswordStore passwordStore) {
        this.passwordStore = passwordStore;
    }

    public void init() throws Exception {

        logger.info("TomcatJSS: initialization");

        logger.fine("certdbDir: " + certdbDir);
        logger.fine("passwordClass: " + passwordClass);
        logger.fine("passwordFile: " + passwordFile);
        logger.fine("serverCertNickFile: " + serverCertNickFile);

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
            logger.warning("TomcatJSS: " + e);
        }

        passwordStore = (IPasswordStore) Class.forName(passwordClass).newInstance();
        passwordStore.init(passwordFile);

        login();

        serverCertNick = new String(Files.readAllBytes(Paths.get(serverCertNickFile))).trim();
        logger.fine("serverCertNick: " + serverCertNick);

        logger.info("TomcatJSS: initialization complete");
    }

    public void login() throws Exception {

        logger.fine("TomcatJSS: logging into tokens");

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
            logger.warning("TomcatJSS: token for " + tag + " not found");
            return;
        }

        int iteration = 0;
        do {
            String strPassword = passwordStore.getPassword(tag, iteration);

            if (strPassword == null) {
                logger.fine("TomcatJSS: no password for " + tag);
                return;
            }

            Password password = new Password(strPassword.toCharArray());

            if (token.isLoggedIn()) {
                logger.fine("TomcatJSS: already logged into " + tag);
                return;
            }

            logger.fine("TomcatJSS: logging into " + tag);
            try {
                token.login(password);
                return;

            } catch (IncorrectPasswordException e) {
                logger.warning("TomcatJSS: incorrect password");
                iteration ++;
            }

        } while (iteration < MAX_LOGIN_ATTEMPTS);

        logger.severe("TomcatJSS: failed to log into " + tag);
    }

    public CryptoToken getToken(String tag) throws Exception {

        CryptoManager manager = CryptoManager.getInstance();

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

    public void addSocketListener(SSLSocketListener listener) {
        socketListeners.add(listener);
    }

    public void removeSocketListener(SSLSocketListener listener) {
        socketListeners.remove(listener);
    }

    public Collection<SSLSocketListener> getSocketListeners() {
        return socketListeners;
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
