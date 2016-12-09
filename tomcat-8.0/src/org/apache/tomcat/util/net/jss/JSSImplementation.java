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

import java.io.FileNotFoundException;
import java.io.FileReader;
import java.io.IOException;
import java.net.Socket;
import java.util.Properties;
import java.util.logging.Level;
import java.util.logging.Logger;

import org.apache.tomcat.util.net.AbstractEndpoint;
import org.apache.tomcat.util.net.SSLImplementation;
import org.apache.tomcat.util.net.SSLSupport;
import org.apache.tomcat.util.net.SSLUtil;
import org.apache.tomcat.util.net.ServerSocketFactory;

public class JSSImplementation extends SSLImplementation {

    final static Logger logger = Logger.getLogger(JSSImplementation.class.getName());

    static final String JSSFactory = "org.apache.tomcat.util.net.jss.JSSFactory";
    static final String SSLSocketClass = "org.mozilla.jss.ssl.SSLSocket";

    private JSSFactory factory = null;

    public JSSImplementation() throws ClassNotFoundException {
        Class.forName(SSLSocketClass);

        try {
            Class<?> factcl = Class.forName(JSSFactory);
            factory = (JSSFactory) factcl.newInstance();
        } catch (Exception e) {
            logger.log(Level.SEVERE, "Error getting factory: " + JSSFactory, e);
        }
    }

    public String getImplementationName() {
        return "JSS";
    }

    public ServerSocketFactory getServerSocketFactory(AbstractEndpoint<?> endpoint) {

        Properties config = new Properties();

        try {
            String configFile = System.getProperty("catalina.base") + "/conf/tomcatjss.conf";
            config.load(new FileReader(configFile));
        } catch (FileNotFoundException e) {
            // ignore
        } catch (IOException e) {
            throw new RuntimeException(e);
        }

        return factory.getSocketFactory(endpoint, config);
    }

    public SSLSupport getSSLSupport(Socket s) {
        SSLSupport ssls = null;
        ssls = factory.getSSLSupport(s);
        return ssls;
    }

    public SSLSupport getSSLSupport(javax.net.ssl.SSLSession session) {
        /*
         * The Tomcat 6.0.26 docs says: This method has been deprecated since it
         * adds a JSSE dependency to this interface. It will be removed in
         * versions after 6.0.x.
         *
         * But we have to provide a implementation of this method because it's
         * declared as abstract.
         *
         * Unfortunately there does not appear to be any way to get SSLSupport
         * information from a session with JSS. JSS looks up the information
         * based on a socket, not a session. This done in SSLSocket.c
         * Java_org_mozilla_jss_ssl_SSLSocket_getStatus().
         *
         * So while it would be nice to provide a working implmentation there
         * doesn't seem to be an easy way to do this. Given that this method is
         * already deprecated and there hasn't been any evidence of it being
         * called it therefore seems reasonable to just return null to satify
         * the compiler's demand for an implementation.
         *
         * Once this abstract method is removed from SSLImplementation in a
         * future release we can remove this stub.
         *
         * NOTE: This method has NOT yet been deprecated in Tomcat 7!
         */
        return null;
    }

    public SSLUtil getSSLUtil(AbstractEndpoint<?> endpoint) {
        return null;
    }
}
