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
 * Copyright (C) 2019 Red Hat, Inc.
 * All rights reserved.
 * END COPYRIGHT BLOCK */

package org.dogtagpki.tomcat;

import java.io.File;

import org.apache.catalina.Lifecycle;
import org.apache.catalina.LifecycleEvent;
import org.apache.catalina.LifecycleListener;
import org.apache.tomcat.util.net.jss.TomcatJSS;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class JSSListener implements LifecycleListener {

    final static Logger logger = LoggerFactory.getLogger(JSSListener.class);

    public String configFile;

    public String getConfigFile() {
        return configFile;
    }

    public void setConfigFile(String configFile) {
        this.configFile = configFile;
    }

    @Override
    public void lifecycleEvent(LifecycleEvent event) {

        String type = event.getType();

        if (type.equals(Lifecycle.BEFORE_INIT_EVENT)) {
            initJSS();
        }
    }

    public void initJSS() {

        logger.info("JSSListener: Initializing JSS");

        try {
            TomcatJSS tomcatjss = TomcatJSS.getInstance();

            String catalinaBase = System.getProperty("catalina.base");
            String jssConf = catalinaBase + "/conf/jss.conf";
            File configFile = new File(jssConf);

            if (configFile.exists()) {
                logger.info("JSSListener: Loading JSS configuration from " + jssConf);
                tomcatjss.loadJSSConfig(configFile);

            } else {
                String serverXml = catalinaBase + "/conf/server.xml";
                logger.info("JSSListener: Loading JSS configuration from " + serverXml);
                tomcatjss.loadTomcatConfig(serverXml);
            }

            tomcatjss.init();

        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }
}
