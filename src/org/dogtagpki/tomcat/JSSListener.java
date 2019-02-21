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
import java.io.FileReader;
import java.util.Properties;

import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.xpath.XPath;
import javax.xml.xpath.XPathConstants;
import javax.xml.xpath.XPathFactory;

import org.apache.catalina.Lifecycle;
import org.apache.catalina.LifecycleEvent;
import org.apache.catalina.LifecycleListener;
import org.apache.commons.lang.StringUtils;
import org.apache.tomcat.util.net.jss.TomcatJSS;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.w3c.dom.Document;
import org.w3c.dom.Element;

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
        logger.info("JSSListener: Config: " + configFile);

        try {
            if (configFile != null) {
                loadJSSConfig();
            } else {
                loadServerXml();
            }

            TomcatJSS tomcatjss = TomcatJSS.getInstance();
            tomcatjss.init();

        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    public void loadJSSConfig() throws Exception {

        Properties properties = new Properties();
        properties.load(new FileReader(configFile));

        TomcatJSS tomcatjss = TomcatJSS.getInstance();

        String certDb = properties.getProperty("certdbDir");
        if (certDb != null)
            tomcatjss.setCertdbDir(certDb);

        String passwordClass = properties.getProperty("passwordClass");
        if (passwordClass != null)
            tomcatjss.setPasswordClass(passwordClass);

        String passwordFile = properties.getProperty("passwordFile");
        if (passwordFile != null)
            tomcatjss.setPasswordFile(passwordFile);

        String enableOCSP = properties.getProperty("enableOCSP");
        if (enableOCSP != null)
            tomcatjss.setEnableOCSP(Boolean.parseBoolean(enableOCSP));

        String ocspResponderURL = properties.getProperty("ocspResponderURL");
        if (ocspResponderURL != null)
            tomcatjss.setOcspResponderURL(ocspResponderURL);

        String ocspResponderCertNickname = properties.getProperty("ocspResponderCertNickname");
        if (ocspResponderCertNickname != null)
            tomcatjss.setOcspResponderCertNickname(ocspResponderCertNickname);

        String ocspCacheSize = properties.getProperty("ocspCacheSize");
        if (StringUtils.isNotEmpty(ocspCacheSize))
            tomcatjss.setOcspCacheSize(Integer.parseInt(ocspCacheSize));

        String ocspMinCacheEntryDuration = properties.getProperty("ocspMinCacheEntryDuration");
        if (StringUtils.isNotEmpty(ocspMinCacheEntryDuration))
            tomcatjss.setOcspMinCacheEntryDuration(Integer.parseInt(ocspMinCacheEntryDuration));

        String ocspMaxCacheEntryDuration = properties.getProperty("ocspMaxCacheEntryDuration");
        if (StringUtils.isNotEmpty(ocspMaxCacheEntryDuration))
            tomcatjss.setOcspMaxCacheEntryDuration(Integer.parseInt(ocspMaxCacheEntryDuration));

        String ocspTimeout = properties.getProperty("ocspTimeout");
        if (StringUtils.isNotEmpty(ocspTimeout))
            tomcatjss.setOcspTimeout(Integer.parseInt(ocspTimeout));

        String strictCiphers = properties.getProperty("strictCiphers");
        if (strictCiphers != null)
            tomcatjss.setStrictCiphers(strictCiphers);

        String sslVersionRangeStream = properties.getProperty("sslVersionRangeStream");
        if (sslVersionRangeStream != null)
            tomcatjss.setSslVersionRangeStream(sslVersionRangeStream);

        String sslVersionRangeDatagram = properties.getProperty("sslVersionRangeDatagram");
        if (sslVersionRangeDatagram != null)
            tomcatjss.setSslVersionRangeDatagram(sslVersionRangeDatagram);

        String sslRangeCiphers = properties.getProperty("sslRangeCiphers");
        if (sslRangeCiphers != null)
            tomcatjss.setSslRangeCiphers(sslRangeCiphers);

        String sslOptions = properties.getProperty("sslOptions");
        if (sslOptions != null)
            tomcatjss.setSslOptions(sslOptions);

        String ssl2Ciphers = properties.getProperty("ssl2Ciphers");
        if (ssl2Ciphers != null)
            tomcatjss.setSsl2Ciphers(ssl2Ciphers);

        String ssl3Ciphers = properties.getProperty("ssl3Ciphers");
        if (ssl3Ciphers != null)
            tomcatjss.setSsl3Ciphers(ssl3Ciphers);

        String tlsCiphers = properties.getProperty("tlsCiphers");
        if (tlsCiphers != null)
            tomcatjss.setTlsCiphers(tlsCiphers);
    }

    public void loadServerXml() throws Exception {

        DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
        DocumentBuilder builder = factory.newDocumentBuilder();

        String catalinaBase = System.getProperty("catalina.base");
        File file = new File(catalinaBase + "/conf/server.xml");
        Document doc = builder.parse(file);

        XPathFactory xPathfactory = XPathFactory.newInstance();
        XPath xpath = xPathfactory.newXPath();

        Element connector = (Element) xpath.evaluate(
                "/Server/Service[@name='Catalina']/Connector[@SSLEnabled='true']",
                doc, XPathConstants.NODE);

        TomcatJSS tomcatjss = TomcatJSS.getInstance();

        String certDb = connector.getAttribute("certdbDir");
        if (certDb != null)
            tomcatjss.setCertdbDir(certDb);

        String passwordClass = connector.getAttribute("passwordClass");
        if (passwordClass != null)
            tomcatjss.setPasswordClass(passwordClass);

        String passwordFile = connector.getAttribute("passwordFile");
        if (passwordFile != null)
            tomcatjss.setPasswordFile(passwordFile);

        String serverCertNickFile = connector.getAttribute("serverCertNickFile");
        if (serverCertNickFile != null)
            tomcatjss.setServerCertNickFile(serverCertNickFile);

        String enableOCSP = connector.getAttribute("enableOCSP");
        if (enableOCSP != null)
            tomcatjss.setEnableOCSP(Boolean.parseBoolean(enableOCSP));

        String ocspResponderURL = connector.getAttribute("ocspResponderURL");
        if (ocspResponderURL != null)
            tomcatjss.setOcspResponderURL(ocspResponderURL);

        String ocspResponderCertNickname = connector.getAttribute("ocspResponderCertNickname");
        if (ocspResponderCertNickname != null)
            tomcatjss.setOcspResponderCertNickname(ocspResponderCertNickname);

        String ocspCacheSize = connector.getAttribute("ocspCacheSize");
        if (StringUtils.isNotEmpty(ocspCacheSize))
            tomcatjss.setOcspCacheSize(Integer.parseInt(ocspCacheSize));

        String ocspMinCacheEntryDuration = connector.getAttribute("ocspMinCacheEntryDuration");
        if (StringUtils.isNotEmpty(ocspMinCacheEntryDuration))
            tomcatjss.setOcspMinCacheEntryDuration(Integer.parseInt(ocspMinCacheEntryDuration));

        String ocspMaxCacheEntryDuration = connector.getAttribute("ocspMaxCacheEntryDuration");
        if (StringUtils.isNotEmpty(ocspMaxCacheEntryDuration))
            tomcatjss.setOcspMaxCacheEntryDuration(Integer.parseInt(ocspMaxCacheEntryDuration));

        String ocspTimeout = connector.getAttribute("ocspTimeout");
        if (StringUtils.isNotEmpty(ocspTimeout))
            tomcatjss.setOcspTimeout(Integer.parseInt(ocspTimeout));

        String strictCiphers = connector.getAttribute("strictCiphers");
        if (strictCiphers != null)
            tomcatjss.setStrictCiphers(strictCiphers);

        String sslVersionRangeStream = connector.getAttribute("sslVersionRangeStream");
        if (sslVersionRangeStream != null)
            tomcatjss.setSslVersionRangeStream(sslVersionRangeStream);

        String sslVersionRangeDatagram = connector.getAttribute("sslVersionRangeDatagram");
        if (sslVersionRangeDatagram != null)
            tomcatjss.setSslVersionRangeDatagram(sslVersionRangeDatagram);

        String sslRangeCiphers = connector.getAttribute("sslRangeCiphers");
        if (sslRangeCiphers != null)
            tomcatjss.setSslRangeCiphers(sslRangeCiphers);

        String sslOptions = connector.getAttribute("sslOptions");
        if (sslOptions != null)
            tomcatjss.setSslOptions(sslOptions);

        String ssl2Ciphers = connector.getAttribute("ssl2Ciphers");
        if (ssl2Ciphers != null)
            tomcatjss.setSsl2Ciphers(ssl2Ciphers);

        String ssl3Ciphers = connector.getAttribute("ssl3Ciphers");
        if (ssl3Ciphers != null)
            tomcatjss.setSsl3Ciphers(ssl3Ciphers);

        String tlsCiphers = connector.getAttribute("tlsCiphers");
        if (tlsCiphers != null)
            tomcatjss.setTlsCiphers(tlsCiphers);
    }
}
