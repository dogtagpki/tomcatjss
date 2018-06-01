package org.dogtagpki.tomcat;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;

import org.apache.tomcat.util.net.jss.TomcatJSS;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class Http11Protocol extends org.apache.coyote.http11.Http11Protocol {

    public static Logger logger = LoggerFactory.getLogger(Http11Protocol.class);

    TomcatJSS tomcatjss = TomcatJSS.getInstance();

    public String getCertdbDir() {
        return tomcatjss.getCertdbDir();
    }

    public void setCertdbDir(String certdbDir) {
        tomcatjss.setCertdbDir(certdbDir);
    }

    public String getPasswordClass() {
        return tomcatjss.getPasswordClass();
    }

    public void setPasswordClass(String passwordClass) {
        tomcatjss.setPasswordClass(passwordClass);
    }

    public String getPasswordFile() {
        return tomcatjss.getPasswordFile();
    }

    public void setPasswordFile(String passwordFile) {
        tomcatjss.setPasswordFile(passwordFile);
    }

    public String getServerCertNickFile() {
        return tomcatjss.getServerCertNickFile();
    }

    public void setServerCertNickFile(String serverCertNickFile) {
        tomcatjss.setServerCertNickFile(serverCertNickFile);
    }

    public boolean getEnabledOCSP() {
        return tomcatjss.getEnableOCSP();
    }

    public void setEnableOCSP(boolean enableOCSP) {
        tomcatjss.setEnableOCSP(enableOCSP);
    }

    public String getOcspResponderURL() {
        return tomcatjss.getOcspResponderURL();
    }

    public void setOcspResponderURL(String ocspResponderURL) {
        tomcatjss.setOcspResponderURL(ocspResponderURL);
    }

    public String getOcspResponderCertNickname() {
        return tomcatjss.getOcspResponderCertNickname();
    }

    public void setOcspResponderCertNickname(String ocspResponderCertNickname) {
        tomcatjss.setOcspResponderCertNickname(ocspResponderCertNickname);
    }

    public int getOcspCacheSize() {
        return tomcatjss.getOcspCacheSize();
    }

    public void setOcspCacheSize(int ocspCacheSize) {
        tomcatjss.setOcspCacheSize(ocspCacheSize);
    }

    public int getOcspMinCacheEntryDuration() {
        return tomcatjss.getOcspMinCacheEntryDuration();
    }

    public void setOcspMinCacheEntryDuration(int ocspMinCacheEntryDuration) {
        tomcatjss.setOcspMinCacheEntryDuration(ocspMinCacheEntryDuration);
    }

    public int getOcspMaxCacheEntryDuration() {
        return tomcatjss.getOcspMaxCacheEntryDuration();
    }

    public void setOcspMaxCacheEntryDuration(int ocspMaxCacheEntryDuration) {
        tomcatjss.setOcspMaxCacheEntryDuration(ocspMaxCacheEntryDuration);
    }

    public int getOcspTimeout() {
        return tomcatjss.getOcspTimeout();
    }

    public void setOcspTimeout(int ocspTimeout) {
        tomcatjss.setOcspTimeout(ocspTimeout);
    }

    public String getStrictCiphers() {
        return tomcatjss.getStrictCiphers();
    }

    public void setStrictCiphers(String strictCiphers) {
        tomcatjss.setStrictCiphers(strictCiphers);
    }

    public String getSslVersionRangeStream() {
        return tomcatjss.getSslVersionRangeStream();
    }

    public void setSslVersionRangeStream(String sslVersionRangeStream) {
        tomcatjss.setSslVersionRangeStream(sslVersionRangeStream);
    }

    public String getSslVersionRangeDatagram() {
        return tomcatjss.getSslVersionRangeDatagram();
    }

    public void setSslVersionRangeDatagram(String sslVersionRangeDatagram) {
        tomcatjss.setSslVersionRangeDatagram(sslVersionRangeDatagram);;
    }

    public String getSslRangeCiphers() {
        return tomcatjss.getSslRangeCiphers();
    }

    public void setSslRangeCiphers(String sslRangeCiphers) {
        tomcatjss.setSslRangeCiphers(sslRangeCiphers);
    }

    public String getSslOptions() {
        return tomcatjss.getSslOptions();
    }

    public void setSslOptions(String sslOptions) {
        tomcatjss.setSslOptions(sslOptions);
    }

    public String getSsl2Ciphers() {
        return tomcatjss.getSsl2Ciphers();
    }

    public void setSsl2Ciphers(String ssl2Ciphers) {
        tomcatjss.setSsl2Ciphers(ssl2Ciphers);
    }

    public String getSsl3Ciphers() {
        return tomcatjss.getSsl3Ciphers();
    }

    public void setSsl3Ciphers(String ssl3Ciphers) {
        tomcatjss.setSsl3Ciphers(ssl3Ciphers);
    }

    public String getTlsCiphers() {
        return tomcatjss.getTlsCiphers();
    }

    public void setTlsCiphers(String tlsCiphers) {
        tomcatjss.setTlsCiphers(tlsCiphers);
    }

    public void setKeystorePassFile(String keystorePassFile) {
        try {
            Path path = Paths.get(keystorePassFile);
            String password = new String(Files.readAllBytes(path)).trim();
            setKeystorePass(password);

        } catch (IOException e) {
            throw new RuntimeException(e);
        }
    }

    public void setTruststorePassFile(String truststorePassFile) {
        try {
            Path path = Paths.get(truststorePassFile);
            String password = new String(Files.readAllBytes(path)).trim();
            setTruststorePass(password);

        } catch (IOException e) {
            throw new RuntimeException(e);
        }
    }
}
