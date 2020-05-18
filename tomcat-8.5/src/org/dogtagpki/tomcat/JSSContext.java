package org.dogtagpki.tomcat;

import java.security.Provider;
import java.security.KeyManagementException;
import java.security.SecureRandom;
import java.security.Security;
import java.util.List;

import javax.net.ssl.KeyManager;
import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.TrustManager;

import org.apache.tomcat.util.net.SSLContext;

import org.mozilla.jss.JSSProvider;
import org.mozilla.jss.provider.javax.crypto.JSSKeyManager;
import org.mozilla.jss.provider.javax.crypto.JSSTrustManager;
import org.mozilla.jss.ssl.javax.JSSEngine;
import org.mozilla.jss.ssl.javax.JSSParameters;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class JSSContext implements org.apache.tomcat.util.net.SSLContext {
    public static Logger logger = LoggerFactory.getLogger(JSSContext.class);

    private javax.net.ssl.SSLContext ctx;
    private String alias;

    private JSSKeyManager jkm;
    private JSSTrustManager jtm;

    public JSSContext(String alias) {
        logger.debug("JSSContext(" + alias + ")");
        this.alias = alias;

        /* These KeyManagers and TrustManagers aren't used with the SSLEngine;
         * they're only used to implement certain function calls below. */
        jkm = new JSSKeyManager();
        jtm = new JSSTrustManager();
    }

    public void init(KeyManager[] kms, TrustManager[] tms, SecureRandom sr) throws KeyManagementException {
        logger.debug("JSSContext.init(...)");

        try {
            String provider = "SunJSSE";
            if (JSSProvider.ENABLE_JSSENGINE) {
                provider = "Mozilla-JSS";
            }

            ctx = javax.net.ssl.SSLContext.getInstance("TLS", provider);
            ctx.init(kms, tms, sr);
        } catch (Exception e) {
            throw new KeyManagementException(e.getMessage(), e);
        }
    }

    public javax.net.ssl.SSLEngine createSSLEngine() {
        logger.debug("JSSContext.createSSLEngine()");
        javax.net.ssl.SSLEngine eng = ctx.createSSLEngine();

        if (eng instanceof JSSEngine) {
            JSSEngine j_eng = (JSSEngine) eng;
            j_eng.setCertFromAlias(alias);
        }

        return eng;
    }

    public javax.net.ssl.SSLSessionContext getServerSessionContext() {
        logger.debug("JSSContext.getServerSessionContext()");
        return ctx.getServerSessionContext();
    }

    public javax.net.ssl.SSLServerSocketFactory getServerSocketFactory() {
        logger.debug("JSSContext.getServerSocketFactory()");
        return ctx.getServerSocketFactory();
    }

    public javax.net.ssl.SSLParameters getSupportedSSLParameters() {
        logger.debug("JSSContext.getSupportedSSLParameters()");
        return ctx.getSupportedSSLParameters();
    }

    public java.security.cert.X509Certificate[] getCertificateChain(java.lang.String alias) {
        logger.debug("JSSContext.getCertificateChain(" + alias + ")");

        try {
            return jkm.getCertificateChain(alias);
        } catch (Exception e) {
            throw new RuntimeException(e.getMessage(), e);
        }
    }

    public java.security.cert.X509Certificate[] getAcceptedIssuers() {
        logger.debug("JSSContext.getAcceptedIssuers()");

        try {
            return jtm.getAcceptedIssuers();
        } catch (Exception e) {
            throw new RuntimeException(e.getMessage(), e);
        }
    }

    public void destroy() {
        logger.debug("JSSContext.destory()");
    }
}
