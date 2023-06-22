package org.dogtagpki.tomcat;


import java.nio.channels.SocketChannel;
import java.util.List;

import javax.net.ssl.SSLEngine;

import org.apache.juli.logging.Log;
import org.apache.juli.logging.LogFactory;
import org.apache.tomcat.util.ExceptionUtils;
import org.apache.tomcat.util.net.NioChannel;
import org.apache.tomcat.util.net.NioEndpoint;
import org.apache.tomcat.util.net.SocketBufferHandler;
import org.apache.tomcat.util.net.openssl.ciphers.Cipher;

public class JSSNioEndpoint extends NioEndpoint {

    private static final Log log = LogFactory.getLog(NioEndpoint.class);
    /**
     * Code in the following method is almost identical of that available in the base
     * class {@link org.apache.tomcat.util.net.NioEndpoint#setSocketOptions(SocketChannel) from tomcat.
     * <p>
     * The only difference is the instantiation of the JSSSecureNioChannel class instead of the tomcat
     * provided SecureNioChannel class. This is needed because the channel class is hard-coded in the
     * base class method.
     *
     * @see org.apache.tomcat.util.net.NioEndpoint#setSocketOptions(SocketChannel socket)
     */

    @Override
    protected boolean setSocketOptions(SocketChannel socket) {
        NioSocketWrapper socketWrapper = null;
        try {
            // Allocate channel and wrapper
            NioChannel channel = null;
            if (getNioChannels() != null) {
                channel = getNioChannels().pop();
            }
            if (channel == null) {
                SocketBufferHandler bufhandler = new SocketBufferHandler(
                        socketProperties.getAppReadBufSize(),
                        socketProperties.getAppWriteBufSize(),
                        socketProperties.getDirectBuffer());
                if (isSSLEnabled()) {
// This is the change from the code in the base class
                    channel = new JSSSecureNioChannel(bufhandler, this);
// End of difference
                } else {
                    channel = new NioChannel(bufhandler);
                }
            }
            NioSocketWrapper newWrapper = new NioSocketWrapper(channel, this);
            channel.reset(socket, newWrapper);
            connections.put(socket, newWrapper);
            socketWrapper = newWrapper;

            // Set socket properties
            // Disable blocking, polling will be used
            socket.configureBlocking(false);
            if (getUnixDomainSocketPath() == null) {
                socketProperties.setProperties(socket.socket());
            }

            socketWrapper.setReadTimeout(getConnectionTimeout());
            socketWrapper.setWriteTimeout(getConnectionTimeout());
            socketWrapper.setKeepAliveLeft(JSSNioEndpoint.this.getMaxKeepAliveRequests());
            getPoller().register(socketWrapper);
            return true;
        } catch (Throwable t) {
            ExceptionUtils.handleThrowable(t);
            try {
                log.error(sm.getString("endpoint.socketOptionsError"), t);
            } catch (Throwable tt) {
                ExceptionUtils.handleThrowable(tt);
            }
            if (socketWrapper == null) {
                destroySocket(socket);
            }
        }
        // Tell to close the socket if needed
        return false;

    }
    @Override
    protected SSLEngine createSSLEngine(String arg0, List<Cipher> arg1, List<String> arg2) {
        return super.createSSLEngine(arg0, arg1, arg2);
    }

}
