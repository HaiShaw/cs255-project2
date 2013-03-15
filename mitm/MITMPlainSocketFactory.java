package mitm;

import java.io.IOException;
import java.net.InetAddress;
import java.net.ServerSocket;
import java.net.Socket;

/**
 * MITMPlainSocketFactory is used to create plaintext non-SSL sockets.
 */
public final class MITMPlainSocketFactory implements MITMSocketFactory
{
    public final ServerSocket createServerSocket(String localHost,
						 int localPort,
						 int timeout)
	throws IOException
    {
	final ServerSocket socket =
	    new ServerSocket(localPort, 50, InetAddress.getByName(localHost));

	socket.setSoTimeout(timeout);

	return socket;
    }

    public final Socket createClientSocket(String remoteHost, int remotePort)
	throws IOException
    {
	return new Socket(remoteHost, remotePort);
    }
}

