package mitm;

import java.io.IOException;
import java.net.ServerSocket;
import java.net.Socket;

public interface MITMSocketFactory
{
    ServerSocket createServerSocket(String localHost, int localPort,
				    int timeout)
	throws IOException;

    Socket createClientSocket(String remoteHost, int remotePort)
	throws IOException;
}

