package mitm;

import java.io.InputStream;
import java.io.InterruptedIOException;
import java.io.IOException;
import java.io.OutputStream;
import java.io.PrintWriter;
import java.net.ServerSocket;
import java.net.Socket;


public abstract class ProxyEngine implements Runnable {

    public static final String ACCEPT_TIMEOUT_MESSAGE = "Listen time out";
    private final ProxyDataFilter m_requestFilter;
    private final ProxyDataFilter m_responseFilter;
    private final ConnectionDetails m_connectionDetails;

    private final PrintWriter m_outputWriter;

    public final MITMSocketFactory m_socketFactory;
    protected ServerSocket m_serverSocket;

    public ProxyEngine(MITMSocketFactory socketFactory,
		       ProxyDataFilter requestFilter,
		       ProxyDataFilter responseFilter,
		       ConnectionDetails connectionDetails,
		       int timeout)
	throws IOException
    {
	m_socketFactory = socketFactory;
	m_requestFilter = requestFilter;
	m_responseFilter = responseFilter;
	m_connectionDetails = connectionDetails;

	m_outputWriter = requestFilter.getOutputPrintWriter();

	m_serverSocket =
	    m_socketFactory.createServerSocket(
		connectionDetails.getLocalHost(),
		connectionDetails.getLocalPort(),
		timeout);
    }

    //run() method from Runnable is implemented in subclasses

    public final ServerSocket getServerSocket() {
	return m_serverSocket;
    }

    protected final MITMSocketFactory getSocketFactory() {
	return m_socketFactory;
    }

    protected final ConnectionDetails getConnectionDetails() {
	return m_connectionDetails;
    }

    
    /*
     * Launch a pair of threads that:
     * (1) Copy data sent from the client to the remote server
     * (2) Copy data sent from the remote server to the client
     *
     */
    protected final void launchThreadPair(Socket localSocket, Socket remoteSocket,
					  InputStream localInputStream,
					  OutputStream localOutputStream,
					  String remoteHost,
					  int remotePort)
	throws IOException
    {

	new StreamThread(new ConnectionDetails(
			     m_connectionDetails.getLocalHost(),
			     localSocket.getPort(),
			     remoteHost,
			     remoteSocket.getPort(),
			     m_connectionDetails.isSecure()),
			 localInputStream,
			 remoteSocket.getOutputStream(),
			 m_requestFilter,
			 m_outputWriter);

	new StreamThread(new ConnectionDetails(
			     remoteHost,
			     remoteSocket.getPort(),
			     m_connectionDetails.getLocalHost(),
			     localSocket.getPort(),
			     m_connectionDetails.isSecure()),
			 remoteSocket.getInputStream(),
			 localOutputStream,
			 m_responseFilter,
			 m_outputWriter);
    }
}

