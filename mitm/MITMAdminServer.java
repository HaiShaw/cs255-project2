/**
 * CS255 project 2
 */

package mitm;

import java.net.*;
import java.io.*;
import java.security.GeneralSecurityException;
import java.util.*;
import java.util.regex.*;

class MITMAdminServer implements Runnable
{
    private ServerSocket m_serverSocket;
    private Socket m_socket = null;
    private HTTPSProxyEngine m_engine;
    
    public MITMAdminServer( String localHost, int adminPort, HTTPSProxyEngine engine ) throws IOException,GeneralSecurityException {
	MITMSSLSocketFactory socketFactory = new MITMSSLSocketFactory();
				
	m_serverSocket = socketFactory.createServerSocket( localHost, adminPort, 0 );
	m_engine = engine;
    }

    public void run() {
	System.out.println("Admin server initialized, listening on port " + m_serverSocket.getLocalPort());
	while( true ) {
	    try {
		m_socket = m_serverSocket.accept();

		byte[] buffer = new byte[40960];

		Pattern userPwdPattern =
		    Pattern.compile("password:(\\S+)\\s+command:(\\S+)\\sCN:(\\S*)\\s");
		
		BufferedInputStream in =
		    new BufferedInputStream(m_socket.getInputStream(),
					    buffer.length);

		// Read a buffer full.
		int bytesRead = in.read(buffer);

		String line =
		    bytesRead > 0 ?
		    new String(buffer, 0, bytesRead) : "";

		Matcher userPwdMatcher =
		    userPwdPattern.matcher(line);

		// parse username and pwd
		if (userPwdMatcher.find()) {
		    String password = userPwdMatcher.group(1);

		    // TODO(cs255): authenticate the user
		    // boolean authenticated = true;
            String hashed = "";
            boolean authenticated = false;

            try {
                hashed = new Scanner(new File(JSSEConstants.PWD_FILE)).useDelimiter("\\Z").next();
            } catch (FileNotFoundException e) {
                sendString("Password file not found.\n");
                authenticated = false;
            }

            try {
                if (BCrypt.checkpw(password, hashed)) {
                    authenticated = true;
                } else {
                    authenticated = false;
                }
            } catch (Exception e) {
                sendString("Password authentication failed.\n");
                authenticated = false;
            }


		    // if authenticated, do the command
		    if( authenticated ) {
			String command = userPwdMatcher.group(2);
			String commonName = userPwdMatcher.group(3);

			doCommand( command );
		    } else {
                sendString("Authentication failed!\n");
                m_socket.close();
            }
		}	
	    }
	    catch( InterruptedIOException e ) {
	    }
	    catch( Exception e ) {
		e.printStackTrace();
	    }
	}
    }

    private void sendString(final String str) throws IOException {
	PrintWriter writer = new PrintWriter( m_socket.getOutputStream() );
	writer.println(str);
	writer.flush();
    }
    
    private void doCommand( String cmd ) throws IOException {

	// TODO(cs255): instead of greeting admin client, run the indicated command
	// sendString("How are you Admin Client !!");
    String c = cmd.toLowerCase();
    if (c.equals("stats")) {
        sendString("Total number of requests proxied: " + m_engine.getNumProxiedRequests() + "\n");
    } else if (c.equals("shutdown")) {
        sendString("Shutting down proxy server\n");
        System.exit(0);
    } else {
        sendString("Unknown command: " + c);
        sendString("Expected: stats | shutdown\n");
    }

	m_socket.close();
	
    }

}
