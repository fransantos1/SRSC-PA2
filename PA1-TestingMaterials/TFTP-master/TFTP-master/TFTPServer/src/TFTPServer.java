import java.net.*;
import java.io.*;
import java.util.*;

public class TFTPServer {

	public static void main(String argv[]) {
		try {
			if(argv.length != 1) {
				System.out.println("Usage: java TFTPServer <port>");
				System.exit(1);
			}
			String[] params = server_shp_phase1.server(Integer.parseInt(argv[0]));

			DSTP.init(new CryptoConfig("./ciphersuite.conf"));
	
		
			//use port 6973
			DatagramSocket sock = new DatagramSocket(6973);
			System.out.println("Server Ready.  Port:  " + sock.getLocalPort());

			// Listen for requests
			while (true) {
				
				TFTPpacket in = TFTPpacket.receive(sock);	
				// receive read request
				if (in instanceof TFTPread) {
					System.out.println("Read Request from " + in.getAddress());
					TFTPserverRRQ r = new TFTPserverRRQ((TFTPread) in);
				}
				// receive write request
				else if (in instanceof TFTPwrite) {
					System.out.println("Write Request from " + in.getAddress());
					TFTPserverWRQ w = new TFTPserverWRQ((TFTPwrite) in);
				}
			}
		} catch (SocketException e) {
			System.out.println("Server terminated(SocketException) " + e.getMessage());
		} catch (TftpException e) {
			System.out.println("Server terminated(TftpException)" + e.getMessage());
		} catch (IOException e) {
			System.out.println("Server terminated(IOException)" + e.getMessage());
		} catch (Exception e) {
			e.printStackTrace();
		}
	}
}