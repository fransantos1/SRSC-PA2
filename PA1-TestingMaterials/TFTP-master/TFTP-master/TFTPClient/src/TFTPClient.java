

import java.net.InetAddress;
import java.net.UnknownHostException;
class UseException extends Exception {
	public UseException() {
		super();
	}

	public UseException(String s) {
		super(s);
	}
}

public class TFTPClient {
	public static void main(String argv[]) throws TftpException, UseException {
		String host = "";
		String fileName = "";
		String mode="octet"; //default mode
		String type="";
		try {
			// Process command line
			if (argv.length == 0)
				throw new UseException("--Usage-- \nTFTPClient <username> <password> <server_host> <tcp_port> <type_r_w> <filename> <mode>" );

			/*
			0 - username
			1 - password
			2 - server_host
			3 - tcp_port
			4 - type_r_w
			5 - filename
			6 - mode

			*/

			//use default mode(octet)
			if(argv.length == 6){
				host =argv[2];
			    type = argv[argv.length - 2];
				System.out.println("type: " + type);
			    fileName = argv[argv.length - 1];
				System.out.println("filename: " + fileName);
			}
				
			//use other modes
			else if(argv.length == 7){
				host = argv[2];
				mode =argv[argv.length-1];
				type = argv[argv.length - 3];
				fileName = argv[argv.length - 2];
			}

			else throw new UseException("wrong command. \n--Usage-- \nocter mode:  TFTPClient [host] [Type(R/W?)] [filename] \nother mode:  TFTPClient [host] [Type(R/W?)] [filename] [mode]");
			//! IN HERE IT DOESNT REALLY MATTER WHAT THE ARGV IS BECAUSE THATS HANDLELED BY THE TFTP ITSELF
			
			InetAddress server = InetAddress.getByName(host);
			System.out.println("Server: " + server);
			try {
				CryptoConfig config = client_shp_phase1.client(argv[0], argv[1], Integer.parseInt(argv[3]), 0, argv[2], argv);
				DSTP.init(config);
			} catch (Exception e) {
				e.printStackTrace();
			}
			//process read request
			if(type.matches("R")){
				TFTPclientRRQ r = new TFTPclientRRQ(server, fileName, mode);}
			//process write request
			else if(type.matches("W")){
				TFTPclientWRQ w = new TFTPclientWRQ(server, fileName, mode);
			}
			else{throw new UseException("wrong command. \n--Usage-- \nocter mode:  TFTPClient [host] [Type(R/W?)] [filename] \nother mode:  TFTPClient [host] [Type(R/W?)] [filename] [mode]");}
			
		} catch (UnknownHostException e) {
			System.out.println("Unknown host " + host);
		} catch (UseException e) {
			System.out.println(e.getMessage());
		}
	}
}