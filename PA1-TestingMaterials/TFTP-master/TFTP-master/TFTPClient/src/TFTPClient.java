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

			// new
			//	TFTPClient <username> <password> <server_host> <tcp_port> <type_r_w> <filename> <mode>
			// old
			//   java TFTPClient [host] [Request Type] [Filename] (mode)

			if (argv.length == 0)
				throw new UseException("--Usage--  TFTPClient <username> <password> <server_host> <tcp_port> <type_r_w> <filename> <mode>" );
			if(argv.length == 3){
				host =argv[2];
			    type = argv[argv.length - 2];
			    fileName = argv[argv.length - 1];}
			//use other modes
			else if(argv.length == 4){
				host = argv[2];
				mode =argv[argv.length-1];
				type = argv[argv.length - 3];
				fileName = argv[argv.length - 2];
			}

			else throw new UseException("wrong command. \n--Usage-- \nocter mode:  TFTPClient [host] [Type(R/W?)] [filename] \nother mode:  TFTPClient [host] [Type(R/W?)] [filename] [mode]");
			client_shp_phase1 client = new client_shp_phase1();
			String[] args = {mode, type, fileName};
			CryptoConfig config = null;
			try {

				config = client.client(argv[0], argv[1], Integer.parseInt(argv[3]), 0, argv[2], args);
			} catch (NumberFormatException e) {
				e.printStackTrace();
				return;
			} catch (Exception e) {
				e.printStackTrace();
				return;
			}

			System.out.println("Recieved: " + config.getCiphersuite());
			InetAddress server = InetAddress.getByName(host);
			try {
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