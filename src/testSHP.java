import java.io.IOException;
import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.net.InetSocketAddress;
import java.net.SocketAddress;
import java.security.Security;
import java.util.ArrayList;
import java.util.Set;

import DataBase.User;
import DataBase.dataBaseManager;

public class testSHP {
    
    public static void main(String[] args) {
        Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());
        if(args.length == 0){
            System.out.println("No Params");
            return;
        }
        if(args[0].equals("c")){
            testClient();
        }else{
            testServer();
        }
       
    }
    public static void testClient(){
        try {
            String[] args = {"olas", "olas"};
            client_shp_phase1 client= new client_shp_phase1();
            CryptoConfig cripto = client.client("alice@gmail.com", "StrongPassword123", 5001,399, "127.0.0.1", args);
            System.out.println("Recieved: "+cripto.getCiphersuite());
            
            DSTP dstp_client = new DSTP();
            dstp_client.init(cripto);

            SocketAddress inSocketAddress = parseSocketAddress("127.0.0.1:4000");
    
            DatagramSocket inSocket = new DatagramSocket(inSocketAddress); 

            byte[] buffer = new byte[4 * 1024];

            DatagramPacket inPacket = new DatagramPacket(buffer, buffer.length);
            dstp_client.receave(inSocket, inPacket);
            System.out.println("Received: " + new String(inPacket.getData(), 0, inPacket.getLength()));

        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public static  void testServer(){
        try {
            server_shp_phase1 server = new server_shp_phase1();
            String[] str = server.server();
            System.out.println(str[0]);
            System.out.println(str[1]);
            System.out.println(str[2]);
            String sample = "ola";
            DSTP dstp_server = new DSTP();
            CryptoConfig cryptoConfig = new CryptoConfig("./Server/ciphersuite.conf");
            dstp_server.init(cryptoConfig);

            DatagramSocket s = new DatagramSocket();
            InetSocketAddress addr = new InetSocketAddress("127.0.0.1",4000);
            byte[] buff = sample.getBytes();
		    DatagramPacket p=new DatagramPacket(buff,buff.length,addr);
            dstp_server.send(p,s);
            System.out.println("Sent: " + sample);
        } catch (Exception e) {
            // TODO Auto-generated catch block
            e.printStackTrace();
        }
    }

        private static InetSocketAddress parseSocketAddress(String socketAddress) 
    {
        String[] split = socketAddress.split(":");
        String host = split[0];
        int port = Integer.parseInt(split[1]);
        return new InetSocketAddress(host, port);
    }
    

}
