import java.io.IOException;
import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.net.InetSocketAddress;
import java.net.SocketAddress;
import java.security.Security;
import java.util.ArrayList;
import java.util.Set;

import Client.*;
import Common.*;
import Server.*;

public class testSHP {
    
    public static void main(String[] args) {
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
            CryptoConfig cripto = client_shp_phase1.client("alice@gmail.com", "StrongPassword123", 5001,399, "127.0.0.1", args);
            String sample = "ola";
            DSTP.init(cripto);
            SocketAddress inSocketAddress = parseSocketAddress("127.0.0.1:4000");
           
            DatagramSocket s = new DatagramSocket();
            InetSocketAddress addr = new InetSocketAddress("127.0.0.1",4000);
            byte[] buff = sample.getBytes();
		    DatagramPacket p=new DatagramPacket(buff,buff.length,addr);
            DSTP.send(p,s);
            System.out.println("Sent: " + sample);

        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public static  void testServer(){
        try {
            String[] str = server_shp_phase1.server(5001);
            System.out.println(str[0]);
            System.out.println(str[1]);
            System.out.println(str[2]);
           

            CryptoConfig cryptoConfig = new CryptoConfig("./Server/ciphersuite.conf");
            DSTP.init(cryptoConfig);

            SocketAddress inSocketAddress = parseSocketAddress("127.0.0.1:4000");
    
            DatagramSocket inSocket = new DatagramSocket(inSocketAddress); 

            byte[] buffer = new byte[4 * 1024];

            DatagramPacket inPacket = new DatagramPacket(buffer, buffer.length);
            DSTP.receave(inSocket, inPacket);
            System.out.println("Received: " + new String(inPacket.getData(), 0, inPacket.getLength()));


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
