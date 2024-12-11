/* hjUDPproxy, for use in 2024
 */

 import java.net.DatagramPacket;
 import java.net.DatagramSocket;
 import java.net.Inet4Address;
 import java.net.InetAddress;
 import java.net.InetSocketAddress;
 import java.net.SocketAddress;
 import java.util.Arrays;
 import java.util.Set;
 import java.util.stream.Collectors;
 
 class hjUDPproxy {
     public static void main(String[] args) throws Exception {
         System.out.println(args.length);
 if (args.length !=7)
     {
         System.out.println("Use:java Proxy <username> <password> <server> <tcp_port> <movie> <udp_port> <player_port>");
         System.exit(0);
     }
 
     //args[0] = username
     //args[1] = password
     //args[2] = server
     //args[3] = tcp_port
     //args[4] = movie
     //args[5] = udp_port
     //args[6] = player_port
 
     // SERVER NEEDS :
     // args[0] = args[4] (movie)
     // args[1] = destination IP
     // args[2] = args[5] (udp_port)
 System.out.println("in Port = "+args[5]);
    System.out.println("out Port = "+args[6]);
 
     String sendArgs[] = {args[4]};
     CryptoConfig config =client_shp_phase1.client(args[0], args[1], Integer.parseInt(args[3]) ,Integer.parseInt(args[5]), args[2], sendArgs);
     
     String destinations="127.0.0.1:"+args[6]; 
 
     SocketAddress inSocketAddress = new InetSocketAddress(Integer.parseInt(args[5]));
     Set<SocketAddress> outSocketAddressSet = Arrays.stream(destinations.split(",")).map(s -> parseSocketAddress(s)).collect(Collectors.toSet());
 
         // Manage this according to your required setup, namely
     // if you want to use unicast or multicast channels
 
         // If listen a remote unicast server try the remote config
         // uncomment the following line
     
      DatagramSocket inSocket = new DatagramSocket(inSocketAddress); 
 
     // If listen a remote multicast server using IP Multicasting
         // addressing (remember IP Multicast Range) and port 
     // uncomment the following two lines
 
     //	MulticastSocket ms = new MulticastSocket(9999);
     //        ms.joinGroup(InetAddress.getByName("239.9.9.9"));
 
     int countframes=0;
         DatagramSocket outSocket = new DatagramSocket();
         byte[] buffer = new byte[4 * 1024];
         
         System.out.println(config.getCiphersuite());
         DSTP.init(config);
 
         while (true) {
 
             DatagramPacket inPacket = new DatagramPacket(buffer, buffer.length);
         // If listen a remote unicast server
         // uncomment the following line
 
             DSTP.receave(inSocket, inPacket);
             
 
         //inSocket.receive(inPacket);  // if remote is unicast
 
         // If listen a remote multcast server
         // uncomment the following line
 
             //ms.receive(inPacket);          // if remote is multicast
 
         // Just for debug... 
             //countframes++;
             //System.out.println(":"+countframes);           // debug	    
             //System.out.print(":");           // debug
             
             for (SocketAddress outSocketAddress : outSocketAddressSet) 
             {
           
                 outSocket.send(new DatagramPacket(inPacket.getData(), inPacket.getLength(), outSocketAddress));
             }
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
 