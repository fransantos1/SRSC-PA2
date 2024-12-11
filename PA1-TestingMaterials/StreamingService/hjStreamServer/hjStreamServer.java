/*
* hjStreamServer.java 
* Streaming server: emitter of video streams (movies)
* Can send in unicast or multicast IP for client listeners
* that can play in real time the transmitted movies
*/

import java.io.*;
import java.net.*;

class hjStreamServer {

	static public void main( String []args ) throws Exception {
		String new_rgs[] = server_shp_phase1.server(5001);
		System.out.println("all args: "+new_rgs[0]+" "+new_rgs[1]+" "+new_rgs[2]);

		// args[0] = destination IP
		// args[2] = destination port
		// args[1] = file name
		
		int size;
		int count = 0;
 		long time;
		DataInputStream g = new DataInputStream( new FileInputStream("./movies/"+new_rgs[2]) );
		byte[] buff = new byte[65000];
		DatagramSocket s = new DatagramSocket();
		InetSocketAddress addr =
		    new InetSocketAddress(new_rgs[0],Integer.parseInt(new_rgs[1]));

		System.out.println("sending to "+addr);
		DatagramPacket p=new DatagramPacket(buff,buff.length,addr);
		long t0 = System.nanoTime(); // tempo de referencia
		long q0 = 0;
		System.out.println("waiting connection");
		DSTP.init(new CryptoConfig("ciphersuite.conf"));
		while ( g.available() > 0 ) {
			size = g.readShort();
			time = g.readLong();
			if ( count == 0 ) q0 = time; // tempo de referencia no stream
			count += 1;
			g.readFully(buff, 0, size );
			p.setData(buff, 0, size );
			p.setSocketAddress( addr );
			long t = System.nanoTime();
			Thread.sleep( Math.max(0, ((time-q0)-(t-t0))/1000000) );
			DSTP.send(p, s);
			
			//s.send(p);
			System.out.print( "." );
		}

		System.out.println("DONE! packets sent: "+count);
	}

}
