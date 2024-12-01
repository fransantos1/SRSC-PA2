import java.net.*;
import java.security.SecureRandom;
import java.security.SecureRandomSpi;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.IOException;

/*
TCP, following a Client/Server Model

• Password-based encryption methods
• Public-key cryptography
• Digital signatures
• Diffie-Hellman key agreement"


Phase 01 (16 vals I think)
    • Use of Password Based Encryption (LAB 3 Materials), Digital Signatures and HMAC as
        basic Cryptographic Constructions for Phase 1
Phase 02
     •Use of Password Based Encryption (LAB 3 Materials), Digital Signatures, DiffieHellman Agreements and HMAC as required Cryptographic Constructions for Phase 2
     • Complementary improvements

SHP packet

SHP Protocol Version(4 bits) 
SHP protocol Release(4 bits)
MsgType code(8 bits)
SHP Message Payload  (Variable Size, depending on the MsgType)


    Client:
        Cleint ECC Key Pairs
        Server PublicKey
    
    Server:
        Users Database
        Server ECC Key Pairs
        Crypto Params (PA1)

     */

import DataBase.dataBaseManager;

public class SHP {
    private final int HEADERSIZE = 2;
    private int ver = 0;
    private int release = 0;


    public SHP (){}
    public void client() throws IOException{
        /*
    message 3(type 3): client-> server
        PBEH(password), Salt, Counter (request, userID, Nonce3+1, Nonce4 , udp_port),
        DigitalSig (request, userID, Nonce3+1, Nonce4 , udp_port ),
        HMACkmac (X)

        MsgType 3 size: Size depending on used cryptographic constructions in message components
        request: the request, according to the application (ex., movie or files to transfer)
        PBE() : Must choose a secure PasswordBasedEncryption scheme
        DigitlSig() : an ECDSA Signature, made with the client ECC private key (with a selected curve)
        HMAC(): Must choose a secure HMAC construction, with the kmac derived from the password
        X: the content of all (encrypted and signed) components in the message, to allow a fast message authenticity and integrity check

   

    message 5(type 5): client-> server
        Eks (”GO”, Nonce5 + 1), MACKmac (Eks (”GO”, Nonce5 + 1))

        MsgType 5: is just a synchronization message, the Keys for E() and MAC() are those received
        in crypto config (in cipersuite.conf) sent from the server in MsgType 4).
        MsgType 5 size: dependis on the used cryptographic constructions, with Ks and Kmac
        depending on the configurations in ciphersuite.conf
        In this message, the client informs the server that it will be able to use the established
        cryptographic configurations (and included keys), as well as proving knowledge of the
        cryptographic keys to use with the symmetric cryptographic constructions, the symmetric
        cryptographic algorithms, and the MAC constructions (HMAC or SHA) that have been
        established.
         */

        Socket socket = new Socket();
        socket.connect(new InetSocketAddress("127.0.0.1", 5001), 1000);
        System.out.println("Connection Successful!");
        DataInputStream dataIn = new DataInputStream(socket.getInputStream());
        DataOutputStream dataOut = new DataOutputStream(socket.getOutputStream());

        int type = 1;
        byte[] msg = "eusouofran@gmail.com".getBytes();
        byte[] Nonces = new byte[48];
        
        while(true){
            //-------------------------------------------- SEND MESSAGE 1 ---------------------------------------------------------//
                /* message 1(type 1): client-> server
                        320 Bytes max
                        userId( String of max 320bytes )*/
            SHPPacket outpacket = new SHPPacket(ver, release, type, msg);
            sendPacket(dataOut, outpacket);
            if(type == 5){
                break;
            }

            SHPPacket inpacket = recievePacket(dataIn);
            switch(inpacket.getMsgType()){
                case 2:
                    //-------------------------------------------- RECIEVE MESSAGE 2 ------------------------------------------------------//
                    Nonces = inpacket.getMsg();

                    System.out.print("Recieved 3 nonces:");
                    for (int i = 0; i < 3; i++) {
                        byte[] nonce = new byte[16];
                        System.arraycopy(Nonces, i * 16, nonce, 0, 16);
                        System.out.print(" Nonce " + (i + 1) + ": " + bytesToHex(nonce));
                    }
                    System.out.println("\n");
                    //-------------------------------------------- SEND MESSAGE 3 ---------------------------------------------------------//
                    type = 3;
                    break;
                case 4:
                    //-------------------------------------------- RECIEVE MESSAGE 4 ------------------------------------------------------//
                    //-------------------------------------------- SEND MESSAGE 5 ---------------------------------------------------------//
                    type = 5;
                    break;
            }

        }
       
        dataIn.close();
        dataOut.close();
        socket.close();
    }
    //server side
    public void server() throws IOException{
        SecureRandom secrandom = new SecureRandom();
        dataBaseManager DB = new dataBaseManager();
        /*
 

            message 4(type 4): server-> client
                Ekpubclient (request-confirmation, Nonce4+1, Nonce5, crypto config),
                DigitalSig (request-confirmation, userID, Nonce4+1, Nonce5 , crypto config),
                HMACkmac (X)

                MsgType 4 size: size depending on used cryptographic constructions
                Request-confirmation: confirmation of client request (message type 3)
                DigitlSig: an ECDSA Signature, made with the client ECC probate key (with a selected curve)
                Must choose a secure HMAC construction, with the kmac as used in MsgType3
                Crypto config: datatype to send the Crypto configurations (ciphersuite.conf)
                X: the content of all (encrypted and signed) components in the message, to allow a fast message authenticity and integrity check

        */
       
        ServerSocket serverSocket = new ServerSocket(5001);
        System.out.println("Listening for clients...");
        Socket clientSocket = serverSocket.accept();
        String clientSocketIP = clientSocket.getInetAddress().toString();
        int clientSocketPort = clientSocket.getPort();
        System.out.println("[IP: " + clientSocketIP + " ,Port: " + clientSocketPort +"]  " + "Client Connection Successful!");
        DataInputStream dataIn = new DataInputStream(clientSocket.getInputStream());
        DataOutputStream dataOut = new DataOutputStream(clientSocket.getOutputStream());
        byte[] Nonces = new byte[48];


        int type = 0;
        byte[] msg = "hello from server".getBytes();
        while(true){
            SHPPacket inpacket = recievePacket(dataIn);
            switch(inpacket.getMsgType()){
                case 1:
                    //-------------------------------------------- RECIEVE MESSAGE 1 ----------------------------------------------------------//3
                    String userID = new String(inpacket.getMsg());
                    System.out.println("Recieved usrID: "+ userID);
                    //-------------------------------------------- SEND MESSAGE 2 -------------------------------------------------------------//
                    /* message 2(type 2): server-> client
                            48 bytes
                            Nonce1, Nonce2, Nonce3
                            Nonces: Secure Randomly Generatd by the Server, 128 bits each one (128*3 / 8 = 48) */

                    
                    for(int i = 0; i < 3; i++){
                        byte[] nonce = new byte[16];
                        secrandom.nextBytes(nonce);
                        System.arraycopy(nonce, 0 , Nonces, nonce.length*i , nonce.length);
                        
                    }
                    msg = Nonces;
                    type = 2;
                    break;
                case 3:
                    //-------------------------------------------- RECIEVE MESSAGE 3 ----------------------------------------------------------//
                    //-------------------------------------------- SEND MESSAGE 4 -------------------------------------------------------------//
                    type = 4;
                    break;
                case 5:
                    //-------------------------------------------- RECIEVE MESSAGE 5 ----------------------------------------------------------//
                    type = 5;
                    break;
            }


            if(type == 5)
                break;
            if(msg == null)
                break;
            SHPPacket outpacket = new SHPPacket(ver, release, type, msg);
            sendPacket(dataOut, outpacket);
  
             
        }
        dataIn.close();
        dataOut.close();
        serverSocket.close();
        clientSocket.close();
    }



    private void sendPacket(DataOutputStream out,SHPPacket packet) throws IOException{
        byte[] outpacket = packet.toByteArray();
        out.writeInt(outpacket.length);
        out.write(outpacket);
    }

    private SHPPacket recievePacket(DataInputStream in) throws IOException{

        byte[] inpacket = new byte[in.readInt()];
        in.read(inpacket);
        SHPPacket packet = SHPPacket.fromByteArray(inpacket);
        System.out.println(packet.toString());
        return packet;
    }

    public static String bytesToHex(byte[] bytes) {
        StringBuilder sb = new StringBuilder();
        for (byte b : bytes) {
            sb.append(String.format("%02x", b));
        }
        return sb.toString();
    }

}   



/*
     
                     */