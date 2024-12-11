import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.security.MessageDigest;

import javax.crypto.Cipher;
import javax.crypto.Mac;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;

import Common.*;

/*
    CONFIDENTIALIY: ALG/MODE/PADDING
    SYMMETRIC_KEY: key in hexadecimal value with the required key size
    SYMMTRIC_KEY_SIZE: integer representing the number of BITS
    IV_SIZE: integer or NULL
    IV: hexadecimal value or NULL
    INTEGRITY: HMAC or H
    H: definition of secure ash Function or NULL
    MAC: definition of MAC (HMAC or CMAC algorithms)
    MACKEY: mackey value in hexadecimal with rquired keysize or NULL
    MACKEY_SIZE: integer representing the size of the MACKEY in BITS
 */







public class DSTP {

    private static String ciphersuite = null;
    private static IvParameterSpec ivSpec = null;
    private static SecretKey key = null;
    private static MessageDigest hash = null;
    private static Mac hMac = null;
    private static SecretKey hMacKey = null;
    private static byte[] keyBytes = null;
    private static int sequenceNumber = 0;


    public static void init(CryptoConfig config) throws Exception {
        ciphersuite = config.getCiphersuite();
        key = config.getKey();
        ivSpec = config.getIvSpec();

        System.out.println(config.toString());
        
        
        if (config.getDigestType() == config.HASH) {
            hash = config.getHash();
            System.out.println("Using Hash: "+hash.getAlgorithm());

        }else{
            hMac = config.getHMac();
            hMacKey =config.getHMacKey();
        }

    }


/*
         DSTP Packet format
    DSTP Header:
    Version(16bit) | Release(8bit) | Payload Len(16bit) 

    DSTP Payload:
    Encrypted( Sequence Number(16bit) | DATA(variable) | H(variable) )
    Encrypted( Sequence Number(16bit) | DATA(variable) | HMAC(variable) )
 */

 public static void receave(DatagramSocket socket, DatagramPacket outPacket) throws Exception {
    System.out.println("----------------------------RECIEVING----------------------------");
    //RECIEVING
    Cipher cipher = Cipher.getInstance(ciphersuite);

    byte[] fullPayLoad = new byte[8192];
    DatagramPacket packet = new DatagramPacket(fullPayLoad, fullPayLoad.length);
    socket.receive(packet); // Receive packet
    

    byte[] header = new byte[5];
    System.arraycopy(fullPayLoad, 0, header, 0, header.length);
    int extractedVersion = ((header[0] & 0xFF) << 8) | (header[1] & 0xFF); // Combine to get version
    int extractedRelease = header[2] & 0xFF; // 8-bit release value
    int extractedPayloadLen = ((header[3] & 0xFF) << 8) | (header[4] & 0xFF); // Combine to get payload length
    System.out.println(extractedVersion);



    if(ivSpec != null){
        cipher.init(Cipher.DECRYPT_MODE, key,ivSpec);
    }else{
        cipher.init(Cipher.DECRYPT_MODE, key);
    }


    
    byte[] extractedDSTPPayload =new byte[cipher.getOutputSize(extractedPayloadLen)];
    int ptLength = 0;
    ptLength=cipher.update(fullPayLoad,5, extractedPayloadLen, extractedDSTPPayload,0);
    ptLength += cipher.doFinal(extractedDSTPPayload, ptLength);
    //PAYLOAD


    int hashSize = 0;
    if(hash != null){
       hashSize = hash.getDigestLength();
   }else{
       hMac.init(hMacKey);
       hashSize =hMac.getMacLength();
   }


    int extractedSequenceNumber = ((extractedDSTPPayload[0] & 0xFF) << 8) | (extractedDSTPPayload[1] & 0xFF); // Sequence number
    System.out.println("Extracted Sequence Number: " + extractedSequenceNumber);

    byte[] extractedMessageBytes = new byte[extractedPayloadLen -2- hashSize]; // Adjust as needed
    System.arraycopy(extractedDSTPPayload, 2, extractedMessageBytes, 0, extractedMessageBytes.length); // Adjust offset if needed;
   System.out.println(Utils.toString(extractedMessageBytes));
    
    byte[] extractedHashIn = new byte[hashSize];
    System.arraycopy(extractedDSTPPayload, 2+extractedMessageBytes.length, extractedHashIn, 0, extractedHashIn.length); // Adjust offset if needed

    System.out.println("Message Extracted Size: " +extractedMessageBytes.length);

    byte[] inMessageHash;
     if(hash != null){
        inMessageHash = new byte[hash.getDigestLength()];
        hash.update(extractedMessageBytes);
        inMessageHash = hash.digest();
    }else{
        hMac.init(hMacKey);
        inMessageHash = new byte[hMac.getMacLength()];
        hMac.update(extractedMessageBytes);
        inMessageHash = hMac.doFinal();
    }

    
    if(!MessageDigest.isEqual(inMessageHash, extractedHashIn)){
        System.out.println("Message Tempered");
        return;
    }
    System.out.println("Message Verified");
    
    outPacket.setAddress(packet.getAddress());
    outPacket.setPort(packet.getPort());

    outPacket.setData(extractedMessageBytes, 0, extractedMessageBytes.length);
}



public static void send(DatagramPacket packet, DatagramSocket socket)  throws Exception {
    sequenceNumber ++;

    byte[] inByteArray = new byte[packet.getLength()]; 
    System.out.print(inByteArray.length);
    System.arraycopy(packet.getData(), 0, inByteArray, 0, packet.getLength());

    //Initialize tools
     Cipher cipher = Cipher.getInstance(ciphersuite);
     if(ivSpec != null){
         cipher.init(Cipher.ENCRYPT_MODE, key,ivSpec);
     }else{
         cipher.init(Cipher.ENCRYPT_MODE, key);
     }

     byte[] sendHash;
     if(hash != null){
        sendHash = new byte[hash.getDigestLength()];
        hash.update(inByteArray);
        sendHash = hash.digest();
    }else{
        hMac.init(hMacKey);
        sendHash = new byte[hMac.getMacLength()];
        hMac.update(inByteArray);
        sendHash = hMac.doFinal();
    }


    //Version(16bit) | Release(8bit) | Payload Len(16bit)  
 
        byte[] DSTPPayload = new byte[2 + packet.getLength()  + sendHash.length]; //+2 is for the sequence number

        
        DSTPPayload[0] = (byte) ((sequenceNumber >> 8) & 0xFF);
        DSTPPayload[1] = (byte) (sequenceNumber & 0xFF); 

        System.arraycopy(inByteArray, 0, DSTPPayload, 2, packet.getLength());

        System.arraycopy(sendHash, 0, DSTPPayload, 2+packet.getLength(), sendHash.length);

    
        byte[] encryptDSTPayload = cipher.doFinal(DSTPPayload);



        int version = 0x009; 
        int release = 0x05; 
        int payloadLen = encryptDSTPayload.length;
        

        byte[] DSTPHeader = new byte[5];
        DSTPHeader[0] = (byte) ((version >> 8) & 0xFF); 
        DSTPHeader[1] = (byte) (version & 0xFF);     
        DSTPHeader[2] = (byte) (release & 0xFF);   
        DSTPHeader[3] = (byte) ((payloadLen >> 8) & 0xFF); 
        DSTPHeader[4] = (byte) (payloadLen & 0xFF);
        

        byte[] fullPayLoad = new byte[encryptDSTPayload.length + DSTPHeader.length];

        System.arraycopy(DSTPHeader, 0, fullPayLoad, 0, DSTPHeader.length);
        System.arraycopy(encryptDSTPayload, 0, fullPayLoad, DSTPHeader.length, encryptDSTPayload.length);

        packet.setData(fullPayLoad);
        packet.setLength(fullPayLoad.length);

        socket.send(packet);

    }

}
