
import java.net.*;
import java.nio.ByteBuffer;
import java.security.Key;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.SecureRandomSpi;
import java.security.Security;
import java.security.Signature;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;
import java.util.Properties;

import javax.crypto.Cipher;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.PBEParameterSpec;

import DataBase.User;

import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.FileInputStream;
import java.io.IOException;
import java.math.BigInteger;



public class client_shp_phase1 {
    private int ver = 0;
    private int release = 0;
    private static byte[] delimiter = {0x00, 0x1E, 0x52, 0x00};
    private final String  path = "./Client/";

    public client_shp_phase1(){
    }

    public void client() throws Exception{

        Properties client_properties = new Properties();
        Properties server_properties = new Properties();
        FileInputStream fis = new FileInputStream(path+"ClientECCKeyPair.sec");
        client_properties.load(fis);
        fis = new FileInputStream(path+"ServerECCPubKey.txt");
        server_properties.load(fis);
        fis.close();

       

        // DIGITAL SIGNATURE.
        KeyFactory keyFactory = KeyFactory.getInstance("ECDSA", "BC");

        //---------------------------------------------------------------------- PRIVATE KEY -----------------------------------------------------//
        String privateKeyBase641 = client_properties.getProperty("PrivateKey");
        byte[] privateKeyBytes = Base64.getDecoder().decode(privateKeyBase641);
        PKCS8EncodedKeySpec privateKeySpec = new PKCS8EncodedKeySpec(privateKeyBytes);
        PrivateKey privateKey = keyFactory.generatePrivate(privateKeySpec);

        //---------------------------------------------------------------------- PUBLIC KEY -----------------------------------------------------//

        String publicKeyBase641 = client_properties.getProperty("PublicKey");
        byte[] publicKeyBytes = Base64.getDecoder().decode(publicKeyBase641);
        X509EncodedKeySpec publicKeySpec = new X509EncodedKeySpec(publicKeyBytes);
        PublicKey publicKey = keyFactory.generatePublic(publicKeySpec);
        
        KeyPair keyPair = new KeyPair(publicKey, privateKey);
        //----------------------------------------------------------------------SERVER PUBLIC KEY -----------------------------------------------//

        String publicKeyServer64 = server_properties.getProperty("PublicKey");
        byte[] publicKeyBytes_Server = Base64.getDecoder().decode(publicKeyServer64);
        X509EncodedKeySpec server_PublicKeySpec = new X509EncodedKeySpec(publicKeyBytes_Server);
        PublicKey serverPublicKey = keyFactory.generatePublic(server_PublicKeySpec);



       
        Signature signature = Signature.getInstance("SHA256withECDSA", "BC");


        User client = new User("alice@gmail.com", "24c1f255e20fbe37e8a7f7090c8d1c2923c39e2a9bc21146f876e174cb6d41ec", "4f1b78329c106679a3dbec3cd9d97b0b", null);
        
	   



        int iterationCount = 2048; 
        int udp_port = 5001;

        Socket socket = new Socket();
        socket.connect(new InetSocketAddress("127.0.0.1", udp_port), 1000);
        System.out.println("Connection Successful!");
        DataInputStream dataIn = new DataInputStream(socket.getInputStream());
        DataOutputStream dataOut = new DataOutputStream(socket.getOutputStream());

        int type = 1;
        byte[] msg = client.getId().getBytes();
        ArrayList<byte[]> nonces = new ArrayList<>();

        
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
                    byte[] body = inpacket.getMsg();

                    System.out.print("Recieved 3 nonces:");
                    for (int i = 0; i < 3; i++) {
                        byte[] nonce = new byte[16];
                        System.arraycopy(body, i * 16, nonce, 0, 16);
                        nonces.add(nonce);
                        System.out.print(" Nonce " + (i + 1) + ": " + bytesToHex(nonce));
                    }
                    System.out.println("\n");

                    //-------------------------------------------- SEND MESSAGE 3 ---------------------------------------------------------//

                    /* message 3(type 3): client-> server
                            - PBE H(password),Salt,Counter (request, userID, Nonce3+1, Nonce4 , udp_port),
                        DigitalSig (request, userID, Nonce3+1, Nonce4 , udp_port ),
                        HMACkmac (X)
                        MsgType 3 size: Size depending on used cryptographic constructions in message components
                        request: the request, according to the application (ex., movie or files to transfer)
                        PBE() : Must choose a secure PasswordBasedEncryption scheme
                        DigitlSig() : an ECDSA Signature, made with the client ECC private key (with a selected curve)
                        HMAC(): Must choose a secure HMAC construction, with the kmac derived from the password
                        X: the content of all (encrypted and signed) components in the message, to allow a fast message authenticity and integrity check*/
                    
                    
                    ArrayList<byte[]> PBE_body = new ArrayList<>(); 
                    ArrayList<byte[]> DigitalSig = new ArrayList<>(); 
                
                    //request
                    byte[] request = "req2uest".getBytes();
                    PBE_body.add(request);
                    //userId
                    byte[] usrid = client.getId().getBytes();
                    PBE_body.add(usrid);
                    //nonce3+1
                    byte[] Nonce3 = nonces.get(2);
                    byte[] nonce3_new = new BigInteger(Nonce3).add(BigInteger.ONE).toByteArray();
                    PBE_body.add(nonce3_new);
                    //nonce4    
                    byte[] nonce4 = genNonce();
                    PBE_body.add(nonce4);
                    //udpPort
                    byte[] udpPortSend = Utils.toByteArray(String.valueOf(udp_port));
                    PBE_body.add(udpPortSend);
                    
                    System.out.println("-------------------------------------------------");
                    System.out.println("request     : " + new String(request) +
                                    " | Size: " + request.length);
                    System.out.println("usrid       : " + new String(usrid) +
                                    " | Size: " + usrid.length);
                    System.out.println("new Nonce3  : " + new BigInteger(1, nonce3_new).toString(16) +
                                    " | Size: " + nonce3_new.length);
                    System.out.println("nonce4      : " + new BigInteger(1, nonce4).toString(16) +
                                    " | Size: " + nonce4.length);
                    System.out.println("udpPortSend : " + Integer.parseInt(Utils.toString(udpPortSend)) +
                                    " | Size: " + udpPortSend.length);
                    System.out.println("-------------------------------------------------");
                    
                    byte[] new_body = concenateByteArr(PBE_body);

                    char[] password = client.getPwd().toCharArray();
                    byte[] salt = hexStringToByteArray(client.getSalt());
                    System.out.print("Salt: {");
                    for (int i = 0; i < salt.length; i++) {
                        System.out.print("0x" + String.format("%02x", salt[i]) + (i < salt.length - 1 ? ", " : " "));
                    }
                    System.out.println("}\n This has: "+ salt.length*8+" bits");
 
                    // Encryption 
                    PBEKeySpec pbeSpec = new PBEKeySpec(password);
                    SecretKeyFactory keyFact = SecretKeyFactory.getInstance("PBEWITHSHA256AND192BITAES-CBC-BC","BC");
                    Key sKey= keyFact.generateSecret(pbeSpec);
                    Cipher cEnc = Cipher.getInstance("PBEWITHSHA256AND192BITAES-CBC-BC","BC");
                    cEnc.init(Cipher.ENCRYPT_MODE, sKey, new PBEParameterSpec(salt, iterationCount));
                    
                    // Signature
                    signature.initSign(keyPair.getPrivate(), new SecureRandom());
                    signature.update(new_body);

                    ArrayList<byte[]> arrBody = new ArrayList<>();
                    byte[] PBE = cEnc.doFinal(new_body);
                    arrBody.add(PBE);

                    byte[]  sigBytes = signature.sign();
                    arrBody.add(sigBytes);

                    msg = concenateByteArr(arrBody);

                    type = 3;


                    
                    break;
                case 4:
                    //-------------------------------------------- RECIEVE MESSAGE 4 ------------------------------------------------------//

                    //-------------------------------------------- SEND MESSAGE 5 ---------------------------------------------------------//
                    /*message 5(type 5): client-> server
                        Eks (”GO”, Nonce5 + 1), MACKmac (Eks (”GO”, Nonce5 + 1))
                        MsgType 5: is just a synchronization message, the Keys for E() and MAC() are those received
                        in crypto config (in cipersuite.conf) sent from the server in MsgType 4).
                        MsgType 5 size: dependis on the used cryptographic constructions, with Ks and Kmac
                        depending on the configurations in ciphersuite.conf
                        In this message, the client informs the server that it will be able to use the established
                        cryptographic configurations (and included keys), as well as proving knowledge of the
                        cryptographic keys to use with the symmetric cryptographic constructions, the symmetric
                        cryptographic algorithms, and the MAC constructions (HMAC or SHA) that have been
                        established.*/
                    type = 5;
                    break;
            }

        }
       
        dataIn.close();
        dataOut.close();
        socket.close();
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

    private static String bytesToHex(byte[] bytes) {
        StringBuilder sb = new StringBuilder();
        for (byte b : bytes) {
            sb.append(String.format("%02x", b));
        }
        return sb.toString();
    }


    /*  The provided converter in Utils wasnt outputing correctly and was outputing with double the size
     * https://stackoverflow.com/questions/140131/convert-a-string-representation-of-a-hex-dump-to-a-byte-array-using-java
    */
    public static byte[] hexStringToByteArray(String s) {
        int len = s.length();
        byte[] data = new byte[len / 2];
        for (int i = 0; i < len; i += 2) {
            data[i / 2] = (byte) ((Character.digit(s.charAt(i), 16) << 4)
                                 + Character.digit(s.charAt(i+1), 16));
        }
        return data;
    }
    public static byte[] genNonce(){
        SecureRandom secrandom = new SecureRandom();
        byte[] nonce = new byte[16];
        secrandom.nextBytes(nonce);
        return nonce;
    }

    public static byte[] concenateByteArr(ArrayList<byte[]> list){
        int totalLen = 0;
        for(int i = 0; i < list.size(); i++){

            totalLen += list.get(i).length;
            if(i != list.size()-1)
                totalLen+= delimiter.length;
        }   

        byte[] returnByte = new byte[totalLen];
        int index = 0;

        for( int i = 0; i < list.size(); i++){
            byte[] putByte = list.get(i);
            System.arraycopy(putByte , 0, returnByte, index, putByte.length);
            index += putByte.length;
            if(i != list.size()-1){
                System.arraycopy(delimiter , 0, returnByte, index, delimiter.length);
                index += delimiter.length;
            }
        }
        return returnByte;
    }
    public static ArrayList<byte[]> separateByteArr(byte[] arr){
        ArrayList<byte[]> list = new ArrayList<>();
        int copyIndex = 0;
        int delIndex = 0;
        System.out.println(bytesToHex(arr));
        for(int i = 0; i < arr.length; i++){
            if(arr[i] != delimiter[delIndex]){
                delIndex = 0;
                continue;
            }
            if(delIndex < delimiter.length-1){
                delIndex++;
                continue;
            }
            int size = i - delIndex - copyIndex;
            delIndex = 0;
            byte[] insertByte = new byte[size];

            System.arraycopy(arr, copyIndex, insertByte, 0, size);
            list.add(insertByte);
            copyIndex = i+1;
        }
        int size = arr.length - copyIndex;
        byte[] insertByte = new byte[size];
        System.arraycopy(arr, copyIndex, insertByte, 0, size);
        list.add(insertByte);

        return list;
    }

    
}
