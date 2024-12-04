import java.net.*;
import java.nio.ByteBuffer;
import java.security.Key;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.SecureRandomSpi;
import java.security.Security;
import java.security.Signature;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.ECPrivateKeySpec;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.sql.ClientInfoStatus;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Base64;
import java.util.List;
import java.util.Properties;

import javax.crypto.Cipher;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.PBEParameterSpec;

import DataBase.*;

import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.math.BigInteger;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.util.Properties;







public class server_shp_phase1 {
    private final String  path = "./Server/";


    private int ver = 0;
    private int release = 0;
    private static byte[] delimiter = {0x00, 0x1E, 0x52, 0x00};
    public server_shp_phase1(){
        
    }




      public void server() throws Exception{

        Properties properties = new Properties();
        FileInputStream fis = new FileInputStream(path+"ServerECCKeyPair.sec");
        properties.load(fis);
        fis.close();

        String privateKeyBase641 = properties.getProperty("PrivateKey");
        String publicKeyBase641 = properties.getProperty("PublicKey");

        // Decode the Base64 strings to byte arrays
        byte[] privateKeyBytes = Base64.getDecoder().decode(privateKeyBase641);
        byte[] publicKeyBytes = Base64.getDecoder().decode(publicKeyBase641);


        PKCS8EncodedKeySpec privateKeySpec = new PKCS8EncodedKeySpec(privateKeyBytes);
        KeyFactory keyFactory = KeyFactory.getInstance("ECDSA", "BC");
        PrivateKey privateKey = keyFactory.generatePrivate(privateKeySpec);

        // Reconstruct the public key
        X509EncodedKeySpec publicKeySpec = new X509EncodedKeySpec(publicKeyBytes);
        PublicKey publicKey = keyFactory.generatePublic(publicKeySpec);

        KeyPair keypair = new KeyPair(publicKey, privateKey);


        ECGenParameterSpec ecSpec= new ECGenParameterSpec("secp256k1");
        Signature signature = Signature.getInstance("SHA256withECDSA", "BC");




        SecureRandom secrandom = new SecureRandom();
        dataBaseManager DB = new dataBaseManager();

        int iterationCount = 2048; 

        ServerSocket serverSocket = new ServerSocket(5001);
        System.out.println("Listening for clients...");
        Socket clientSocket = serverSocket.accept();
        String clientSocketIP = clientSocket.getInetAddress().toString();
        int clientSocketPort = clientSocket.getPort();
        System.out.println("[IP: " + clientSocketIP + " ,Port: " + clientSocketPort +"]  " + "Client Connection Successful!");
        DataInputStream dataIn = new DataInputStream(clientSocket.getInputStream());
        DataOutputStream dataOut = new DataOutputStream(clientSocket.getOutputStream());
        ArrayList<byte[]> nonces = new ArrayList<>();

        User user = null;
        int type = 0;
        byte[] msg = null;
        boolean isErr = false;
        PublicKey clientPubKey = null;
        while(true){
            SHPPacket inpacket = recievePacket(dataIn);
            switch(inpacket.getMsgType()){
                case 1:
                    //-------------------------------------------- RECIEVE MESSAGE 1 ----------------------------------------------------------//3
                    String userID = new String(inpacket.getMsg());
                    System.out.println("Recieved usrID: "+ userID);
                    System.out.println("Getting full account");
                    user = DB.getUser(userID);
                    String base64String = user.getKpubClient().replaceAll("\\s", ""); // Removes any spaces or newlines
                    byte[] client_keybytes = Base64.getDecoder().decode(base64String);
                    X509EncodedKeySpec client_keySPEC = new X509EncodedKeySpec(client_keybytes);
                    clientPubKey = keyFactory.generatePublic(client_keySPEC);

                    System.out.println("full User: "+ user.toString());

                    //-------------------------------------------- SEND MESSAGE 2 -------------------------------------------------------------//
                    /* message 2(type 2): server-> client
                            48 bytes
                            Nonce1, Nonce2, Nonce3
                            Nonces: Secure Randomly Generatd by the Server, 128 bits each one (128*3 / 8 = 48) */

                    msg = new byte[16*3];
                    for(int i = 0; i < 3; i++){
                        byte[] nonce = new byte[16];
                        secrandom.nextBytes(nonce);
                        System.arraycopy(nonce, 0 , msg, nonce.length*i , nonce.length);
                        nonces.add(nonce);
                    }
                    type = 2;
                    break;
                case 3:
                    //-------------------------------------------- RECIEVE MESSAGE 3 ----------------------------------------------------------//
                    byte[] input = inpacket.getMsg();
                    char[] password = user.getPwd().toCharArray();
                    byte[] salt = hexStringToByteArray(user.getSalt());
                    
                    ArrayList<byte[]> bodyArr = separateByteArr(input);
                    byte[] PBE = bodyArr.get(0);
                    byte[] sig = bodyArr.get(1);



                    PBEKeySpec pbeSpec = new PBEKeySpec(password);
                    SecretKeyFactory keyFact = SecretKeyFactory.getInstance("PBEWITHSHA256AND192BITAES-CBC-BC","BC");
                    Key sKey= keyFact.generateSecret(pbeSpec);
                    Cipher cDec = Cipher.getInstance("PBEWITHSHA256AND192BITAES-CBC-BC","BC");
                         
                    cDec.init(Cipher.DECRYPT_MODE, sKey, new PBEParameterSpec(salt, iterationCount));
                    byte[] inBytes = cDec.doFinal(PBE);


                    ArrayList<byte[]> new_arrayList = separateByteArr(inBytes);
                    String request = new String(new_arrayList.get(0));
                    System.out.println("Request: "+request);
                    String userid = new String(new_arrayList.get(1));
                    if(!userid.equals(user.getId())){
                        System.out.println("TYPE 3 RECIEVED: NOT THE RIGHT USER");
                        isErr = true;
                        break;
                    }

                    System.out.println("Still talking to the same correct User");

                    byte[] inNonce3 = new_arrayList.get(2);

                    byte[] myNonce3 = new BigInteger(nonces.get(2)).add(BigInteger.ONE).toByteArray();
                    System.out.println("Old nonce3   : " + bytesToHex(nonces.get(2)));
                    System.out.println("In nonce3    : " + bytesToHex(inNonce3));
                    System.out.println("My nonce3 +1 : " + bytesToHex(myNonce3));
                    if(!Arrays.equals(inNonce3, myNonce3)){
                        System.out.println("Nonce 3 is not correct");
                        isErr = true;
                        break;
                    }    
                    nonces.add(new_arrayList.get(3));
                    System.out.println("My nonce4    : " + bytesToHex(nonces.get(3)));
                    int inUDP_port = Integer.parseInt(Utils.toString(new_arrayList.get(4)));

                    signature.initVerify(clientPubKey);
                    signature.update(inBytes);
                    if (signature.verify(sig))
                    {
                        System.out.println("Assinatura ECDSA validada - reconhecida");
                    }
                    else
                    {
                        System.out.println("Assinatura nao reconhecida");
                    }

                    //-------------------------------------------- SEND MESSAGE 4 -------------------------------------------------------------//
                    /*message 4(type 4): server-> client
                            Ekpubclient (request-confirmation, Nonce4+1, Nonce5, crypto config),
                            DigitalSig (request-confirmation, userID, Nonce4+1, Nonce5 , crypto config),
                            HMACkmac (X)

                            MsgType 4 size: size depending on used cryptographic constructions
                            Request-confirmation: confirmation of client request (message type 3)
                            DigitlSig: an ECDSA Signature, made with the client ECC probate key (with a selected curve)
                            Must choose a secure HMAC construction, with the kmac as used in MsgType3
                            Crypto config: datatype to send the Crypto configurations (ciphersuite.conf)
                            X: the content of all (encrypted and signed) components in the message, to allow a fast message authenticity and integrity check*/
                    type = 4;
                    break;
                case 5:
                    //-------------------------------------------- RECIEVE MESSAGE 5 ----------------------------------------------------------//
                    type = 5;
                    break;
            }
            if(isErr){
                System.out.println("Error");
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
