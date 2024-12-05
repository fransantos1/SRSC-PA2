import java.net.*;
import java.nio.ByteBuffer;
import java.security.Key;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;
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
import javax.crypto.Mac;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.PBEParameterSpec;
import javax.crypto.spec.SecretKeySpec;

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


        // LOADING CRYPTO CONFIG


        CryptoConfig cryptoConfig = new CryptoConfig("cryptoconfig.txt");


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


        
        Mac hMac = Mac.getInstance("HMacSHA256");
        Key hMacKey = null;


        Cipher cipher;

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
            System.out.println("Recieved Message: "+ Utils.toHex(inpacket.getMsg()));
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


                    byte[] pwd_byteArr = Base64.getDecoder().decode(user.getPwd());
                    hMacKey = new SecretKeySpec(pwd_byteArr, "HMacSHA256");
                    hMac.init(hMacKey);
                    
                    System.out.println("full User: "+ user.toString());

                    //-------------------------------------------- SEND MESSAGE 2 -------------------------------------------------------------//
        
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
                    
                    ArrayList<byte[]> bodyArr = separateByteArr(inpacket.getMsg());
                    byte[] hash = bodyArr.get(2);
                    bodyArr.remove(2);


                    // Verifying Hash
                    // first thing because is the fastest

                    hMac.update(concenateByteArr(bodyArr), 0, concenateByteArr(bodyArr).length);
                    byte[] newHash = hMac.doFinal();
                    if(!MessageDigest.isEqual(newHash, hash)){
                        System.out.println("Incorrect HASH");
                        isErr = true;
                        break;
                    }

                    // Decrypting Body
                    byte[] PBE = bodyArr.get(0);


                    char[] password = user.getPwd().toCharArray();
                    byte[] salt = hexStringToByteArray(user.getSalt());
                    PBEKeySpec pbeSpec = new PBEKeySpec(password);
                    SecretKeyFactory keyFact = SecretKeyFactory.getInstance("PBEWITHSHA256AND192BITAES-CBC-BC","BC");
                    Key sKey= keyFact.generateSecret(pbeSpec);
                    Cipher cDec = Cipher.getInstance("PBEWITHSHA256AND192BITAES-CBC-BC","BC");
                         
                    cDec.init(Cipher.DECRYPT_MODE, sKey, new PBEParameterSpec(salt, iterationCount));

                    byte[] inBytes = cDec.doFinal(PBE);
                    ArrayList<byte[]> inPBEArrayList = separateByteArr(inBytes);

                    // Request
                    String request = new String(inPBEArrayList.get(0));

                    //Validate UserId
                    String userid = new String(inPBEArrayList.get(1));
                    if(!userid.equals(user.getId())){
                        System.out.println("TYPE 3 RECIEVED : NOT THE RIGHT USER");
                        isErr = true;
                        break;
                    }

                    // nonce challange
                    byte[] challengeNonce3 = inPBEArrayList.get(2);
                    byte[] correct_challengeNonce3 = new BigInteger(nonces.get(2)).add(BigInteger.ONE).toByteArray();
                    if(!Arrays.equals(challengeNonce3, correct_challengeNonce3)){
                        System.out.println("Nonce 3 is not correct");
                        isErr = true;
                        break;
                    }    

                    // new nonce
                    byte[] nonce4 = inPBEArrayList.get(3);
                    nonces.add(nonce4);

                    // client UDP_port
                    int inUDP_port = Integer.parseInt(Utils.toString(inPBEArrayList.get(4)));


                    byte[] sig = bodyArr.get(1);

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


                    // Encrypted body
                    ArrayList<byte[]> fullBodyArray = new ArrayList<>();

                    byte[] body1;
                    ArrayList<byte[]> body1Arr = new ArrayList<>();
                    byte[] request_confirmation = inPBEArrayList.get(0);
                    body1Arr.add(request_confirmation);
                    byte[] nonce4_1 = new BigInteger(nonces.get(3)).add(BigInteger.ONE).toByteArray();
                    body1Arr.add(nonce4_1);
                    byte[] nonce5 = genNonce();
                    body1Arr.add(nonce5);
                    nonces.add(nonce5);


                    byte[] cryptoConfByteArr = cryptoConfig.toByteArray();
                    body1Arr.add(cryptoConfByteArr);
                    body1 = concenateByteArr(body1Arr);

                    cipher = Cipher.getInstance("ECIES", "BC");
                    cipher.init(Cipher.ENCRYPT_MODE, clientPubKey);
                    byte[] encryptedMessage = cipher.doFinal(body1);

                    fullBodyArray.add(encryptedMessage);


                    // DIGITAL SIGNATURE
                    
                    byte[] body2;
                    ArrayList<byte[]> body2ArrayList = new ArrayList<>();
                    body2ArrayList.add(request_confirmation);
                    byte[] userId = user.getId().getBytes();
                    body2ArrayList.add(userId);
                    body2ArrayList.add(nonce4_1);
                    body2ArrayList.add(nonce5);
                    body2ArrayList.add(cryptoConfByteArr);
                    body2 = concenateByteArr(body2ArrayList);

                    signature.initSign(privateKey, new SecureRandom());
                    signature.update(body2);
                    byte[]  signedBody2 = signature.sign();

                    fullBodyArray.add(signedBody2);

                    // HMAC
                    hMac.update(body1);

                    byte[] sendHash = hMac.doFinal();

                    System.out.println("New hash: " +Utils.toHex(sendHash));
                    fullBodyArray.add(sendHash);

                    msg = concenateByteArr(fullBodyArray);

                    type = 4;
                    break;
                case 5:
                    //-------------------------------------------- RECIEVE MESSAGE 5 ----------------------------------------------------------//
                    System.out.println("//-------------------------------------------- RECIEVED MESSAGE 5 ----------------------------------------------------------//");
                    byte[] encrypted = inpacket.getMsg();
                    cipher = Cipher.getInstance(cryptoConfig.getCiphersuite());
                    if (cryptoConfig.getIvSpec() != null) {
                        cipher.init(Cipher.DECRYPT_MODE, cryptoConfig.getKey(), cryptoConfig.getIvSpec());
                    } else {
                        cipher.init(Cipher.DECRYPT_MODE, cryptoConfig.getKey());
                    }



                    byte[] extratedBody =new byte[cipher.getOutputSize(encrypted.length)];
                    System.out.println("predicted size: " + cipher.getOutputSize(encrypted.length));


                    int ptLen = cipher.update(encrypted,0, encrypted.length, extratedBody,0);
                    cipher.doFinal(extratedBody, ptLen);

                    ArrayList<byte[]> decryptedBody = separateByteArr(extratedBody);
                    
                    System.out.println("-----------------------------------------------------------------------");
                    System.out.println("Decrypted: " + Utils.toHex(extratedBody));
                    System.out.println("Decrypted Length: " + extratedBody.length);
                    System.out.println("Array size: " + decryptedBody.size());
                    System.out.println("GO part: " + new String(decryptedBody.get(0)));
                    System.out.println("Nonce :" + Utils.toHex(decryptedBody.get(1)));
                    System.out.println(Arrays.equals(decryptedBody.get(1),  new BigInteger(nonces.get(4)).add(BigInteger.ONE).toByteArray()));
                    System.out.println("-----------------------------------------------------------------------");
                    


                    



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