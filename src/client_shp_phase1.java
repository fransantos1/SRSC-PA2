
import java.net.*;
import java.security.Key;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.MessageDigest;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Signature;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Base64;
import java.util.Properties;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.Mac;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.PBEParameterSpec;
import javax.crypto.spec.SecretKeySpec;

import java.io.ByteArrayOutputStream;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.ObjectOutputStream;
import java.math.BigInteger;





/*
Common params:
    server: the server host machine (DNS name) or IP address
    username: username as registered in the user database, server side
    password: user password
    tcp_port: the tcp port where the server is waiting to execute the SHP protocol


Streaming Service params:
    
    movie: the requested movie
    udp_port: the udp_port where the client will receive the movie for real-time playing
    player_port: the udp_port of the player that will play the streamed movie

TFTP Service params:
    type_r_w 
    filename 
    mode



 */



public class client_shp_phase1 {
    private int ver = 0;
    private int release = 0;
    private static byte[] delimiter = {0x00, 0x1E, 0x52, 0x00};
    private final String  path = "./Client/";


    public client_shp_phase1(){}

    public CryptoConfig client(String inusername, String inpwd, int server_tcp_port, int my_udp_port,String serverIp, String[] params) throws Exception{



         KeyGenerator keyGen = KeyGenerator.getInstance("RC4");
            keyGen.init(168, new SecureRandom()); // 168-bit key

            // Generate the secret key
            SecretKey secretKey = keyGen.generateKey();
            System.out.println("Secret key: " + Utils.toHex(secretKey.getEncoded()));
        
        MessageDigest tDigest = MessageDigest.getInstance("SHA-256");
        tDigest.update(inpwd.getBytes());
        
        // USER INFORMATION
        String username = inusername;
        byte[] pwd = tDigest.digest();
        byte[] salt;



        Properties client_properties = new Properties();
        Properties server_properties = new Properties();
        FileInputStream fis = new FileInputStream(path+"ClientECCKeyPair.sec");
        client_properties.load(fis);
        fis = new FileInputStream(path+"ServerECCPubKey.txt");
        server_properties.load(fis);
        fis.close();

       
        //--------------------------------------------------------------------- DIGITAL SIGNATURE -----------------------------------------------------------//

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
        //---------------------------------------------------------------------- SERVER PUBLIC KEY -----------------------------------------------//

        String publicKeyServer64 = server_properties.getProperty("PublicKey");
        byte[] publicKeyBytes_Server = Base64.getDecoder().decode(publicKeyServer64);
        X509EncodedKeySpec server_PublicKeySpec = new X509EncodedKeySpec(publicKeyBytes_Server);
        PublicKey serverPublicKey = keyFactory.generatePublic(server_PublicKeySpec);
       
        Signature signature = Signature.getInstance("SHA256withECDSA", "BC");


        //---------------------------------------------------------------------- SECURE KEYHASHING ------------------------------------------------//

        Mac hMac = Mac.getInstance("HMacSHA256");
        Key hMacKey = new SecretKeySpec(pwd, "HMacSHA256");
        System.out.println("password: "+Utils.toHex(pwd));
        System.out.println("hMacKey: "+Utils.toHex(hMacKey.getEncoded()));



        Cipher cipher;

        
        CryptoConfig cryptoConfig = null;

	   
        int iterationCount; 

        Socket socket = new Socket();
        socket.connect(new InetSocketAddress(serverIp, server_tcp_port), 1000);
        System.out.println("Connection Successful!");
        DataInputStream dataIn = new DataInputStream(socket.getInputStream());
        DataOutputStream dataOut = new DataOutputStream(socket.getOutputStream());

        System.out.println("//-------------------------------------------- SEND MESSAGE 1 ---------------------------------------------------------//");
        //-------------------------------------------- SEND MESSAGE 1 ---------------------------------------------------------//
        int type = 1;
        byte[] msg = username.getBytes();
        ArrayList<byte[]> nonces = new ArrayList<>();

        boolean finish = false;
        
        while(true){
            

            SHPPacket outpacket = new SHPPacket(ver, release, type, msg);
            sendPacket(dataOut, outpacket);
            
            if(type == 5){
                break;
            }

            SHPPacket inpacket = recievePacket(dataIn);
            switch(inpacket.getMsgType()){
                case 2:
                System.out.println("//-------------------------------------------- RECIEVE MESSAGE 2 ------------------------------------------------------//");
                    //-------------------------------------------- RECIEVE MESSAGE 2 ------------------------------------------------------//

                    byte[] body = inpacket.getMsg();
                    for (int i = 0; i < 3; i++) {
                        byte[] nonce = new byte[16];
                        System.arraycopy(body, i * 16, nonce, 0, 16);
                        nonces.add(nonce);
                    }
                    // nonce 1 is used to generate salt
                    salt = nonces.get(0);

                    // FIRST BYTE OF NONCE 2 IS ITERATION COUNT
                    iterationCount = nonces.get(1)[1] & 0xFF;
                    System.out.println("//-------------------------------------------- SEND MESSAGE 3 ---------------------------------------------------------//");

                    //-------------------------------------------- SEND MESSAGE 3 ---------------------------------------------------------//


                    //setup encryption
                    PBEKeySpec pbeSpec = new PBEKeySpec(Utils.toHex(pwd).toCharArray());
                    SecretKeyFactory keyFact = SecretKeyFactory.getInstance("PBEWITHSHA256AND192BITAES-CBC-BC","BC");
                    Key sKey= keyFact.generateSecret(pbeSpec);
                    Cipher cEnc = Cipher.getInstance("PBEWITHSHA256AND192BITAES-CBC-BC","BC");
                    cEnc.init(Cipher.ENCRYPT_MODE, sKey, new PBEParameterSpec(salt, iterationCount));


                    // PASSWORD BASED ENCRYPTION BODY
                    ArrayList<byte[]> PBE_body = new ArrayList<>();

                    //REQUEST
                    ByteArrayOutputStream byteArrayOutputStream = new ByteArrayOutputStream();
                    ObjectOutputStream objectOutputStream = new ObjectOutputStream(byteArrayOutputStream);
                    objectOutputStream.writeObject(params);
                    objectOutputStream.flush();
                    byte[] request = byteArrayOutputStream.toByteArray();
                    PBE_body.add(request);

                        // MY USER ID/USERNAME
                    byte[] usrid = username.getBytes();
                    PBE_body.add(usrid);

                        // NONCE 3 + 1 
                    byte[] nonce3_new = new BigInteger(nonces.get(2)).add(BigInteger.ONE).toByteArray();
                    PBE_body.add(nonce3_new);

                        // CREATE A NONCE 4 FOR SERVER
                    nonces.add(genNonce());
                    PBE_body.add(nonces.get(3));

                        // SEND MY UDP PORT
                    byte[] udpPortSend = Utils.toByteArray(String.valueOf(my_udp_port));
                    PBE_body.add(udpPortSend);

                        // CREATE MY BODY BYTE ARRAY
                    byte[] new_body = concenateByteArr(PBE_body);
                    

                    // FULL BODY
                    ArrayList<byte[]> arrBody = new ArrayList<>();

                
                    
                    byte[] PBE = cEnc.doFinal(new_body);
                    arrBody.add(PBE);

                    // Signature
                    signature.initSign(keyPair.getPrivate(), new SecureRandom());
                    signature.update(new_body);
                    byte[]  sigBytes = signature.sign();
                    arrBody.add(sigBytes);

                    // hash
                    hMac.init(hMacKey);
                    hMac.update(concenateByteArr(arrBody));
                    byte[] hash = hMac.doFinal();
                    arrBody.add(hash);

                    msg = concenateByteArr(arrBody);

                    type = 3;
                    break;

                case 4:
                    System.out.println("//-------------------------------------------- RECIEVE MESSAGE 4 ------------------------------------------------------//");
                    //-------------------------------------------- RECIEVE MESSAGE 4 ------------------------------------------------------//

                    ArrayList<byte[]> arrayBody = separateByteArr(inpacket.getMsg());
                    byte[] encryptedBody = arrayBody.get(0);
                    byte[] signedBody = arrayBody.get(1);
                    byte[] hashBody = arrayBody.get(2);

                    System.out.println(arrayBody.size());

                    cipher = Cipher.getInstance("ECIES", "BC");
                    cipher.init(Cipher.DECRYPT_MODE, keyPair.getPrivate());

                    byte[] decrypted = cipher.doFinal(encryptedBody);
                    ArrayList<byte[]> decBody = separateByteArr(decrypted);

                    // verify Nonce
                    byte[] inNonce4 = decBody.get(1);
                    byte[] myNonce4 = new BigInteger(nonces.get(3)).add(BigInteger.ONE).toByteArray();
                    if(!Arrays.equals(inNonce4, myNonce4)){
                        System.out.println("Nonce 4 + 1 is not correct");
                    }else{
                        System.out.println("correct Nonce");
                    }
                    System.out.println("Nonce 5:"+ Utils.toHex(decBody.get(2)));
                    nonces.add(decBody.get(2));

                    cryptoConfig = CryptoConfig.fromByteArray(decBody.get(3));
                    //cryptoConfig.writeConfigs("./Client/cryptoConfig.txt");
                   

                    // SIGNATURE
                    byte[] signedbody;
                    ArrayList<byte[]> body2ArrayList = new ArrayList<>();
                    body2ArrayList.add(decBody.get(0));
                    byte[] userId = username.getBytes();
                    body2ArrayList.add(userId);
                    body2ArrayList.add(decBody.get(1));
                    body2ArrayList.add(decBody.get(2));
                    body2ArrayList.add(decBody.get(3));
                    signedbody = concenateByteArr(body2ArrayList);
                    signature.initVerify(serverPublicKey);
                    signature.update(signedbody);
                    if (signature.verify(signedBody))
                    {
                        System.out.println("Assinatura ECDSA validada - reconhecida");
                    }
                    else
                    {
                        System.out.println("Assinatura nao reconhecida");
                        break;
                    }

                    hMac.update(decrypted, 0,decrypted.length);
                    byte[] newHash = hMac.doFinal();
                    if(!MessageDigest.isEqual(newHash, hashBody)){
                        System.out.println("Incorrect HASH");
                        //break;
                    }
                   
                    System.out.println("//-------------------------------------------- SEND MESSAGE 5 ---------------------------------------------------------//");
                    //-------------------------------------------- SEND MESSAGE 5 ---------------------------------------------------------//
                    ArrayList<byte[]> fullBodyArrayList = new ArrayList<>();


                    ArrayList<byte[]> encryptedBodyArrayList = new ArrayList<>();                    
                    byte[] part1 = "GO".getBytes();
                    byte[] part2 = new BigInteger(nonces.get(4)).add(BigInteger.ONE).toByteArray();;
                    encryptedBodyArrayList.add(part1);
                    encryptedBodyArrayList.add(part2);
                    byte[] fullbody = concenateByteArr(encryptedBodyArrayList);

         

                    cipher = Cipher.getInstance(cryptoConfig.getCiphersuite());
                    if (cryptoConfig.getIvSpec() != null) {
                        cipher.init(Cipher.ENCRYPT_MODE, cryptoConfig.getKey(), cryptoConfig.getIvSpec());
                    } else {
                        cipher.init(Cipher.ENCRYPT_MODE, cryptoConfig.getKey());
                    }
                    byte[] encrypted = cipher.doFinal(fullbody);
                    fullBodyArrayList.add(encrypted);

                    byte[] sendHash;
                    
                    if(cryptoConfig.getDigestType() == cryptoConfig.HASH ){
                        MessageDigest messageDigest = cryptoConfig.getHash();
                        sendHash = new byte[messageDigest.getDigestLength()];
                        messageDigest.update(fullbody); // UNCRYPTED BODY BECAUSE ITS A HASH AND NOT A HMAC
                        sendHash = messageDigest.digest();
                    }else{
                        hMac.init(cryptoConfig.getHMacKey());
                        sendHash = new byte[hMac.getMacLength()];
                        hMac.update(encrypted);
                        sendHash = hMac.doFinal();
                        System.out.println("HMAC: " + Utils.toHex(sendHash));
                    }
                    fullBodyArrayList.add(sendHash);
                    msg = concenateByteArr(fullBodyArrayList);
                    type = 5;
                    break;
                
                case 255:
                    finish = true;
                    System.out.println(new String(inpacket.getMsg()));
                    break;
            }
            if(finish){
                break;
            }
               
        }
        dataIn.close();
        dataOut.close();
        socket.close();
        return cryptoConfig;
        
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
        //System.out.println(bytesToHex(arr));
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