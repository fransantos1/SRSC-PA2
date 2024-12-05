
import java.net.*;
import java.nio.ByteBuffer;
import java.security.Key;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.MessageDigest;
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
import java.util.Arrays;
import java.util.Base64;
import java.util.List;
import java.util.Properties;

import javax.crypto.Cipher;
import javax.crypto.Mac;
import javax.crypto.SecretKeyFactory;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.PBEParameterSpec;
import javax.crypto.spec.SecretKeySpec;

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

    //! change nonce 
    //! nonces cant be repeated so change the

    public void client() throws Exception{
        User client = new User("alice@gmail.com", "24c1f255e20fbe37e8a7f7090c8d1c2923c39e2a9bc21146f876e174cb6d41ec", "4f1b78329c106679a3dbec3cd9d97b0b", null);


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

        byte[] pwd_byteArr = Base64.getDecoder().decode(client.getPwd());
        Mac hMac = Mac.getInstance("HMacSHA256");
        Key hMacKey = new SecretKeySpec(pwd_byteArr, "HMacSHA256");


        Cipher cipher;


        CryptoConfig cryptoConfig;


        //! GENERATE iterationCount with NONCE 1 or 2
	   
        int iterationCount = 2048; 


        int udp_port = 5001;

        Socket socket = new Socket();
        socket.connect(new InetSocketAddress("127.0.0.1", udp_port), 1000);
        System.out.println("Connection Successful!");
        DataInputStream dataIn = new DataInputStream(socket.getInputStream());
        DataOutputStream dataOut = new DataOutputStream(socket.getOutputStream());


        //-------------------------------------------- SEND MESSAGE 1 ---------------------------------------------------------//
        int type = 1;
        byte[] msg = client.getId().getBytes();
        ArrayList<byte[]> nonces = new ArrayList<>();

        
        while(true){
            


            System.out.println("Sending Message: "+ Utils.toHex(msg));
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
                    for (int i = 0; i < 3; i++) {
                        byte[] nonce = new byte[16];
                        System.arraycopy(body, i * 16, nonce, 0, 16);
                        nonces.add(nonce);
                    }

                    //-------------------------------------------- SEND MESSAGE 3 ---------------------------------------------------------//
                    
                    
                    ArrayList<byte[]> PBE_body = new ArrayList<>();
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
                    nonces.add(nonce4);
                    PBE_body.add(nonce4);
                    //udpPort
                    byte[] udpPortSend = Utils.toByteArray(String.valueOf(udp_port));
                    PBE_body.add(udpPortSend);
                    byte[] new_body = concenateByteArr(PBE_body);

                    char[] password = client.getPwd().toCharArray();
                    byte[] salt = hexStringToByteArray(client.getSalt());
 
                    ArrayList<byte[]> arrBody = new ArrayList<>();

                    // Encryption 
                    PBEKeySpec pbeSpec = new PBEKeySpec(password);
                    SecretKeyFactory keyFact = SecretKeyFactory.getInstance("PBEWITHSHA256AND192BITAES-CBC-BC","BC");
                    Key sKey= keyFact.generateSecret(pbeSpec);
                    Cipher cEnc = Cipher.getInstance("PBEWITHSHA256AND192BITAES-CBC-BC","BC");
                    cEnc.init(Cipher.ENCRYPT_MODE, sKey, new PBEParameterSpec(salt, iterationCount));
                
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

                   

                    // SIGNATURE
                    byte[] signedbody;
                    ArrayList<byte[]> body2ArrayList = new ArrayList<>();
                    body2ArrayList.add(decBody.get(0));
                    byte[] userId = client.getId().getBytes();
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
                   

                    //-------------------------------------------- SEND MESSAGE 5 ---------------------------------------------------------//
                    ArrayList<byte[]> fullBodyArrayList = new ArrayList<>();


                    ArrayList<byte[]> encryptedBodyArrayList = new ArrayList<>();                    
                    byte[] part1 = "GO".getBytes();
                    byte[] part2 = new BigInteger(nonces.get(4)).add(BigInteger.ONE).toByteArray();;
                    encryptedBodyArrayList.add(part1);
                    encryptedBodyArrayList.add(part2);
                    byte[] fullbody = concenateByteArr(encryptedBodyArrayList);

                    System.out.println("-----------------------------------------------------------------------");
                    System.out.println("Full Body: " + Utils.toHex(fullbody));
                    System.out.println("Full Body Length: " + fullbody.length);
                    System.out.println("-----------------------------------------------------------------------");

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