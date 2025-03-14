

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
import java.security.Security;
import java.security.Signature;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Base64;
import java.util.Properties;

import javax.crypto.Cipher;
import javax.crypto.KeyAgreement;
import javax.crypto.KeyGenerator;
import javax.crypto.Mac;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.DHParameterSpec;
import javax.crypto.spec.IvParameterSpec;
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



public class client_shp_phase1 {
    private static int ver = 0;
    private static int release = 0;
    private static byte[] delimiter = {0x00, 0x1E, 0x52, 0x00};
    private static final String  path = "./";

    public client_shp_phase1(){}

    public static CryptoConfig client(String inusername, String inpwd, int server_tcp_port, int my_udp_port,String serverIp, String[] params) throws Exception{
        Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());

        
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
        //--------------------------------------------------------------------- Diffie-hellman --------------------------------------------------------------//

        //--------------------------------------------------------------------- Diffie-hellman --------------------------------------------------------------//
        //generated using openssl dhparam -out dhparam.pem 2048
              BigInteger g2048 = new BigInteger("2");
              BigInteger p2048 = new BigInteger(
                      "8a90de47177b59cd0839c0a0b6428eaa5cdf0328c936e6962a016d5b56508fbe"
                    + "4230bb64f726bfeecabc4d55029d0ba31910e6e1cce92ba983b30d69685c904d"
                    + "4837fc8d91dad77a11933e57e6b44bdcf2871c46ba1d4084ae1203bb9a69083d"
                    + "47ed42cef9e4e6f7b048ebb8ec9c8f08e0501bee0088b610bb3ebc957e0af377"
                    + "938127a41fb85b3ddc9adad2ac92385556b233af58de0a462be60a349994821e"
                    + "9d6bf27cbbdabef66415bdfa9934509333271f36e435875bea27dbad674baa2b"
                    + "0d6aa32b66ce65afb4d629db63cf2c304f2beae4d43becbb07e530f9ebb4bf81"
                    + "512badab3a7ca87119758c589a4fe6c9ec0ea79127b687bd682eb8d31e5592e7", 16);
      
            /*
                    Diffie Hellman Agreement
                • Private and public numbers generated by the Client and the Server must have 2048 bits
                • Use pre-defined / Pres-shared primitive root and prime number in Client and Server Setup, for the Diffie Hellman Agreement
                • After Message-Type 4, Client and Server must establish a secret Ks, from which all keys (symmetric keys or HMAC keys) must be derived
           
         */

        DHParameterSpec dhParams = new DHParameterSpec(p2048, g2048);
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("DH", "BC");
        // DH Pair Generator
        keyGen.initialize(dhParams);

        MessageDigest	DHhash = MessageDigest.getInstance("SHA256", "BC");	
        // A: Alice
        KeyAgreement DHKeyAgree = KeyAgreement.getInstance("DH", "BC");
        KeyPair      DHPair = keyGen.generateKeyPair();
        DHKeyAgree.init(DHPair.getPrivate());
        byte[] DHSharedKey = null;
        

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
            SHPPacket inpacket = recievePacket(dataIn);
            switch(inpacket.getMsgType()){
                case 2:
                System.out.println("//-------------------------------------------- RECIEVE MESSAGE 2 ------------------------------------------------------//");


                    byte[] body = inpacket.getMsg();
                    for (int i = 0; i < 3; i++) {
                        byte[] nonce = new byte[16];
                        System.arraycopy(body, i * 16, nonce, 0, 16);
                        nonces.add(nonce);
                    }
                    salt = nonces.get(0);
                    iterationCount = nonces.get(1)[1] & 0xFF;


                    System.out.println("//-------------------------------------------- SEND MESSAGE 3 ---------------------------------------------------------//");


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
                    
                    

                    // FULL BODY
                    ArrayList<byte[]> arrBody = new ArrayList<>();

                
                    byte[] new_body = concenateByteArr(PBE_body);
                    byte[] PBE = cEnc.doFinal(new_body);
                    arrBody.add(PBE);


                    // Signature

                    byte[] publicKeyBytesDH = DHPair.getPublic().getEncoded();
                    arrBody.add(publicKeyBytesDH);

                    // ADING TO THE PBE_BODY FOR THE SIGNATURE
                    PBE_body.add(publicKeyBytesDH);

                    

                    signature.initSign(keyPair.getPrivate(), new SecureRandom());
                    signature.update(concenateByteArr(PBE_body));
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

                    ArrayList<byte[]> arrayBody = separateByteArr(inpacket.getMsg());
                    byte[] encryptedBody = arrayBody.get(0);
                    byte[] dhServerpub = arrayBody.get(1);
                    byte[] signedBody = arrayBody.get(2);
                    byte[] hashBody = arrayBody.get(3);

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
                    
                    PublicKey publicKey_fromByte = KeyFactory.getInstance("DH", "BC").generatePublic(new X509EncodedKeySpec(dhServerpub));                     
                    DHKeyAgree.doPhase(publicKey_fromByte, true);
                    DHSharedKey = DHhash.digest(DHKeyAgree.generateSecret());
                    System.out.println("I generated :" + Utils.toHex(DHSharedKey));
                    
          



                    // SIGNATURE
                    byte[] signedbody;
                    ArrayList<byte[]> body2ArrayList = new ArrayList<>();
                    body2ArrayList.add(decBody.get(0));
                    byte[] userId = username.getBytes();
                    body2ArrayList.add(userId);
                    body2ArrayList.add(decBody.get(1));
                    body2ArrayList.add(decBody.get(2));
                    body2ArrayList.add(decBody.get(3));
                    body2ArrayList.add(dhServerpub);
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
                        break;
                    }

                    type = 4;
                    break;
                case 255:
                    finish = true;
                    System.out.println("ERROR: "+new String(inpacket.getMsg()));
                    break;
            }
            if(type == 4){
                break;
            }

            if(finish){
                break;
            }
               
        }
        //! IN HERE READ CRYPTOCONFIG AND GENERATE THE NECESSARY KEYS
        // HMAC KEY
        // CRYPTOGRAPHIC KEY

        cipher = Cipher.getInstance(cryptoConfig.getCiphersuite());
        MessageDigest digest = MessageDigest.getInstance("SHA-256");
        byte[] hashedKey = digest.digest(DHSharedKey);

        if (cryptoConfig.getCiphersuite().contains("CBC") || cryptoConfig.getCiphersuite().contains("CFB") || cryptoConfig.getCiphersuite().contains("OFB") || cryptoConfig.getCiphersuite().contains("CTR")) {
            // Generate a random IV
            System.out.println("NEEDS IV");
            
        
            // Truncate or pad the hashed key to match the block size
            byte[] iv = new byte[cipher.getBlockSize()];
            System.arraycopy(hashedKey, 0, iv, 0, Math.min(hashedKey.length, iv.length));
            IvParameterSpec ivSpec = new IvParameterSpec(iv);
            System.out.println("Deterministic IV: " + Utils.toHex(iv));
            System.out.println("IV size: " + iv.length);
            cryptoConfig.setIvSpec(Utils.toHex(iv));
        }
        

        int keySizeInbits = Integer.parseInt(cryptoConfig.getSymetricKeySize_str());

        byte[] key = new byte[keySizeInbits / 8];

        int offset = 0;
        while (offset < key.length) {
            hashedKey = digest.digest(hashedKey);
            
            int remaining = key.length - offset;
            int lengthToCopy = Math.min(remaining, hashedKey.length);
            System.arraycopy(hashedKey, 0, key, offset, lengthToCopy);
            offset += lengthToCopy;
        }
        cryptoConfig.setKey(Utils.toHex(key));
        SecretKey SymKey = new SecretKeySpec(key, cipher.getAlgorithm());
        System.out.println("Deterministic Key: " + Utils.toHex(SymKey.getEncoded()));
        System.out.println("Algorithm: " + cipher.getAlgorithm());
        
        if(cryptoConfig.getDigestType() != cryptoConfig.HASH){
            hashedKey = digest.digest(DHSharedKey);
            Key hmacKey = new SecretKeySpec(hashedKey, "HMacSHA256");
            System.out.println("HMAC Key: " + Utils.toHex(hmacKey.getEncoded()));
            cryptoConfig.setHMacKey(Utils.toHex(hashedKey));
        }


        cryptoConfig.updateConfig();


        dataIn.close();
        dataOut.close();
        socket.close();
        return cryptoConfig;
        
    }
    private static void sendPacket(DataOutputStream out,SHPPacket packet) throws IOException{
        byte[] outpacket = packet.toByteArray();
        out.writeInt(outpacket.length);
        out.write(outpacket);
    }

    private static SHPPacket recievePacket(DataInputStream in) throws IOException{

        byte[] inpacket = new byte[in.readInt()];
        in.read(inpacket);
        SHPPacket packet = SHPPacket.fromByteArray(inpacket);
        System.out.println(packet.toString());
        return packet;
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