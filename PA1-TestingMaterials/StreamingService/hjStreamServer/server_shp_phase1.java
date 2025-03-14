
import java.net.*;
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
import java.security.spec.ECGenParameterSpec;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Base64;
import java.util.Properties;

import javax.crypto.Cipher;
import javax.crypto.KeyAgreement;
import javax.crypto.Mac;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.interfaces.DHPrivateKey;
import javax.crypto.interfaces.DHPublicKey;
import javax.crypto.spec.DHParameterSpec;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.PBEParameterSpec;
import javax.crypto.spec.SecretKeySpec;

import DataBase.*;

import java.io.ByteArrayInputStream;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.io.ObjectInputStream;
import java.math.BigInteger;
import java.io.FileInputStream;



public class server_shp_phase1 {
    private static final String  path = "./";


    private static int ver = 0;
    private static int release = 0;
    private static byte[] delimiter = {0x00, 0x1E, 0x52, 0x00};
    public server_shp_phase1(){}

    public static String[] server(int tcp_port) throws Exception{
        Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());


        Properties properties = new Properties();
        FileInputStream fis = new FileInputStream(path+"ServerECCKeyPair.sec");
        properties.load(fis);
        fis.close();


        // LOADING CRYPTO CONFIG

        CryptoConfig cryptoConfig = new CryptoConfig(path+"ciphersuite.conf");
        System.out.println(cryptoConfig.getCiphersuite());
        System.out.println(cryptoConfig.getDigestType());

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
        KeyAgreement DHKeyAgree = KeyAgreement.getInstance("DH", "BC");
        KeyPair      DHPair = keyGen.generateKeyPair();
        DHKeyAgree.init(DHPair.getPrivate());       
        byte[] DHSharedKey = null; 



        Mac hMac = Mac.getInstance("HMacSHA256");
        Key hMacKey = null;


        Cipher cipher;

        SecureRandom secrandom = new SecureRandom();
        dataBaseManager DB = new dataBaseManager(path);

        ServerSocket serverSocket = new ServerSocket(tcp_port);
        System.out.println("Listening for clients...");
        Socket clientSocket = serverSocket.accept();
        String clientSocketIP = clientSocket.getInetAddress().getHostAddress();
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
        String[] request = null;

        int iterationCount = 0; 

        while(true){
            SHPPacket inpacket = recievePacket(dataIn);
            switch(inpacket.getMsgType()){
                case 1:
                    System.out.println("//-------------------------------------------- RECIEVE MESSAGE 1 ----------------------------------------------------------//");
                    String userID = new String(inpacket.getMsg());
                    System.out.println("Recieved usrID: "+ userID);
                    System.out.println("Getting full account");
                    user = DB.getUser(userID);
                    if(user == null){
                        msg = "User not found".getBytes();
                        isErr = true;
                        break;
                    }
                    String base64String = user.getKpubClient().replaceAll("\s", "");
                    byte[] client_keybytes = Base64.getDecoder().decode(base64String);
                    X509EncodedKeySpec client_keySPEC = new X509EncodedKeySpec(client_keybytes);
                    clientPubKey = keyFactory.generatePublic(client_keySPEC);
                    byte[] pwd_byteArr = hexStringToByteArray(user.getPwd());
                    
                    hMacKey = new SecretKeySpec(pwd_byteArr, "HMacSHA256");
                    hMac.init(hMacKey);

                    System.out.println("//-------------------------------------------- SEND MESSAGE 2 -------------------------------------------------------------//");
                    msg = new byte[16*3];
                    for(int i = 0; i < 3; i++){
                        byte[] nonce = new byte[16];
                        secrandom.nextBytes(nonce);
                        System.arraycopy(nonce, 0 , msg, nonce.length*i , nonce.length);
                        nonces.add(nonce);
                    }
                    iterationCount = nonces.get(1)[1] & 0xFF;

                    user = new User(user.getId(), user.getPwd(), Utils.toHex(nonces.get(0)), user.getKpubClient());
                    DB.updateUser(user);


                    type = 2;
                    break;
                case 3:

                    System.out.println("//-------------------------------------------- RECIEVE MESSAGE 3 ----------------------------------------------------------//");
                    
                    ArrayList<byte[]> bodyArr = separateByteArr(inpacket.getMsg());
                    byte[] hash = bodyArr.get(3);
                    System.out.println("Number of parts in bodyARR: " + bodyArr.size());
                    bodyArr.remove(3);
                    hMac.update(concenateByteArr(bodyArr), 0, concenateByteArr(bodyArr).length);
                    byte[] newHash = hMac.doFinal();
                    if(!MessageDigest.isEqual(newHash, hash)){
                        msg = "Incorrect Hash".getBytes();
                        isErr = true;
                        break;
                    }
                
                    byte[] PBE = bodyArr.get(0);

                    char[] password = user.getPwd().toCharArray();
                    byte[] salt = hexStringToByteArray(user.getSalt());
                    PBEKeySpec pbeSpec = new PBEKeySpec(password);
                    SecretKeyFactory keyFact = SecretKeyFactory.getInstance("PBEWITHSHA256AND192BITAES-CBC-BC","BC");
                    Key sKey= keyFact.generateSecret(pbeSpec);
                    Cipher cDec = Cipher.getInstance("PBEWITHSHA256AND192BITAES-CBC-BC","BC");
                    

                    cDec.init(Cipher.DECRYPT_MODE, sKey, new PBEParameterSpec(salt, iterationCount));
                    byte[] inBytes = null;

                    try{
                        inBytes = cDec.doFinal(PBE);
                    }catch(Exception e){
                        msg = "Wrong Password".getBytes();
                        isErr = true;
                        break;  
                    }
      


                    ArrayList<byte[]> inPBEArrayList = separateByteArr(inBytes);
                    inPBEArrayList.add(bodyArr.get(1));
                    ByteArrayInputStream byteArrayInputStream = new ByteArrayInputStream(inPBEArrayList.get(0));
                    ObjectInputStream objectInputStream = new ObjectInputStream(byteArrayInputStream);
                    request=(String[]) objectInputStream.readObject();
                    objectInputStream.close();
                    byteArrayInputStream.close();
                    String[] newRequest = new String[request.length + 2];
                    newRequest[0] = clientSocketIP;
                    newRequest[1] = Utils.toString(inPBEArrayList.get(4));
                    System.arraycopy(request, 0, newRequest, 2, request.length);
                    request = newRequest;

                    //Validate UserId
                    String userid = new String(inPBEArrayList.get(1));
                    if(!userid.equals(user.getId())){
                        msg = "Not the same user".getBytes();
                        isErr = true;
                        break;
                    }

                    byte[] challengeNonce3 = inPBEArrayList.get(2);
                    byte[] correct_challengeNonce3 = new BigInteger(nonces.get(2)).add(BigInteger.ONE).toByteArray();
                    if(!Arrays.equals(challengeNonce3, correct_challengeNonce3)){
                        msg = "Nonce 3 challenge failed".getBytes();
                        isErr = true;
                        break;
                    }    

                    // new nonce
                    byte[] nonce4 = inPBEArrayList.get(3);
                    nonces.add(nonce4);
                   
                    byte[] sig = bodyArr.get(2);


                    signature.initVerify(clientPubKey);
                    signature.update(concenateByteArr(inPBEArrayList));
                    if (!signature.verify(sig)){
                        msg = "Signature not recognized".getBytes();
                        isErr = true;
                        break;
                    }

                    PublicKey publicKey_fromByte = KeyFactory.getInstance("DH", "BC").generatePublic(new X509EncodedKeySpec(bodyArr.get(1)));                     
                    DHKeyAgree.doPhase(publicKey_fromByte, true);
                    DHSharedKey = DHhash.digest(DHKeyAgree.generateSecret());

                    System.out.println("I generated\n" + Utils.toHex(DHSharedKey));

                    
                    System.out.println("//-------------------------------------------- SEND MESSAGE 4 -------------------------------------------------------------//");
                    ArrayList<byte[]> fullBodyArray = new ArrayList<>();


                    //------------------ ENCRYPTED MESSAGE ------------------//
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

                    //------------------ DH PUBLIC KEY ------------------//
                    byte[] publicKeyBytesDH = DHPair.getPublic().getEncoded();
                    fullBodyArray.add(publicKeyBytesDH);

                    //------------------ SIGNATURE ------------------//
                    
                    byte[] body2;
                    ArrayList<byte[]> body2ArrayList = new ArrayList<>();
                    body2ArrayList.add(request_confirmation);
                    byte[] userId = user.getId().getBytes();
                    body2ArrayList.add(userId);
                    body2ArrayList.add(nonce4_1);
                    body2ArrayList.add(nonce5);
                    body2ArrayList.add(cryptoConfByteArr);
                    body2ArrayList.add(publicKeyBytesDH);
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

            }

            if(msg == null)
                break;
            if(isErr){
                System.out.println("Error: " + new String(msg));
                type = -1;
            }
            SHPPacket outpacket = new SHPPacket(ver, release, type, msg);
            sendPacket(dataOut, outpacket);
            if(type == 4)
                break;
            if(isErr)
                break;

        }
        //GOT TO GIVE A DELAY FOR THE CLIENT TO START RECIEVING 

        //! IN HERE READ CRYPTOCONFIG AND GENERATE THE NECESSARY KEYS
        // IV
        // HMAC KEY
        // CRYPTOGRAPHIC KEY
        cipher = Cipher.getInstance(cryptoConfig.getCiphersuite());
        MessageDigest digest = MessageDigest.getInstance("SHA-256");
        byte[] hashedKey = digest.digest(DHSharedKey);
        System.out.println(cryptoConfig.getIVSize_str());
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



        cryptoConfig.SaveFile(path+"ciphersuite.conf");
        dataIn.close();
        dataOut.close();
        serverSocket.close();
        clientSocket.close();
        return request;
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