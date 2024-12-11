
import java.net.*;
import java.security.Key;
import java.security.KeyFactory;
import java.security.KeyPair;
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
import javax.crypto.Mac;
import javax.crypto.SecretKeyFactory;
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

        while(true){
            SHPPacket inpacket = recievePacket(dataIn);
            switch(inpacket.getMsgType()){
                case 1:
                    System.out.println("//-------------------------------------------- RECIEVE MESSAGE 1 ----------------------------------------------------------//");
                    String userID = new String(inpacket.getMsg());
                    System.out.println("Recieved usrID: "+ userID);
                    System.out.println("Getting full account");
                    user = DB.getUser(userID);
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
                    type = 2;
                    break;
                case 3:
                    System.out.println("//-------------------------------------------- RECIEVE MESSAGE 3 ----------------------------------------------------------//");
                    //-------------------------------------------- RECIEVE MESSAGE 3 ----------------------------------------------------------//
                    
                    ArrayList<byte[]> bodyArr = separateByteArr(inpacket.getMsg());
                    byte[] hash = bodyArr.get(2);
                    bodyArr.remove(2);
                    hMac.update(concenateByteArr(bodyArr), 0, concenateByteArr(bodyArr).length);
                    byte[] newHash = hMac.doFinal();
                    System.out.println("New hash: " +Utils.toHex(newHash));
                    System.out.println("Old hash: " +Utils.toHex(hash));
                    if(!MessageDigest.isEqual(newHash, hash)){
                        msg = "Incorrect Hash".getBytes();
                        isErr = true;
                        break;
                    }
                
                    byte[] PBE = bodyArr.get(0);

                    //updating the salt
                    user = new User(user.getId(), user.getPwd(), Utils.toHex(nonces.get(0)), user.getKpubClient());
                    DB.updateUser(user);

                    char[] password = user.getPwd().toCharArray();
                    byte[] salt = hexStringToByteArray(user.getSalt());
                    PBEKeySpec pbeSpec = new PBEKeySpec(password);
                    SecretKeyFactory keyFact = SecretKeyFactory.getInstance("PBEWITHSHA256AND192BITAES-CBC-BC","BC");
                    Key sKey= keyFact.generateSecret(pbeSpec);
                    Cipher cDec = Cipher.getInstance("PBEWITHSHA256AND192BITAES-CBC-BC","BC");
                    int iteration = nonces.get(1)[1] & 0xFF;

                    cDec.init(Cipher.DECRYPT_MODE, sKey, new PBEParameterSpec(salt, iteration));
                    byte[] inBytes = null;

                    try{
                        inBytes = cDec.doFinal(PBE);
                    }catch(Exception e){
                        msg = "Wrong Password".getBytes();
                        isErr = true;
                        break;  
                    }
      


                    ArrayList<byte[]> inPBEArrayList = separateByteArr(inBytes);

           

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

                    byte[] sig = bodyArr.get(1);

                    signature.initVerify(clientPubKey);
                    signature.update(inBytes);
                    if (!signature.verify(sig)){
                        msg = "Signature not recognized".getBytes();
                        isErr = true;
                        break;
                    }
                    
                    System.out.println("//-------------------------------------------- SEND MESSAGE 4 -------------------------------------------------------------//");

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
                    System.out.println("//-------------------------------------------- RECIEVED MESSAGE 5 ----------------------------------------------------------//");
                    ArrayList<byte[]> bodyArr5 = separateByteArr(inpacket.getMsg());
                    byte[] encrypted = bodyArr5.get(0);
                    byte[] inhash = bodyArr5.get(1);

                    if(cryptoConfig.getDigestType() == cryptoConfig.HMAC){
                        hMac.init(cryptoConfig.getHMacKey());
                        newHash = new byte[hMac.getMacLength()];
                        hMac.update(encrypted);
                        newHash = hMac.doFinal();
                        if(!MessageDigest.isEqual(newHash, inhash)){
                            msg = "Incorrect HMAC".getBytes();
                            isErr = true;
                            break;
                        }
                    }

                    cipher = Cipher.getInstance(cryptoConfig.getCiphersuite());
                    if (cryptoConfig.getIvSpec() != null) {
                        cipher.init(Cipher.DECRYPT_MODE, cryptoConfig.getKey(), cryptoConfig.getIvSpec());
                    } else {
                        cipher.init(Cipher.DECRYPT_MODE, cryptoConfig.getKey());
                    }


                    byte[] extratedBody =new byte[cipher.getOutputSize(encrypted.length)];


                    int ptLen = cipher.update(encrypted,0, encrypted.length, extratedBody,0);
                    cipher.doFinal(extratedBody, ptLen);

                    ArrayList<byte[]> decryptedBody = separateByteArr(extratedBody);

                    if(!Arrays.equals(decryptedBody.get(1),  new BigInteger(nonces.get(4)).add(BigInteger.ONE).toByteArray())){
                        msg = "Nonce 5 is not correct".getBytes();
                        isErr = true;
                        break;
                    }

                    if(cryptoConfig.getDigestType() == cryptoConfig.HASH ){
                        MessageDigest messageDigest = cryptoConfig.getHash();
                        newHash = new byte[messageDigest.getDigestLength()];
                        messageDigest.update(extratedBody); // UNCRYPTED BODY BECAUSE ITS A HASH AND NOT A HMAC
                        newHash = messageDigest.digest();
                        if(!MessageDigest.isEqual(newHash, inhash)){
                            msg = "Incorrect HASH".getBytes();
                            isErr = true;
                            break;
                        }
                    }
                    type = 5;
                    break;
            }
            if(type == 5)
                break;
            if(msg == null)
                break;
            if(isErr){
                System.out.println("Error: " + new String(msg));
                type = -1;
            }
            SHPPacket outpacket = new SHPPacket(ver, release, type, msg);
            sendPacket(dataOut, outpacket);
            if(isErr)
                break;

        }
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