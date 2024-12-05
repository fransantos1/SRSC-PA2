import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Base64;
import java.util.Properties;

import javax.crypto.Mac;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

import java.io.*;

public class CryptoConfig implements Serializable {
    private static final long serialVersionUID = 1L;

    public final int HASH = 0;
    public final int HMAC = 1;


    private String ciphersuite_str ;
    private String symetricKey_str;
    private String IV_str;
    private String Integrity_str;
    private String Hash_algorithm_str;
    private String MAC_algorithm_str;
    private String MacKey_str;




    private int              digestType;
    private String           ciphersuite = null;
    private SecretKey        key = null;
    private IvParameterSpec  ivSpec = null;
    private MessageDigest    hash = null;
    private Mac              hMac = null;
    private SecretKey        hMacKey = null;
    

    // Constructors
    public CryptoConfig(String path) {
        Properties prop = new Properties();
        try (FileInputStream fis = new FileInputStream(path)) {
            System.out.println("Read Properties");
            prop.load(fis);
        } catch (FileNotFoundException ex) {
            System.out.println(ex);
        } catch (IOException ex) {
            System.out.println(ex);
        }


        this.ciphersuite_str = prop.getProperty("CONFIDENTIALIY");
        this.symetricKey_str = prop.getProperty("SYMMETRIC_KEY");
        this.IV_str = prop.getProperty("IV");
        this.Integrity_str = prop.getProperty("INTEGRITY");
        this.Hash_algorithm_str = prop.getProperty("H");
        this.MAC_algorithm_str = prop.getProperty("MAC");
        this.MacKey_str = prop.getProperty("MACKEY");


        this.ciphersuite = prop.getProperty("CONFIDENTIALIY");

        byte[] keybytes = new byte[prop.getProperty("SYMMETRIC_KEY").length() / 2];

        for (int i = 0; i < keybytes.length; i++) {
            int index = i * 2;
            int j = Integer.parseInt(prop.getProperty("SYMMETRIC_KEY").substring(index, index + 2), 16);
            keybytes[i] = (byte) j;
        }
        this.key = new SecretKeySpec(keybytes, prop.getProperty("SYMMETRIC_KEY").split("/")[0]);

        if(!prop.getProperty("IV").equals("NULL")){
            byte[] ivBytes = new byte[prop.getProperty("IV").length()/2];

            for (int i = 0; i < ivBytes.length; i++) {
                int index = i * 2;
                int j = Integer.parseInt(prop.getProperty("IV").substring(index, index + 2), 16);
                ivBytes[i] = (byte) j;
            }
            this.ivSpec = new IvParameterSpec(ivBytes);                 
        }
        
        try {
            if(prop.getProperty("INTEGRITY").equals("H")){
                digestType = HASH;
                hash = MessageDigest.getInstance(prop.getProperty("H"));
            }else{
                digestType = HMAC;
                hMac = Mac.getInstance(prop.getProperty("MAC"));
                byte[] macKeyBytes = Base64.getDecoder().decode(prop.getProperty("MACKEY"));
                hMacKey = new SecretKeySpec(macKeyBytes, prop.getProperty("MAC"));
            }
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        }
    }

    public CryptoConfig(String ciphersuite, String symetricKey, String IV, String Integrity, String Hash_algorithm, String MAC_algorithm, String MacKey) {

        this.ciphersuite_str = ciphersuite;
        this.symetricKey_str = symetricKey;
        this.IV_str = IV;
        this.Integrity_str = Integrity;
        this.Hash_algorithm_str = Hash_algorithm;
        this.MAC_algorithm_str = MAC_algorithm;
        this.MacKey_str = MacKey;

        this.ciphersuite = ciphersuite;

        byte[] keybytes = new byte[symetricKey.length() / 2];

        for (int i = 0; i < keybytes.length; i++) {
            int index = i * 2;
            int j = Integer.parseInt(symetricKey.substring(index, index + 2), 16);
            keybytes[i] = (byte) j;
        }
        this.key = new SecretKeySpec(keybytes, symetricKey.split("/")[0]);

        if(!IV.equals("NULL")){
            byte[] ivBytes = new byte[IV.length()/2];

            for (int i = 0; i < ivBytes.length; i++) {
                int index = i * 2;
                int j = Integer.parseInt(IV.substring(index, index + 2), 16);
                ivBytes[i] = (byte) j;
            }
            this.ivSpec = new IvParameterSpec(ivBytes);                 
        }
        
        try {
            if(Integrity.equals("H")){
                digestType = HASH;
                hash = MessageDigest.getInstance(Hash_algorithm);
            }else{
                digestType = HMAC;
                hMac = Mac.getInstance(MAC_algorithm);
                byte[] macKeyBytes = Base64.getDecoder().decode(MacKey);
                hMacKey = new SecretKeySpec(macKeyBytes, MAC_algorithm);
            }
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        }

    }
    
 
    public String getCiphersuite() {
        return ciphersuite;
    }

    public IvParameterSpec getIvSpec() {
        return ivSpec;
    }

    public SecretKey getKey() {
        return key;
    }

    public MessageDigest getHash() {
        return hash;
    }

    public Mac getHMac() {
        return hMac;
    }

    public SecretKey getHMacKey() {
        return hMacKey;
    }
    public int getDigestType(){
        return digestType;
    }
    // Convert the object to a byte array
    public byte[] toByteArray() {
        try {
            // Collect all String fields into a Properties object for easy serialization
            Properties props = new Properties();
            props.setProperty("CONFIDENTIALIY", ciphersuite_str);
            props.setProperty("SYMMETRIC_KEY", symetricKey_str);
            props.setProperty("IV", IV_str);
            props.setProperty("INTEGRITY", Integrity_str);
            props.setProperty("H", Hash_algorithm_str);
            props.setProperty("MAC", MAC_algorithm_str);
            props.setProperty("MACKEY", MacKey_str);
    
            // Serialize the Properties object to a byte array
            ByteArrayOutputStream bos = new ByteArrayOutputStream();
            props.store(bos, null);
            return bos.toByteArray();
        } catch (IOException e) {
            e.printStackTrace();
            return null;
        }
    }

// Create an object from a byte array
public static CryptoConfig fromByteArray(byte[] bytes) {
    try {
        // Load the byte array into a Properties object
        ByteArrayInputStream bis = new ByteArrayInputStream(bytes);
        Properties props = new Properties();
        props.load(bis);

        // Use the String values from Properties to reconstruct the cryptoConfig object
        return new CryptoConfig(
            props.getProperty("CONFIDENTIALIY"),
            props.getProperty("SYMMETRIC_KEY"),
            props.getProperty("IV"),
            props.getProperty("INTEGRITY"),
            props.getProperty("H"),
            props.getProperty("MAC"),
            props.getProperty("MACKEY")
        );
    } catch (IOException e) {
        e.printStackTrace();
        return null;
    }
}



}