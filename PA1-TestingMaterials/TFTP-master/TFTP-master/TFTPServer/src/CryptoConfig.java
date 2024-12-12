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


    private String ciphersuite_str = null ;//CONFIDENTIALIY=AES/CTR/NoPadding
    private String symetricKey_str = null;//SYMMETRIC_KEY=00112233445566778899AABBCCDDEEFF00112233445566778899AABBCCDDEEFF
    private String symetricKeySize_str = null;//SYMMTRIC_KEY_SIZE=256
    private String IV_str = null;//IV=00010203040506070809101112131415
    private String IVSize_str = null;//IV_SIZE=16
    private String Integrity_str = null;//INTEGRITY=H
    private String Hash_algorithm_str = null;//H=SHA256
    private String MAC_algorithm_str = null;//MAC=HMACSHA3-512
    private String MacKey_str = null;//MACKEY=a0c4f12e70e4efba9c7c8de8c31533f3e14ed1c4b2c1fffd5d9e775f5a0d3031
    private String MacKeySize_str = null;//MACKEY_SIZE=256





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
        this.symetricKeySize_str = prop.getProperty("SYMMTRIC_KEY_SIZE");
        this.IV_str = prop.getProperty("IV");
        this.IVSize_str = prop.getProperty("IV_SIZE");
        this.Integrity_str = prop.getProperty("INTEGRITY");
        this.Hash_algorithm_str = prop.getProperty("H");
        this.MAC_algorithm_str = prop.getProperty("MAC");
        this.MacKey_str = prop.getProperty("MACKEY");
        this.MacKeySize_str = prop.getProperty("MACKEY_SIZE");
        
        this.ciphersuite = prop.getProperty("CONFIDENTIALIY");

        byte[] keybytes = new byte[prop.getProperty("SYMMETRIC_KEY").length() / 2];

        for (int i = 0; i < keybytes.length; i++) {
            int index = i * 2;
            int j = Integer.parseInt(prop.getProperty("SYMMETRIC_KEY").substring(index, index + 2), 16);
            keybytes[i] = (byte) j;
        }
        System.out.println(prop.getProperty("SYMMETRIC_KEY"));
        if(!prop.getProperty("SYMMETRIC_KEY").isEmpty())
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
                if(macKeyBytes.length != 0)
                    hMacKey = new SecretKeySpec(macKeyBytes, prop.getProperty("MAC"));
            }
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        }
    }

    public CryptoConfig(String ciphersuite, String symetricKey, String symetricKeySize, String IV,String IVSize, String Integrity, String Hash_algorithm, String MAC_algorithm, String MacKey, String MacKeySize) {

        this.ciphersuite_str = ciphersuite;
        this.symetricKey_str = symetricKey;
        this.symetricKeySize_str = symetricKeySize;
        this.IV_str = IV;
        this.IVSize_str = IVSize;
        this.Integrity_str = Integrity;
        this.Hash_algorithm_str = Hash_algorithm;
        this.MAC_algorithm_str = MAC_algorithm;
        this.MacKey_str = MacKey;
        this.MacKeySize_str = MacKeySize;

        this.ciphersuite = ciphersuite;

        byte[] keybytes = new byte[symetricKey.length() / 2];

        for (int i = 0; i < keybytes.length; i++) {
            int index = i * 2;
            int j = Integer.parseInt(symetricKey.substring(index, index + 2), 16);
            keybytes[i] = (byte) j;
        }

        if(!symetricKey.isEmpty())
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
                if(macKeyBytes.length != 0)
                    hMacKey = new SecretKeySpec(macKeyBytes, MAC_algorithm);
            }
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        }

    }

    public void updateConfig(){
            CryptoConfig updatedConfig = new CryptoConfig(
        this.ciphersuite_str,
        this.symetricKey_str,
        this.symetricKeySize_str,
        this.IV_str,
        this.IVSize_str,
        this.Integrity_str,
        this.Hash_algorithm_str,
        this.MAC_algorithm_str,
        this.MacKey_str,
        this.MacKeySize_str
    );

    // Update the current instance with the new configuration
    this.ciphersuite = updatedConfig.getCiphersuite();
    this.ivSpec = updatedConfig.getIvSpec();
    this.key = updatedConfig.getKey();
    this.hash = updatedConfig.getHash();
    this.hMac = updatedConfig.getHMac();
    this.hMacKey = updatedConfig.getHMacKey();
    this.digestType = updatedConfig.getDigestType();
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

    public void setKey(String symetricKey_str) {

        this.symetricKey_str = symetricKey_str;
    }
    public void setIvSpec(String IV_str) {

        this.IV_str = IV_str;
    }

    public void setHMacKey(String MacKey_str) {
        this.MacKey_str = MacKey_str;
    }
    public String getCiphersuite_str() {
        return ciphersuite_str;
    }
    
    public String getSymetricKey_str() {
        return symetricKey_str;
    }
    
    public String getSymetricKeySize_str() {
        return symetricKeySize_str;
    }
    
    public String getIV_str() {
        return IV_str;
    }
    
    public String getIVSize_str() {
        return IVSize_str;
    }
    
    public String getIntegrity_str() {
        return Integrity_str;
    }
    
    public String getHash_algorithm_str() {
        return Hash_algorithm_str;
    }
    
    public String getMAC_algorithm_str() {
        return MAC_algorithm_str;
    }
    
    public String getMacKey_str() {
        return MacKey_str;
    }
    
    public String getMacKeySize_str() {
        return MacKeySize_str;
    }


    // Convert the object to a byte array
    public byte[] toByteArray() {
        try {
            // Collect all String fields into a Properties object for easy serialization
            Properties props = new Properties();
            props.setProperty("CONFIDENTIALIY", ciphersuite_str);
            props.setProperty("SYMMETRIC_KEY", symetricKey_str);
            props.setProperty("SYMMTRIC_KEY_SIZE", symetricKeySize_str);
            props.setProperty("IV", IV_str);
            props.setProperty("IV_SIZE", IVSize_str);
            props.setProperty("INTEGRITY", Integrity_str);
            props.setProperty("H", Hash_algorithm_str);
            props.setProperty("MAC", MAC_algorithm_str);
            props.setProperty("MACKEY", MacKey_str);
            props.setProperty("MACKEY_SIZE", MacKeySize_str);

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
            props.getProperty("SYMMTRIC_KEY_SIZE"),
            props.getProperty("IV"),
            props.getProperty("IV_SIZE"),
            props.getProperty("INTEGRITY"),
            props.getProperty("H"),
            props.getProperty("MAC"),
            props.getProperty("MACKEY"),
            props.getProperty("MACKEY_SIZE")
        );
    } catch (IOException e) {
        e.printStackTrace();
        return null;
    }
}
public void SaveFile(String path) {
    Properties prop = new Properties();

    // Set the properties from the CryptoConfig fields
    prop.setProperty("CONFIDENTIALIY", this.ciphersuite_str);
    prop.setProperty("SYMMETRIC_KEY", this.symetricKey_str);
    prop.setProperty("SYMMTRIC_KEY_SIZE", this.symetricKeySize_str);
    prop.setProperty("IV", this.IV_str);
    prop.setProperty("IV_SIZE", this.IVSize_str);
    prop.setProperty("INTEGRITY", this.Integrity_str);
    prop.setProperty("H", this.Hash_algorithm_str);
    prop.setProperty("MAC", this.MAC_algorithm_str);
    prop.setProperty("MACKEY", this.MacKey_str);
    prop.setProperty("MACKEY_SIZE", this.MacKeySize_str);

    // Create the output file stream and save the properties
    try (FileOutputStream fos = new FileOutputStream(path)) {
        prop.store(fos, "CryptoConfig Properties");
    } catch (IOException e) {
        e.printStackTrace();
    }
}


@Override
public String toString(){ 
    return "CONFIDENTIALIY: "+ciphersuite_str+"\n"+
    "SYMMETRIC_KEY: "+symetricKey_str+"\n"+
    "SYMMTRIC_KEY_SIZE: "+symetricKeySize_str+"\n"+
    "IV_SIZE: "+IVSize_str+"\n"+
    "IV: "+IV_str+"\n"+
    "INTEGRITY: "+Integrity_str+"\n"+
    "H: "+Hash_algorithm_str+"\n"+
    "MAC: "+MAC_algorithm_str+"\n"+
    "MACKEY: "+MacKey_str+"\n"+
    "MACKEY_SIZE: "+MacKeySize_str;
}
}