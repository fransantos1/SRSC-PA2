import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.security.MessageDigest;
import java.util.Properties;

import javax.crypto.Mac;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;

import java.io.*;

public class cryptoConfig implements Serializable {
    private static final long serialVersionUID = 1L;

    private final String ciphersuite;
    private final String symetricKey;
    private final String symetricKey_size;
    private final String IV_size;
    private final String IV;
    private final String Integrity;
    private final String Hash_algorithm;
    private final String MAC_algorithm;
    private final String MacKey;
    private final String MacKey_size;

    // Constructors
    public cryptoConfig(String path) {
        Properties prop = new Properties();
        try (FileInputStream fis = new FileInputStream(path)) {
            System.out.println("Read Properties");
            prop.load(fis);
        } catch (FileNotFoundException ex) {
            System.out.println(ex);
        } catch (IOException ex) {
            System.out.println(ex);
        }
        this.ciphersuite = prop.getProperty("CONFIDENTIALIY");
        this.symetricKey = prop.getProperty("SYMMETRIC_KEY");
        this.symetricKey_size = prop.getProperty("SYMMTRIC_KEY_SIZE");
        this.IV_size = prop.getProperty("IV_SIZE");
        this.IV = prop.getProperty("IV");
        this.Integrity = prop.getProperty("INTEGRITY");
        this.Hash_algorithm = prop.getProperty("H");
        this.MAC_algorithm = prop.getProperty("MAC");
        this.MacKey = prop.getProperty("MACKEY");
        this.MacKey_size = prop.getProperty("MACKEY_SIZE");
    }

    public cryptoConfig(String ciphersuite, String symetricKey, String symetricKey_size,
                        String IV_size, String IV, String Integrity, String Hash_algorithm,
                        String MAC_algorithm, String MacKey, String MacKey_size) {
        this.ciphersuite = ciphersuite;
        this.symetricKey = symetricKey;
        this.symetricKey_size = symetricKey_size;
        this.IV_size = IV_size;
        this.IV = IV;
        this.Integrity = Integrity;
        this.Hash_algorithm = Hash_algorithm;
        this.MAC_algorithm = MAC_algorithm;
        this.MacKey = MacKey;
        this.MacKey_size = MacKey_size;
    }

    // Serialize object to byte array
    public byte[] toByteArray() {
        try (ByteArrayOutputStream bos = new ByteArrayOutputStream();
             ObjectOutputStream oos = new ObjectOutputStream(bos)) {
            oos.writeObject(this);
            return bos.toByteArray();
        } catch (IOException e) {
            throw new RuntimeException("Error serializing object to byte array", e);
        }
    }

    // Deserialize object from byte array
    public static cryptoConfig fromByteArray(byte[] byteArr) {
        try (ByteArrayInputStream bis = new ByteArrayInputStream(byteArr);
             ObjectInputStream ois = new ObjectInputStream(bis)) {
            return (cryptoConfig) ois.readObject();
        } catch (IOException | ClassNotFoundException e) {
            throw new RuntimeException("Error deserializing byte array to object", e);
        }
    }

    // Getters
    public String getCiphersuite() {
        return ciphersuite;
    }

    public String getSymetricKey() {
        return symetricKey;
    }

    public String getSymetricKey_size() {
        return symetricKey_size;
    }

    public String getIV_size() {
        return IV_size;
    }

    public String getIV() {
        return IV;
    }

    public String getIntegrity() {
        return Integrity;
    }

    public String getHash_algorithm() {
        return Hash_algorithm;
    }

    public String getMAC_algorithm() {
        return MAC_algorithm;
    }

    public String getMacKey() {
        return MacKey;
    }

    public String getMacKey_size() {
        return MacKey_size;
    }
}