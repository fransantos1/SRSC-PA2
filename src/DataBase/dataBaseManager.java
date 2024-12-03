package DataBase;

import java.io.BufferedReader;
import java.io.BufferedWriter;
import java.io.FileReader;
import java.io.FileWriter;
import java.io.IOException;
import java.util.HashMap;

/*
Userid : H(password) : salt : KpubClient

Userid: can use strings as email addresses (ex: alice@gmail.com)
password: a strong password registered for the user
H(password): SHA256(password)
salt: random number registered for each user (128 bits)
KpubClient: a ECC public key registstrd for each user

Note: Can use Base64 or Hexadecimal

representations for the binary objects in the
database entries

 */

public class dataBaseManager {
    private final HashMap<String ,User> dataBase;
    private final String database_path = "./DataBase/userDataBase.txt";
    
    public dataBaseManager(){
        dataBase = new HashMap<>();

        try (BufferedReader br = new BufferedReader(new FileReader(database_path))) {
            String line;
            while ((line = br.readLine()) != null) {
                String[] entries = line.split(":");
                User user = new User(entries[0], entries[1], entries[2], entries[3]);
                dataBase.put(entries[0], user);
            }
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    public User getUser(String userID){
        return dataBase.get(userID);
    }

    public void updateUser(User user) {
        dataBase.put(user.getId(), user);
        try (BufferedReader br = new BufferedReader(new FileReader(database_path))) {
            StringBuilder fileContent = new StringBuilder();
            String line;
            while ((line = br.readLine()) != null) {
                String[] entries = line.split(":");
                if (entries[0].equals(user.getId())) {
                    fileContent.append(user.getId()).append(":").append(user.getPwd()).append(":").append(user.getSalt()).append(":").append(user.getKpubClient()).append("\n");
                } else {
                    fileContent.append(line).append("\n");
                }
            }
            try (BufferedWriter writer = new BufferedWriter(new FileWriter(database_path))) {
                writer.write(fileContent.toString());
            }
    
        } catch (IOException e) {
            e.printStackTrace();
        }
    }
    
    public void removeUser(String userID) {
        dataBase.remove(userID);

        try (BufferedReader br = new BufferedReader(new FileReader(database_path))) {
            StringBuilder fileContent = new StringBuilder();
            String line;
            while ((line = br.readLine()) != null) {
                String[] entries = line.split(":");
                if (!entries[0].equals(userID)) {
                    fileContent.append(line).append("\n");
                }
            }
            try (BufferedWriter writer = new BufferedWriter(new FileWriter(database_path))) {
                writer.write(fileContent.toString());
            }
        } catch (IOException e) {
            e.printStackTrace();
        }
    }
    
   public void addUser(User usr) {
    dataBase.put(usr.getId(), usr);
    try (BufferedWriter writer = new BufferedWriter(new FileWriter(database_path, true))) {
        writer.append(usr.getId()).append(":").append(usr.getPwd()).append(":").append(usr.getSalt()).append(":").append(usr.getKpubClient()).append("\n");
    } catch (IOException e) {
        e.printStackTrace();
    }
}

    
}
