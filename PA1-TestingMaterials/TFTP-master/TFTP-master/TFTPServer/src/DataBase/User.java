package DataBase;


public class User {
    private final String userID;
    private final String pwd;
    private final String salt;
    private final String KpubClient;

    // Constructor
    public User(String userID, String pwd, String salt, String KpubClient) {
        this.userID = userID;
        this.pwd = pwd;
        this.salt = salt;
        this.KpubClient = KpubClient;
    }

    // Getters
    public String getId() {
        return userID;
    }

    public String getPwd() {
        return pwd;
    }

    public String getSalt() {
        return salt;
    }

    public String getKpubClient() {
        return KpubClient;
    }

    // toString method
    @Override
    public String toString() {
        return "User{" +
                "userID='" + userID + '\'' +
                ", pwd='" + pwd + '\'' +
                ", salt='" + salt + '\'' +
                ", KpubClient='" + KpubClient + '\'' +
                '}';
    }
}
