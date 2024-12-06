import java.io.IOException;
import java.security.Security;
import java.util.ArrayList;

import DataBase.User;
import DataBase.dataBaseManager;

public class testSHP {
    
    public static void main(String[] args) {
        Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());
        if(args.length == 0){
            System.out.println("No Params");
            return;
        }
        if(args[0].equals("c")){
            testClient();
        }else{
            testServer();
        }
       
    }
    public static void testClient(){
        try {
            String[] args = {"olas", "olas"};
            client_shp_phase1 client= new client_shp_phase1();
            client.client("alice@gmail.com", "StrongPassword123", 5001,399, "127.0.0.1", args);
        } catch (Exception e) {
            // TODO Auto-generated catch block
            e.printStackTrace();
        }
    }

    public static  void testServer(){
        try {
            server_shp_phase1 server = new server_shp_phase1();
            String[] str = server.server();
            System.out.println(str[0]);
            System.out.println(str[1]);
            System.out.println(str[2]);

        } catch (Exception e) {
            // TODO Auto-generated catch block
            e.printStackTrace();
        }
    }
    

}
