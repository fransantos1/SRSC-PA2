import java.io.IOException;
import java.security.Security;

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
            client_shp_phase1 client= new client_shp_phase1();
            client.client();
        } catch (Exception e) {
            // TODO Auto-generated catch block
            e.printStackTrace();
        }
    }

    public static  void testServer(){
        try {
            server_shp_phase1 server = new server_shp_phase1();
            server.server();
        } catch (Exception e) {
            // TODO Auto-generated catch block
            e.printStackTrace();
        }
    }
    

}
