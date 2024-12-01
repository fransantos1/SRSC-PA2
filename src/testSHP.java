import java.io.IOException;

import DataBase.User;
import DataBase.dataBaseManager;

public class testSHP {
    
    public static void main(String[] args) {
       String email = "StrongPassword123";
       String password = "StrongPassword123";

        dataBaseManager DB = new dataBaseManager();

        if(args.length == 0){
            System.out.println("No Params");
            return;
        }
        SHP shp = new SHP();
        if(args[0].equals("c")){
            testClient(shp);
        }else{
            testServer(shp);
        }

        // Print a welcome message to the console
        System.out.println("Welcome to the Java Program!");

        // Example usage: Call a method or class
       
    }
    public static void testClient(SHP shp){
        try {
            shp.client();
        } catch (IOException e) {
            // TODO Auto-generated catch block
            e.printStackTrace();
        }
    }

    public static  void testServer(SHP shp){
        try {
            shp.server();
        } catch (IOException e) {
            // TODO Auto-generated catch block
            e.printStackTrace();
        }
    }
    

}
