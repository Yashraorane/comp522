import java.security.MessageDigest;

public class Hashing {
    public static void main(String[] args) throws Exception {
        String msg = "Displaying use of hash fucntion method";
        System.out.println("message "+ msg);
        MessageDigest hashing = MessageDigest.getInstance("SHA-256");
        System.out.println("hashed : "+ Utils.toHex(hashing.digest()));
    }
}
