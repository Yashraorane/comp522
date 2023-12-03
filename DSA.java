import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Signature;

public class DSA {

    public static void main(String[] args) {
        try{
            KeyPair kp = generateKeyPair();
            String msg = "Hello this is new sign";
            System.out.println("Message is: " + msg);

            byte[] si = signature(msg,kp.getPrivate());
            System.out.println("Signature is: " + byte2Hex(si));

            boolean verify = verify(msg,si,kp.getPublic());
            System.out.println("Sign verified " + verify);
        }catch (Exception e){
            e.printStackTrace();
        }
    }
    private static KeyPair generateKeyPair() throws NoSuchAlgorithmException{
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("DSA");
        SecureRandom securerandom = new SecureRandom();
        kpg.initialize(1024,securerandom);
        return kpg.generateKeyPair();
    }

    private static boolean verify(String msg, byte[] si, PublicKey public1) throws Exception {
        Signature verifing = Signature.getInstance("SHA256withDSA");
        verifing.initVerify(public1);
        verifing.update(msg.getBytes());
        return verifing.verify(si);
    }

    private static String byte2Hex(byte[] si) {
        StringBuilder hex = new StringBuilder();
        for(byte be: si){
            String hexanum = Integer.toHexString(0XFF & be);
            if (hexanum.length() ==1) {
                hex.append('0');
            }
            hex.append(hexanum);
        }
        return hex.toString();
    }

    private static byte[] signature(String msg1, PrivateKey privatek) throws Exception{
        Signature sign = Signature.getInstance("SHA256withDSA");
        sign.initSign(privatek);
        sign.update(msg1.getBytes());
        return sign.sign();  
    }
}