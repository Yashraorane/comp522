import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.security.PrivateKey;
import java.security.PublicKey;

import javax.crypto.Cipher;

public class RSASHA1 {
    public static void main(String[] args) throws Exception{
    String text = "This is text";

    //SHA-1
    byte[] hmsg = text.getBytes();
    MessageDigest digest = MessageDigest.getInstance("SHA-1");
    digest.digest(hmsg);
    System.out.println("SHA-1 "+ Utils.toHex(hmsg));

    //RSA Keys
    KeyPair kp = generateKeyPair();
    PrivateKey pk = kp.getPrivate();
    PublicKey puk = kp.getPublic();

    //encryption private key
    Cipher ciprivate = Cipher.getInstance("RSA");
    ciprivate.init(Cipher.ENCRYPT_MODE,pk);
    byte[] encrytp_pk = ciprivate.doFinal(hmsg);
    System.out.println("Encrypted digest "+ Utils.toHex(encrytp_pk));
     
    Verify v = new Verify(text,encrytp_pk,puk);
    v.verification();

    //Attacks
    //1 change msg
    v.messageattack("This is a updated msg");
    //2 change encrypted digest
    v.encryptDigestattack(new byte[]{0x01,0x02,0x03});
    //3 change both msg and digest
    v.attack("Change in msg and digest");

    }

    static class Verify {

        private String verifyText;
        private byte[] verifyencrypt_pk;
        private PublicKey verifypuk;

        public Verify(String text, byte[] encrytp_pk, PublicKey puk) {
            this.verifyText=text;
            this.verifyencrypt_pk=encrytp_pk;
            this.verifypuk=puk;
        }

        public void verification() throws Exception{
            
            //Decrypting the receiving digest msg with public key
            Cipher cipublic = Cipher.getInstance("RSA");
            cipublic.init(Cipher.DECRYPT_MODE,verifypuk);
            byte[] decrytp_puk = cipublic.doFinal(verifyencrypt_pk);
            System.out.println("Decrpyted Digest: "+ Utils.toHex(decrytp_puk));

            //calculate SHA-1 digest
            byte[] recalulatinghmsg = verifyText.getBytes();
            MessageDigest digest = MessageDigest.getInstance("SHA-1");
            digest.digest(recalulatinghmsg);
            System.out.println("Recalculated SHA-1 "+ Utils.toHex(recalulatinghmsg));

            //compare
            boolean isSame = MessageDigest.isEqual(decrytp_puk, recalulatinghmsg);
            System.out.println("Digest hmsg is Same "+ isSame);
            System.out.println();
        }

        public void messageattack(String modifedstring) {
            this.verifyText = modifedstring;
            System.out.println("Verify: Msg has been changed");
        }
    
        public void encryptDigestattack(byte[] bs) {
            this.verifyencrypt_pk = bs;
            System.out.println("Verify: exncrypt digest has changed");
        }
    
        public void attack(String modifedstring) {
            messageattack(modifedstring);
            encryptDigestattack(new byte[]{0x01,0x02,0x03});
        }


    } 

    

   
    private static KeyPair generateKeyPair() throws Exception {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
        kpg.initialize(512);
        return kpg.generateKeyPair();
    }
}
