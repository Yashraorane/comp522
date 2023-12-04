import java.security.*;
import javax.crypto.*;
import javax.crypto.interfaces.DHPublicKey;
import javax.crypto.spec.DHParameterSpec;



public class DHKeyfour {
    private DHKeyfour(){}
    
    public static void main(String[] args) throws Exception {
        //User A creates her own DH key pair with 2048-bit key size
        KeyPairGenerator aKpairGen = KeyPairGenerator.getInstance("DH");
        aKpairGen.initialize(2048);
        KeyPair aKpair = aKpairGen.generateKeyPair();

        DHParameterSpec paramShared = ((DHPublicKey)aKpair.getPublic()).getParams();
        //User B creates her own DH key pair 
        KeyPairGenerator bKpairGen = KeyPairGenerator.getInstance("DH");
        bKpairGen.initialize(paramShared);
        KeyPair bKpair = bKpairGen.generateKeyPair();

        //User C creates her own DH key pair 
        KeyPairGenerator cKpairGen = KeyPairGenerator.getInstance("DH");
        cKpairGen.initialize(paramShared);
        KeyPair cKpair = cKpairGen.generateKeyPair();

        //User D creates her own DH key pair 
        KeyPairGenerator dKpairGen = KeyPairGenerator.getInstance("DH");
        dKpairGen.initialize(paramShared);
        KeyPair dKpair = dKpairGen.generateKeyPair();



        //User A initializes KeyAgreement
        KeyAgreement aKeyAgree = KeyAgreement.getInstance("DH");
        //gA
        aKeyAgree.init(aKpair.getPrivate());

        //User B initializes KeyAgreement
        KeyAgreement bKeyAgree = KeyAgreement.getInstance("DH");
        //gB
        bKeyAgree.init(bKpair.getPrivate());

        //User C initializes KeyAgreement
        KeyAgreement cKeyAgree = KeyAgreement.getInstance("DH");
        //gC
        cKeyAgree.init(cKpair.getPrivate());

        //User D initializes KeyAgreement
        KeyAgreement dKeyAgree = KeyAgreement.getInstance("DH");
        //gD
        dKeyAgree.init(dKpair.getPrivate());



        //passing for the first round
        //gDA
        Key da = aKeyAgree.doPhase(dKpair.getPublic(), false);
        //gAB
        Key ab = bKeyAgree.doPhase(aKpair.getPublic(), false);
        //gBC
        Key bc = cKeyAgree.doPhase(bKpair.getPublic(), false);
        //gCD 
        Key cd = dKeyAgree.doPhase(cKpair.getPublic(), false);


        //passing for the second round
        //gCDA
        Key cda = aKeyAgree.doPhase(cd, false);
        //gDAB
        Key dab = bKeyAgree.doPhase(da, false);
        //gABC
        Key abc = cKeyAgree.doPhase(ab, false);
        //gBCD 
        Key bcd = dKeyAgree.doPhase(bc, false);



        //passing for the third round
        //gBCDA 
        aKeyAgree.doPhase(bcd, true);
        //gCDAB
        bKeyAgree.doPhase(cda, true);
        //gDABC
        cKeyAgree.doPhase(dab, true);
        //gABCD
        dKeyAgree.doPhase(abc, true);

        //User A,B,C,D calculate their secrets
        byte[] aShareSecret = aKeyAgree.generateSecret();
        byte[] bShareSecret = bKeyAgree.generateSecret();
        byte[] cShareSecret = cKeyAgree.generateSecret();
        byte[] dShareSecret = dKeyAgree.generateSecret();

        //compare secret in 4 parties
        if(!MessageDigest.isEqual(aShareSecret, bShareSecret) 
        || !MessageDigest.isEqual(bShareSecret, cShareSecret) 
        || !MessageDigest.isEqual(cShareSecret, dShareSecret)){
            throw new Exception("Share differ");
        }
        System.out.println("Share are same");
    }

    private static void bytetohex(byte b, StringBuffer bf){
        char[] hexChars={'0','1','2','3','4','5','6','7','8','9','A','B','C','D','E','F'};
             int high = ((b & 0xf0) >> 4);
             int low = (b & 0x0f);
             bf.append(hexChars[high]);
             bf.append(hexChars[low]);              
    }

    private static String toHexString(byte[] block){
        StringBuffer bf = new StringBuffer();
        int l = block.length;
        for(int i= 0; i<l;i++){
            bytetohex(block[i], bf);
            if(i<l-1){
                bf.append(":");
            }
        }return bf.toString();
    }
}
