import javax.crypto.*;

public class HMacSha256 {
    public static void main(String[] args) throws Exception {
        KeyGenerator kgen = KeyGenerator.getInstance("HmacSHA256");
        SecretKey ks = kgen.generateKey();

        Mac m = Mac.getInstance("HmacSHA256");
        m.init(ks);
        byte[] output = m.doFinal("Hi".getBytes());
        System.out.println(toHexString(output));
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
