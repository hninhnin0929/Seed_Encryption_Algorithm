import java.util.Base64;

import static java.nio.charset.StandardCharsets.UTF_8;

public class Main {
    public static void main(String[] args) {

        byte pbUserKey[]  = "ecplaza153620629".getBytes();
        byte bszIV[] = "5103370346836226".getBytes();

       String plainText="203.233.213.210::20230721024155::hnin0929@ecplaza.net";

        byte pbData[]     = plainText.getBytes();

//        int PLAINTEXT_LENGTH = 14;
//        int CIPHERTEXT_LENGTH = 16;

        int PLAINTEXT_LENGTH = plainText.getBytes().length;

        //call seed encrypt algorithm
        encryptWithSeed(pbUserKey, bszIV, pbData, PLAINTEXT_LENGTH);

        //call seed decrypt algorithm
        String encodedString = "L1abI6uyk0xgcZZKmfrf+lr6eU8GqcJyodxYcOGxdYaWkmItrHPdt5Knntd9xB/Pz+5nT/246wwdK9XWNE30aw==";
        decryptWithSeed(pbUserKey, bszIV, encodedString);
    }

    public static String encryptWithSeed(byte[] pbUserKey, byte[] bszIV, byte[] pbData, int PLAINTEXT_LENGTH) {

        System.out.print("\n");
        System.out.print("[ Test SEED reference code CBC]"+"\n");
        System.out.print("\n\n");

        System.out.print("[ Test Encrypt mode : ��� 1 ]"+"\n");
        System.out.print("Key\t\t\t\t: ");
        for (int i=0; i<16; i++)	System.out.print(Integer.toHexString(0xff&pbUserKey[i])+" ");
        System.out.print("\n");
        System.out.print("Plaintext\t\t\t: ");
        for (int i=0; i<PLAINTEXT_LENGTH; i++)	System.out.print(Integer.toHexString(0xff&pbData[i])+" ");
        System.out.print("\n");

        byte[] defaultCipherText = KISA_SEED_CBC.SEED_CBC_Encrypt(pbUserKey, bszIV, pbData, 0, PLAINTEXT_LENGTH);

        byte[] PPPPP = KISA_SEED_CBC.SEED_CBC_Decrypt(pbUserKey, bszIV, defaultCipherText, 0, defaultCipherText.length);

        System.out.print("\nIV\t\t\t\t: ");
        for (int i=0; i<16; i++)
            System.out.print(Integer.toHexString(0xff&bszIV[i])+" ");
        System.out.print("\n");

        System.out.print("Ciphertext(SEED_CBC_Encrypt)\t: ");
        int CIPHERTEXT_LENGTH = defaultCipherText.length;
        for (int i=0; i<CIPHERTEXT_LENGTH; i++)
            System.out.print(Integer.toHexString(0xff&defaultCipherText[i])+" ");
        System.out.print("\n");

        System.out.print("Plaintext(SEED_CBC_Decrypt)\t: ");
        for (int i=0; i<PLAINTEXT_LENGTH; i++)
            System.out.print(Integer.toHexString(0xff&PPPPP[i])+" ");
        System.out.print("\n\n");

        //base64 encode
        byte[] encodedEncryptedInfo = Base64.getEncoder().encode(defaultCipherText);
        String encodedString = new String(encodedEncryptedInfo, UTF_8);
        System.out.println(encodedString);


        return encodedString;
    }

    public static String decryptWithSeed(byte[] pbUserKey, byte[] bszIV,String encodedString){
        // Base64 decode the string
        byte[] decodedBytes = Base64.getDecoder().decode(encodedString);

        // Convert bytes to a string (assuming it's a text-based content)
        //String decodedString = new String(decodedBytes);

       //System.out.println(decodedString);

        byte[] dec = KISA_SEED_CBC.SEED_CBC_Decrypt(pbUserKey, bszIV, decodedBytes, 0, decodedBytes.length);
        String finalDecodedStr = new String(dec, UTF_8);
        System.out.println(finalDecodedStr);


        // Split the inputString by "::" and store the substrings in an array
        String[] substrings = finalDecodedStr.split("::");

        // Get the last substring after "::"
        String lastSubstring = substrings[substrings.length - 1];

        System.out.println("Last substring after '::': " + lastSubstring);

        return finalDecodedStr;
    }
}