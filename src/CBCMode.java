import java.security.SecureRandom;

public class CBCMode implements BlockCipherMode {
    private final SPNCipher cipher;
    private final PaddingScheme padding;
    private final SecureRandom secureRandom = new SecureRandom();

    public CBCMode(SPNCipher cipher, PaddingScheme padding) {
        this.cipher = cipher;
        this.padding = padding;
    }

    @Override
    public String encrypt(String binaryInput, long[] roundKeys, int rounds) {
        String paddedInput = padding.pad(binaryInput, SPNCipher.BLOCK_BITS);
        StringBuilder cipherResult = new StringBuilder();

        long iv = secureRandom.nextLong();
        cipherResult.append(SPNCipher.longToBinaryString(iv));
        long prevBlock = iv;

        for (int i = 0; i < paddedInput.length(); i += SPNCipher.BLOCK_BITS) {
            String chunk = paddedInput.substring(i, i + SPNCipher.BLOCK_BITS);
            long plainBlock = SPNCipher.binaryStringToLong(chunk);
            plainBlock ^= prevBlock;

            long encryptedBlock = cipher.encryptBlock(plainBlock, roundKeys, rounds, false);
            cipherResult.append(SPNCipher.longToBinaryString(encryptedBlock));
            prevBlock = encryptedBlock;
        }
        return cipherResult.toString();
    }

    @Override
    public String decrypt(String binaryCiphertext, long[] roundKeys, int rounds) {
        String ivChunk = binaryCiphertext.substring(0, SPNCipher.BLOCK_BITS);
        long prevBlock = SPNCipher.binaryStringToLong(ivChunk);
        StringBuilder plainResult = new StringBuilder();

        for (int i = SPNCipher.BLOCK_BITS; i < binaryCiphertext.length(); i += SPNCipher.BLOCK_BITS) {
            String chunk = binaryCiphertext.substring(i, i + SPNCipher.BLOCK_BITS);
            long cipherBlock = SPNCipher.binaryStringToLong(chunk);

            long decryptedBlock = cipher.decryptBlock(cipherBlock, roundKeys, rounds, false);
            decryptedBlock ^= prevBlock;

            plainResult.append(SPNCipher.longToBinaryString(decryptedBlock));
            prevBlock = cipherBlock;
        }
        return padding.unpad(plainResult.toString());
    }
}