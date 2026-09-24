public class ECBMode implements BlockCipherMode {
    private final SPNCipher cipher;
    private final PaddingScheme padding;

    public ECBMode(SPNCipher cipher, PaddingScheme padding) {
        this.cipher = cipher;
        this.padding = padding;
    }

    @Override
    public String encrypt(String binaryInput, long[] roundKeys, int rounds) {
        String paddedInput = padding.pad(binaryInput, SPNCipher.BLOCK_BITS);
        StringBuilder cipherResult = new StringBuilder();

        for (int i = 0; i < paddedInput.length(); i += SPNCipher.BLOCK_BITS) {
            String chunk = paddedInput.substring(i, i + SPNCipher.BLOCK_BITS);
            long plainBlock = SPNCipher.binaryStringToLong(chunk);
            long encryptedBlock = cipher.encryptBlock(plainBlock, roundKeys, rounds, false);
            cipherResult.append(SPNCipher.longToBinaryString(encryptedBlock));
        }
        return cipherResult.toString();
    }

    @Override
    public String decrypt(String binaryCiphertext, long[] roundKeys, int rounds) {
        StringBuilder plainResult = new StringBuilder();

        for (int i = 0; i < binaryCiphertext.length(); i += SPNCipher.BLOCK_BITS) {
            String chunk = binaryCiphertext.substring(i, i + SPNCipher.BLOCK_BITS);
            long cipherBlock = SPNCipher.binaryStringToLong(chunk);
            long decryptedBlock = cipher.decryptBlock(cipherBlock, roundKeys, rounds, false);
            plainResult.append(SPNCipher.longToBinaryString(decryptedBlock));
        }
        return padding.unpad(plainResult.toString());
    }
}