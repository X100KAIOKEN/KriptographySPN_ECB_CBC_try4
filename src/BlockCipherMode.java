public interface BlockCipherMode {
    String encrypt(String binaryInput, long[] roundKeys, int rounds);
    String decrypt(String binaryCiphertext, long[] roundKeys, int rounds);
}