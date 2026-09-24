public interface PaddingScheme {
    String pad(String input, int blockSizeBits);
    String unpad(String input);
}