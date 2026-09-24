import java.security.SecureRandom;

public class ISO10126Padding implements PaddingScheme {
    private final SecureRandom secureRandom = new SecureRandom();

    @Override
    public String pad(String input, int blockSizeBits) {
        StringBuilder sb = new StringBuilder(input);

        int remBits = sb.length() % 8;
        if (remBits != 0) {
            sb.append("0".repeat(8 - remBits));
        }

        int currentBytes = sb.length() / 8;
        int blockBytes = blockSizeBits / 8;
        int padBytes = blockBytes - (currentBytes % blockBytes);

        for (int i = 0; i < padBytes - 1; i++) {
            int randomByte = secureRandom.nextInt(256);
            String randBin = String.format("%8s", Integer.toBinaryString(randomByte)).replace(' ', '0');
            sb.append(randBin);
        }

        String lengthByteBin = String.format("%8s", Integer.toBinaryString(padBytes)).replace(' ', '0');
        sb.append(lengthByteBin);

        return sb.toString();
    }

    @Override
    public String unpad(String input) {
        String lastByteStr = input.substring(input.length() - 8);
        int padBytes = Integer.parseInt(lastByteStr, 2);
        return input.substring(0, input.length() - (padBytes * 8));
    }
}