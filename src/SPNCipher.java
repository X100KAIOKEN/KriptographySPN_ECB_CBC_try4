public class SPNCipher {
    public static final int BLOCK_BITS = 64;
    private final int[] sbox;
    private final int[] invSbox;
    private final int[] pbox;
    private final int[] invPbox;

    public SPNCipher(int[] sbox, int[] pbox) {
        this.sbox = sbox;
        this.pbox = pbox;
        this.invSbox = invertBox(sbox);
        this.invPbox = invertBox(pbox);
    }

    private int[] invertBox(int[] box) {
        int[] inv = new int[box.length];
        for (int i = 0; i < box.length; ++i) {
            inv[box[i]] = i;
        }
        return inv;
    }

    public static long binaryStringToLong(String bitStr) {
        return Long.parseUnsignedLong(bitStr, 2);
    }

    public static String longToBinaryString(long value) {
        String s = Long.toBinaryString(value);
        if (s.length() < BLOCK_BITS) {
            return String.format("%" + BLOCK_BITS + "s", s).replace(' ', '0');
        }
        return s;
    }

    private long applySBox(long state, int[] currentBox) {
        long result = 0;
        for (int i = 0; i < 8; i++) {
            int shift = i * 8;
            int b = (int) ((state >>> shift) & 0xFF);
            long replaced = currentBox[b] & 0xFF;
            result |= (replaced << shift);
        }
        return result;
    }

    private long applyPBox(long state, int[] currentBox) {
        long result = 0;
        for (int i = 0; i < BLOCK_BITS; i++) {
            if (((state >>> i) & 1L) == 1L) {
                result |= (1L << currentBox[i]);
            }
        }
        return result;
    }

    public long encryptBlock(long state, long[] keys, int rounds, boolean verbose) {
        if (verbose) System.out.println("  [Вход]  State = " + longToBinaryString(state));

        state ^= keys[0];
        if (verbose) System.out.println("  [K0 XOR] State = " + longToBinaryString(state));

        for (int r = 1; r < rounds; ++r) {
            state = applySBox(state, sbox);
            state = applyPBox(state, pbox);
            state ^= keys[r];
            if (verbose) System.out.printf("  [Раунд %2d] S-Box -> P-Box -> XOR K%-2d = %s%n", r, r, longToBinaryString(state));
        }

        state = applySBox(state, sbox);
        state ^= keys[rounds];
        if (verbose) System.out.printf("  [Раунд %2d] S-Box -> XOR K%-2d (Финал) = %s%n", rounds, rounds, longToBinaryString(state));

        return state;
    }

    public long decryptBlock(long state, long[] keys, int rounds, boolean verbose) {
        if (verbose) System.out.println("  [Вход]  State = " + longToBinaryString(state));

        state ^= keys[rounds];
        state = applySBox(state, invSbox);
        if (verbose) System.out.printf("  [Раунд %2d] XOR K%-2d -> InvS-Box = %s%n", rounds, rounds, longToBinaryString(state));

        for (int r = rounds - 1; r >= 1; --r) {
            state ^= keys[r];
            state = applyPBox(state, invPbox);
            state = applySBox(state, invSbox);
            if (verbose) System.out.printf("  [Раунд %2d] XOR K%-2d -> InvP-Box -> InvS-Box = %s%n", r, r, longToBinaryString(state));
        }

        state ^= keys[0];
        if (verbose) System.out.println("  [K0 XOR] State = " + longToBinaryString(state) + " (Расшифровано)");

        return state;
    }
}