import java.util.Random;

public class KeyScheduler {
    public static long[] buildRoundKeys(long masterSeed, int rounds) {
        Random rng = new Random(masterSeed);
        long[] keys = new long[rounds + 1];
        for (int i = 0; i <= rounds; ++i) {
            keys[i] = rng.nextLong();
        }
        return keys;
    }
}