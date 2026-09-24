public class Main {

    // S-Box Кузнечика (256 элементов)
    public static final int[] KUZNYECHIK_SBOX = {
            252, 238, 221, 17,  207, 110, 49,  22,  251, 196, 250, 218, 35,  197, 4,   77,
            233, 119, 240, 219, 147, 46,  153, 186, 23,  54,  241, 187, 20,  205, 95,  193,
            249, 24,  101, 90,  226, 92,  239, 33,  129, 28,  60,  66,  139, 1,   142, 79,
            5,   132, 2,   174, 227, 106, 143, 160, 6,   11,  237, 152, 127, 212, 211, 31,
            235, 52,  44,  81,  234, 200, 72,  171, 242, 42,  104, 162, 253, 58,  206, 204,
            181, 112, 14,  86,  8,   12,  118, 18,  191, 114, 19,  71,  156, 183, 93,  135,
            21,  161, 150, 41,  16,  123, 154, 199, 243, 145, 120, 111, 157, 158, 178, 177,
            50,  117, 25,  61,  255, 53,  138, 126, 109, 84,  198, 128, 195, 189, 13,  87,
            223, 245, 36,  169, 62,  168, 67,  201, 215, 121, 214, 246, 124, 34,  185, 3,
            224, 15,  236, 222, 122, 148, 176, 188, 220, 232, 40,  80,  78,  51,  10,  74,
            167, 151, 96,  115, 30,  0,   98,  68,  26,  184, 56,  130, 100, 159, 38,  65,
            173, 69,  70,  146, 39,  94,  85,  47,  140, 163, 165, 125, 105, 213, 149, 59,
            7,   88,  179, 64,  134, 172, 29,  247, 48,  55,  107, 228, 136, 217, 231, 137,
            225, 27,  131, 73,  76,  63,  248, 254, 141, 83,  170, 144, 202, 216, 133, 97,
            32,  113, 103, 164, 45,  43,  9,   91,  203, 155, 37,  208, 190, 229, 108, 82,
            89,  166, 116, 210, 230, 244, 180, 192, 209, 102, 175, 194, 57,  75,  99,  182
    };

    public static int[] buildDefaultPBox() {
        int[] pbox = new int[64];
        for (int i = 0; i < 64; ++i) {
            pbox[i] = (i % 8) * 8 + (i / 8);
        }
        return pbox;
    }

    public static void main(String[] args) {
        final int rounds = 10;


        // 1. ВХОДНЫЕ ДАННЫЕ И КЛЮЧИ


        // KEY Мастер-ключ(64 бита)
        long masterKey = 0x123456789ABCDEFL;

        //Plaintext
        String ptBlock1      = "1111111100000000111111110000000011111111000000001111111100000000"; // 64 бита
        String ptBlock2      = "1111111100000000111111110000000011111111000000001111111100000000"; // 64 бита (дубликат)
        String ptTail        = "1010101010101010"; // 16 бит (некратный хвост)

        String plainText = ptBlock1 + ptBlock2 + ptTail; // Итого: 144 бита

        SPNCipher cipher = new SPNCipher(KUZNYECHIK_SBOX, buildDefaultPBox());
        PaddingScheme isoPadding = new ISO10126Padding();
        BlockCipherMode ecbMode = new ECBMode(cipher, isoPadding);
        BlockCipherMode cbcMode = new CBCMode(cipher, isoPadding);

        long[] roundKeys = KeyScheduler.buildRoundKeys(masterKey, rounds);


        // ВЫВОД: 1. ОБЗОР КЛЮЧЕЙ И ОТКРЫТОГО ТЕКСТА

        System.out.println("");
        System.out.println("1. ИСХОДНЫЙ ОТКРЫТЫЙ ТЕКСТ (PT) И КЛЮЧИ (KEYS)");
        System.out.println("");
        System.out.println("[PT] Plaintext (Открытый текст):");
        System.out.println("     Длина : " + plainText.length() + " бит (" + (plainText.length() / 8) + " байт)");
        System.out.println("     Бит-ст: " + plainText);

        System.out.println("\n[KEY] Master Key (Мастер-ключ):");
        System.out.println("      HEX : " + String.format("0x%016X", masterKey));
        System.out.println("      BIN : " + SPNCipher.longToBinaryString(masterKey));

        System.out.println("\n[KEYS] Раундовые ключи (K0 - K" + rounds + "):");
        for (int i = 0; i <= rounds; i++) {
            System.out.printf("       K%-2d : %s  (0x%016X)%n",
                    i, SPNCipher.longToBinaryString(roundKeys[i]), roundKeys[i]);
        }


        // ВЫВОД: 2. ISO 10126 ПАДДИНГ (PT -> PT_padded)

        System.out.println("");
        System.out.println("2. ДОПОЛНЕНИЕ БЛОКОВ ISO 10126 (PADDING)");
        System.out.println("");
        String paddedPT = isoPadding.pad(plainText, SPNCipher.BLOCK_BITS);
        System.out.println("[PT_Padded] Текст после паддинга (3 блока по 64 бита):");
        System.out.println("            " + paddedPT);
        System.out.println("            Блок 1 (64б) : " + paddedPT.substring(0, 64));
        System.out.println("            Блок 2 (64б) : " + paddedPT.substring(64, 128));
        System.out.println("            Блок 3 (64б) : " + paddedPT.substring(128, 192) + " [16б данных + 40б шум + 8б длина]");


        // ВЫВОД: 3. ПОШАГОВАЯ ТРАССИРОВКА 1 БЛОКА

        System.out.println("");
        System.out.println("3. РАУНДОВАЯ ТРАССИРОВКА SPN-СЕТИ (1 БЛОК)");
        System.out.println("");
        long sampleBlockPT = SPNCipher.binaryStringToLong(ptBlock1);
        System.out.println("[Входной PT Блок 1]: " + SPNCipher.longToBinaryString(sampleBlockPT));

        System.out.println("\nПроцесс шифрования (10 раундов)");
        long sampleBlockCT = cipher.encryptBlock(sampleBlockPT, roundKeys, rounds, true);
        System.out.println("Итоговый CT Блок 1: " + SPNCipher.longToBinaryString(sampleBlockCT));

        System.out.println("\nПроцесс расшифровки (10 раундов)");
        cipher.decryptBlock(sampleBlockCT, roundKeys, rounds, true);


        // ВЫВОД: 4. СРАВНЕНИЕ РЕЖИМОВ ECB И CBC

        System.out.println("");
        System.out.println("4. РЕЗУЛЬТАТЫ ШИФРОВАНИЯ (CIPHERTEXT)");
        System.out.println("");

        String ecbCT = ecbMode.encrypt(plainText, roundKeys, rounds);
        System.out.println("[CT ECB] Шифротекст ECB:");
        for (int i = 0; i < ecbCT.length(); i += SPNCipher.BLOCK_BITS) {
            System.out.println("         Блок " + (i / SPNCipher.BLOCK_BITS + 1) + ": " + ecbCT.substring(i, i + SPNCipher.BLOCK_BITS));
        }

        String cbcCT = cbcMode.encrypt(plainText, roundKeys, rounds);
        System.out.println("\n[CT CBC] Шифротекст CBC:");
        System.out.println("         Вектор IV : " + cbcCT.substring(0, SPNCipher.BLOCK_BITS));
        for (int i = SPNCipher.BLOCK_BITS; i < cbcCT.length(); i += SPNCipher.BLOCK_BITS) {
            System.out.println("         Блок " + (i / SPNCipher.BLOCK_BITS) + "    : " + cbcCT.substring(i, i + SPNCipher.BLOCK_BITS));
        }


        // ВЫВОД: 5. ПРОВЕРКА РАСШИФРОВКИ

        System.out.println(" ");
        System.out.println("5. ПРОВЕРКА ВОССТАНОВЛЕНИЯ ");
        System.out.println(" ");
        String ecbDecryptedPT = ecbMode.decrypt(ecbCT, roundKeys, rounds);
        String cbcDecryptedPT = cbcMode.decrypt(cbcCT, roundKeys, rounds);

        System.out.println("[ECB] Восстановленный PT : " + ecbDecryptedPT);
        System.out.println("[ECB] Совпадение с PT : " + plainText.equals(ecbDecryptedPT));

        System.out.println("\n[CBC] Восстановленный PT : " + cbcDecryptedPT);
        System.out.println("[CBC] Совпадение с PT : " + plainText.equals(cbcDecryptedPT));
    }
}