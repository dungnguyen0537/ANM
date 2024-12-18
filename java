import java.math.BigInteger;
import java.security.SecureRandom;
import java.util.Random;
import java.nio.charset.StandardCharsets;
import java.util.Base64;

public class ElGamalEncryption {
    private BigInteger p, q, g, a, x, d, k;
    private String c1, c2;
    private final SecureRandom secureRandom = new SecureRandom();

    // Helper method to check if a number is probably prime
    private boolean isProbablePrime(BigInteger n, int certainty) {
        return n.isProbablePrime(certainty);
    }

    // Helper method to check if two numbers are coprime
    private boolean areCoprime(BigInteger a, BigInteger b) {
        return a.gcd(b).equals(BigInteger.ONE);
    }

    // Helper method for modular exponentiation
    private BigInteger modPow(BigInteger base, BigInteger exponent, BigInteger modulus) {
        return base.modPow(exponent, modulus);
    }

    // Generate a random BigInteger between min and max
    private BigInteger randomBigInteger(BigInteger min, BigInteger max) {
        BigInteger range = max.subtract(min).add(BigInteger.ONE);
        int bitLength = range.bitLength();
        BigInteger result;
        do {
            result = new BigInteger(bitLength, secureRandom);
        } while (result.compareTo(range) >= 0);
        return result.add(min);
    }

    // Generate a valid prime number p
    private BigInteger generateValidP() {
        BigInteger p;
        do {
            p = new BigInteger(secureRandom.nextInt(129) + 128, certainty, secureRandom);
        } while (!isProbablePrime(p, 100));
        return p;
    }

    // Generate other parameters
    private void generateParameters() {
        q = generateValidQ(p);
        g = generateValidG(p, q);
        a = modPow(g, p.subtract(BigInteger.ONE).divide(q), p);
        x = generateValidX(p, q, g);
        d = modPow(a, x, p);
        k = generateValidK(p, x, q, g);
    }

    // Encryption method
    public String encrypt(String plaintext) {
        byte[] bytes = plaintext.getBytes(StandardCharsets.UTF_16);
        String base64 = Base64.getEncoder().encodeToString(bytes);
        
        StringBuilder c1Builder = new StringBuilder();
        StringBuilder c2Builder = new StringBuilder();

        for (char ch : base64.toCharArray()) {
            BigInteger m = BigInteger.valueOf((int) ch);
            BigInteger c1 = modPow(a, k, p);
            BigInteger c2 = m.multiply(modPow(d, k, p)).mod(p);

            c1Builder.append(c1).append(",");
            c2Builder.append(c2).append(";");
        }

        this.c1 = c1Builder.toString().trim();
        this.c2 = c2Builder.toString().trim();

        String ciphertext = c1Builder.toString() + "|" + c2Builder.toString();
        return Base64.getEncoder().encodeToString(ciphertext.getBytes(StandardCharsets.UTF_16));
    }

    // Decryption method
    public String decrypt(String ciphertext) {
        byte[] decodedBytes = Base64.getDecoder().decode(ciphertext);
        String decodedText = new String(decodedBytes, StandardCharsets.UTF_16);
        
        String[] parts = decodedText.split("\\|");
        String[] c1Parts = parts[0].split(",");
        String[] c2Parts = parts[1].split(";");

        StringBuilder decryptedBuilder = new StringBuilder();

        for (int i = 0; i < c1Parts.length; i++) {
            BigInteger c1 = new BigInteger(c1Parts[i]);
            BigInteger c2 = new BigInteger(c2Parts[i]);

            BigInteger s = modPow(c1, p.subtract(BigInteger.ONE).subtract(x), p);
            BigInteger m = c2.multiply(s).mod(p);

            decryptedBuilder.append((char) m.intValue());
        }

        byte[] decryptedBytes = Base64.getDecoder().decode(decryptedBuilder.toString());
        return new String(decryptedBytes, StandardCharsets.UTF_16);
    }

    // Main method for testing
    public static void main(String[] args) {
        ElGamalEncryption elGamal = new ElGamalEncryption();
        elGamal.p = elGamal.generateValidP();
        elGamal.generateParameters();

        String plaintext = "Hello, ElGamal Encryption!";
        System.out.println("Original: " + plaintext);

        String encrypted = elGamal.encrypt(plaintext);
        System.out.println("Encrypted: " + encrypted);

        String decrypted = elGamal.decrypt(encrypted);
        System.out.println("Decrypted: " + decrypted);
    }
}
