package com.rsa;

import java.math.BigInteger;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.List;
import java.util.Scanner;

public class RSACryptography {

    private static final int BIT_LENGTH = 1024;

    static record RSAKeyPair(RSAKey publicKey, RSAKey privateKey) { }

    static record RSAKey(BigInteger n, BigInteger exponent) {
        @Override
        public String toString() {
            return String.format("(%s, %s)", n, exponent);
        }
    }

    private static final SecureRandom random = new SecureRandom();

    public static void main(String[] args) {
        Scanner scanner = new Scanner(System.in);

        System.out.println("------------ CRIPTOGRAFIA RSA -------------\n");
        System.out.print("Insira a mensagem a ser criptografada: ");
        String message = scanner.nextLine();

        processMessage(message);

        scanner.close();
    }

    public static void processMessage(String message) {
        System.out.println("\n--- PROCESSANDO MENSAGEM ---\n");

        System.out.println(" > Convertendo mensagem para ASCII");
        List<Integer> asciiValues = convertToASCII(message);
        System.out.println("Mensagem original: " + message);
        System.out.println("Valor em ASCII: " + asciiValues);

        System.out.println("\n > Gerando chave RSA");
        RSAKeyPair keyPair = generateKeys();
        RSAKey publicKey = keyPair.publicKey();
        RSAKey privateKey = keyPair.privateKey();

        System.out.println("Chave publica (n, e): " + publicKey);
        System.out.println("\nChave privada (n, d): " + privateKey);

        System.out.println("\n > Encriptando mensagem");
        List<BigInteger> encryptedMessage = encrypt(asciiValues, publicKey);
        System.out.println("Mensagem encriptada: " + encryptedMessage);

        System.out.println("\n > Decriptando mensagem");
        List<Integer> decryptedValues = decrypt(encryptedMessage, privateKey);
        System.out.println("Mensagem ASCII decriptada: " + decryptedValues);

        String decryptedMessage = convertToText(decryptedValues);
        System.out.println(" > Mensagem final: " + decryptedMessage);

        System.out.println("\n--- VERIFICAÇÃO ---");
        System.out.println("Mensagem original == Mensagem decriptada: " + message.equals(decryptedMessage));
    }

    public static List<Integer> convertToASCII(String text) {
        List<Integer> ascii = new ArrayList<>();

        for (char character : text.toCharArray()) {
            ascii.add((int) character);
        }

        return ascii;
    }

    public static String convertToText(List<Integer> asciiValues) {
        StringBuilder text = new StringBuilder();
        for (int value : asciiValues) {
            text.append((char) value);
        }
        return text.toString();
    }

    public static RSAKeyPair generateKeys() {
        BigInteger p = generateLargePrime();
        BigInteger q = generateLargePrime();

        while (p.equals(q)) {
            q = generateLargePrime();
        }

        // n = p * q
        BigInteger n = p.multiply(q);

        // φ(n) = (p-1) * (q-1)
        BigInteger phi = p.subtract(BigInteger.ONE).multiply(q.subtract(BigInteger.ONE));

        BigInteger e = generateLargePrime();

        // 1 < e < φ(n)
        // MDC de φ(n) com 'e' == 1
        while (
            phi.compareTo(e) <= 0  ||
            !phi.gcd(e).equals(BigInteger.ONE) // gcd = Máximo Divisor Comum (MDC)
        ) {
            e = generateLargePrime();
        }

        // d * e ≡ 1 (mod φ(n))
        BigInteger d = e.modInverse(phi);

        RSAKey publicKey = new RSAKey(n, e);
        RSAKey privateKey = new RSAKey(n, d);

        return new RSAKeyPair(publicKey, privateKey);
    }

    public static BigInteger generateLargePrime() {
        return BigInteger.probablePrime(BIT_LENGTH, random);
    }

    public static List<BigInteger> encrypt(List<Integer> values, RSAKey publicKey) {
        List<BigInteger> result = new ArrayList<>();

        for (int value : values) {
            // c = m^e mod n
            BigInteger m = BigInteger.valueOf(value);
            BigInteger c = m.modPow(publicKey.exponent(), publicKey.n());
            result.add(c);
        }

        return result;
    }

    public static List<Integer> decrypt(List<BigInteger> encryptedValues, RSAKey privateKey) {
        List<Integer> result = new ArrayList<>();

        for (BigInteger encryptedValue : encryptedValues) {
            // m = c^d mod n
            BigInteger m = encryptedValue.modPow(privateKey.exponent(), privateKey.n());
            result.add(m.intValue());
        }

        return result;
    }
}