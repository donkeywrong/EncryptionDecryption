import javax.crypto.*;
import javax.crypto.spec.SecretKeySpec;
import java.io.*;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.*;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

public class FileEncryptionWithMultithreading {
    private static final String AES_ALGORITHM = "AES";
    private static final int THREAD_POOL_SIZE = 4; // Number of threads for encryption and decryption

    public static void main(String[] args) {
        String publicKeyFile = "public_key.pem"; // Replace with your RSA public key file path
        String privateKeyFile = "private_key.pem"; // Replace with your RSA private key file path
        String inputFile = "input.txt"; // Replace with the file you want to encrypt/decrypt
        String encryptedFile = "encrypted.txt";
        String decryptedFile = "decrypted.txt";

        try {
            // Load RSA public and private keys from PEM files
            PublicKey publicKey = RSAUtils.loadPublicKey(publicKeyFile);
            PrivateKey privateKey = RSAUtils.loadPrivateKey(privateKeyFile);

            // Generate AES key
            KeyGenerator keyGen = KeyGenerator.getInstance(AES_ALGORITHM);
            keyGen.init(128); // AES key size can be 128, 192, or 256 bits
            SecretKey secretKey = keyGen.generateKey();

            // Encrypt AES key using RSA public key
            byte[] encryptedAESKey = RSAUtils.encryptRSA(secretKey.getEncoded(), publicKey);

            // Save the encrypted AES key to a file
            FileOutputStream keyOutputStream = new FileOutputStream("encrypted_aes_key.bin");
            keyOutputStream.write(encryptedAESKey);
            keyOutputStream.close();

            // Create a thread pool for encryption and decryption
            ExecutorService executor = Executors.newFixedThreadPool(THREAD_POOL_SIZE);

            // Encrypt file using AES with multithreading
            executor.execute(() -> {
                try {
                    encryptFileAES(inputFile, encryptedFile, secretKey);
                } catch (Exception e) {
                    e.printStackTrace();
                }
            });

            // Decrypt file using AES with multithreading
            executor.execute(() -> {
                try {
                    decryptFileAES(encryptedFile, decryptedFile, secretKey);
                } catch (Exception e) {
                    e.printStackTrace();
                }
            });

            // Shutdown the executor
            executor.shutdown();
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    private static void encryptFileAES(String inputFile, String outputFile, SecretKey secretKey) throws Exception {
        // Read input file
        byte[] inputBytes = Files.readAllBytes(Paths.get(inputFile));

        // Encrypt using AES
        Cipher cipher = Cipher.getInstance(AES_ALGORITHM);
        cipher.init(Cipher.ENCRYPT_MODE, secretKey);
        byte[] encryptedBytes = cipher.doFinal(inputBytes);

        // Write encrypted data to the output file
        FileOutputStream outputStream = new FileOutputStream(outputFile);
        outputStream.write(encryptedBytes);
        outputStream.close();

        System.out.println("File encrypted successfully using AES.");
    }

    private static void decryptFileAES(String inputFile, String outputFile, SecretKey secretKey) throws Exception {
        // Read encrypted data from the input file
        byte[] encryptedBytes = Files.readAllBytes(Paths.get(inputFile));

        // Decrypt using AES
        Cipher cipher = Cipher.getInstance(AES_ALGORITHM);
        cipher.init(Cipher.DECRYPT_MODE, secretKey);
        byte[] decryptedBytes = cipher.doFinal(encryptedBytes);

        // Write decrypted data to the output file
        FileOutputStream outputStream = new FileOutputStream(outputFile);
        outputStream.write(decryptedBytes);
        outputStream.close();

        System.out.println("File decrypted successfully using AES.");
    }
}
