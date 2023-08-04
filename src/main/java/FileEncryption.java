import javax.crypto.*;
import javax.crypto.spec.SecretKeySpec;
import java.io.*;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.*;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.concurrent.*;
import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;

public class FileEncryption {

    private static final String AES_ALGORITHM = "AES";
    private static final String RSA_ALGORITHM = "RSA";
    private static final int AES_KEY_SIZE = 128; // For AES, use 128, 192, or 256

    private static final ExecutorService executorService = Executors.newFixedThreadPool(2);

    public static void main(String[] args) {
        try {
            // Generate AES key for data encryption
            SecretKey aesKey = generateAESKey();

            // Read RSA public and private keys from files
            PublicKey publicKey = (PublicKey) readKeyFromFile("public_key.pem", true);
            PrivateKey privateKey = (PrivateKey) readKeyFromFile("private_key.pem", false);

            // Encrypt the file using AES in a separate thread
            String fileToEncrypt = "example.txt";
            byte[] data = Files.readAllBytes(Paths.get(fileToEncrypt));
            Future<byte[]> encryptedDataFuture = executorService.submit(() -> encryptAES(data, aesKey));

            // Encrypt the AES key using RSA public key in another separate thread
            Future<byte[]> encryptedAESKeyFuture = executorService.submit(() -> encryptAESKey(aesKey, publicKey));

            // Save the encrypted data and encrypted AES key to separate files
            try (FileOutputStream fos = new FileOutputStream(fileToEncrypt + ".enc");
                 ObjectOutputStream oos = new ObjectOutputStream(fos)) {
                oos.writeObject(encryptedDataFuture.get());
            }

            try (FileOutputStream fos = new FileOutputStream(fileToEncrypt + ".key");
                 ObjectOutputStream oos = new ObjectOutputStream(fos)) {
                oos.writeObject(encryptedAESKeyFuture.get());
            }

            // For decryption, read the encrypted AES key from the ".key" file
            try (FileInputStream fis = new FileInputStream(fileToEncrypt + ".key");
                 ObjectInputStream ois = new ObjectInputStream(fis)) {
                byte[] encryptedAESKeyFromFile = (byte[]) ois.readObject();
                SecretKey decryptedAESKey = decryptAESKey(encryptedAESKeyFromFile, privateKey);

                // Decrypt the data using AES and the decrypted AES key
                byte[] encryptedDataFromFile = Files.readAllBytes(Paths.get(fileToEncrypt + ".enc"));
                byte[] decryptedData = decryptAES(encryptedDataFromFile, decryptedAESKey);

                // Save the decrypted data to a new file
                try (FileOutputStream fos = new FileOutputStream(fileToEncrypt + ".decrypted")) {
                    fos.write(decryptedData);
                }
            }

            // Shutdown the executor service
            executorService.shutdown();

        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    // Generate AES key for data encryption
    private static SecretKey generateAESKey() throws NoSuchAlgorithmException {
        KeyGenerator keyGenerator = KeyGenerator.getInstance(AES_ALGORITHM);
        keyGenerator.init(AES_KEY_SIZE);
        return keyGenerator.generateKey();
    }

    // Read a key file and extract the RSA public or private key
    private static Key readKeyFromFile(String keyPath, boolean isPublic) throws IOException, GeneralSecurityException {
        byte[] keyBytes = Files.readAllBytes(Paths.get(keyPath));
        KeyFactory keyFactory = KeyFactory.getInstance(RSA_ALGORITHM);

        if (isPublic) {
            X509EncodedKeySpec spec = new X509EncodedKeySpec(keyBytes);
            return keyFactory.generatePublic(spec);
        } else {
            PKCS8EncodedKeySpec spec = new PKCS8EncodedKeySpec(keyBytes);
            return keyFactory.generatePrivate(spec);
        }
    }

    // Decrypt AES key using RSA private key
    private static SecretKey decryptAESKey(byte[] encryptedKey, PrivateKey privateKey) throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException {
        Cipher cipher = Cipher.getInstance(RSA_ALGORITHM);
        cipher.init(Cipher.DECRYPT_MODE, privateKey);
        byte[] decryptedKeyBytes = cipher.doFinal(encryptedKey);
        return new SecretKeySpec(decryptedKeyBytes, AES_ALGORITHM);
    }

    // Decrypt data using AES
    private static byte[] decryptAES(byte[] encryptedData, SecretKey key) throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, InvalidAlgorithmParameterException, IllegalBlockSizeException, BadPaddingException {
        Cipher cipher = Cipher.getInstance("AES/ECB/PKCS5Padding");
        cipher.init(Cipher.DECRYPT_MODE, key);
        return cipher.doFinal(encryptedData);
    }

    // Encrypt data using AES
    private static byte[] encryptAES(byte[] data, SecretKey key) throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException {
        Cipher cipher = Cipher.getInstance("AES/ECB/PKCS5Padding");
        cipher.init(Cipher.ENCRYPT_MODE, key);
        return cipher.doFinal(data);
    }

    // Encrypt AES key using RSA public key
    private static byte[] encryptAESKey(SecretKey aesKey, PublicKey publicKey) throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException {
        Cipher cipher = Cipher.getInstance(RSA_ALGORITHM);
        cipher.init(Cipher.ENCRYPT_MODE, publicKey);
        return cipher.doFinal(aesKey.getEncoded());
    }
}
