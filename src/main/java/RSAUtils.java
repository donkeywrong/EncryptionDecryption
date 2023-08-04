import org.bouncycastle.asn1.pkcs.EncryptedPrivateKeyInfo;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
import org.bouncycastle.asn1.pkcs.RSAPrivateKey;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.openssl.PEMEncryptedKeyPair;
import org.bouncycastle.openssl.PEMKeyPair;
import org.bouncycastle.openssl.PEMParser;
import org.bouncycastle.openssl.PEMWriter;
import org.bouncycastle.openssl.jcajce.JcaPEMKeyConverter;
import org.bouncycastle.openssl.jcajce.JcePEMDecryptorProviderBuilder;
import org.bouncycastle.openssl.jcajce.JcePEMEncryptorBuilder;
import org.bouncycastle.pkcs.jcajce.JcePKCSPBEOutputEncryptorBuilder;


import javax.crypto.Cipher;
import java.io.*;
import java.security.*;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;

public class RSAUtils {
    private static final String RSA_ALGORITHM = "RSA";

    /**
     * Generates an RSA key pair with the specified key size.
     *
     * @param keySize The size of the key, in bits.
     * @return KeyPair object containing the generated RSA public and private keys.
     * @throws NoSuchProviderException If the Bouncy Castle provider is not available.
     * @throws NoSuchAlgorithmException If the RSA algorithm is not supported.
     */
    public static KeyPair generateRSAKeyPair(int keySize) throws NoSuchProviderException, NoSuchAlgorithmException {
        // Add Bouncy Castle provider to the security provider list
        Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());

        // Generate RSA key pair using Bouncy Castle provider
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance(RSA_ALGORITHM, "BC");
        keyPairGenerator.initialize(keySize);
        return keyPairGenerator.generateKeyPair();
    }

    /**
     * Loads an RSA public key from a PEM file.
     *
     * @param filename The path to the PEM file containing the RSA public key.
     * @return PublicKey object representing the RSA public key.
     * @throws IOException            If an I/O error occurs while reading the file.
     * @throws NoSuchAlgorithmException If the RSA algorithm is not supported.
     */
    public static PublicKey loadPublicKey(String filename) throws IOException, NoSuchAlgorithmException {
        try (PEMParser pemParser = new PEMParser(new FileReader(filename))) {
            // Read the PEM file and parse it as SubjectPublicKeyInfo
            SubjectPublicKeyInfo publicKeyInfo = (SubjectPublicKeyInfo) pemParser.readObject();
            byte[] publicKeyBytes = publicKeyInfo.getEncoded();

            // Convert the public key bytes to a PublicKey object
            X509EncodedKeySpec spec = new X509EncodedKeySpec(publicKeyBytes);
            KeyFactory keyFactory = KeyFactory.getInstance(RSA_ALGORITHM);
            try {
                return keyFactory.generatePublic(spec);
            } catch (InvalidKeySpecException e) {
                throw new RuntimeException("Error while generating the RSA public key", e);
            }
        }
    }

    /**
     * Loads an RSA private key from a PEM file.
     *
     * @param filename The path to the PEM file containing the RSA private key.
     * @return PrivateKey object representing the RSA private key.
     * @throws IOException            If an I/O error occurs while reading the file.
     * @throws NoSuchAlgorithmException If the RSA algorithm is not supported.
     * @throws NoSuchProviderException  If the Bouncy Castle provider is not available.
     */
    public static PrivateKey loadPrivateKey(String filename) throws IOException, NoSuchAlgorithmException, NoSuchProviderException {
        try (PEMParser pemParser = new PEMParser(new FileReader(filename))) {
            // Read the PEM file and parse it as PEMKeyPair
            PEMKeyPair pemKeyPair = (PEMKeyPair) pemParser.readObject();

            // Create a PEM key converter
            JcaPEMKeyConverter converter = new JcaPEMKeyConverter().setProvider("BC");

            // Convert the PEM key pair to a PrivateKey object
            return converter.getPrivateKey(pemKeyPair.getPrivateKeyInfo());
        }
    }

    /**
     * Encrypts data using an RSA public key.
     *
     * @param data      The data to be encrypted.
     * @param publicKey The RSA public key.
     * @return The encrypted data.
     * @throws Exception If encryption fails due to invalid key or padding issues.
     */
    public static byte[] encryptRSA(byte[] data, PublicKey publicKey) throws Exception {
        Cipher cipher = Cipher.getInstance(RSA_ALGORITHM);
        cipher.init(Cipher.ENCRYPT_MODE, publicKey);
        return cipher.doFinal(data);
    }

    /**
     * Decrypts data using an RSA private key.
     *
     * @param encryptedData The data to be decrypted.
     * @param privateKey    The RSA private key.
     * @return The decrypted data.
     * @throws Exception If decryption fails due to invalid key or padding issues.
     */
    public static byte[] decryptRSA(byte[] encryptedData, PrivateKey privateKey) throws Exception {
        Cipher cipher = Cipher.getInstance(RSA_ALGORITHM);
        cipher.init(Cipher.DECRYPT_MODE, privateKey);
        return cipher.doFinal(encryptedData);
    }

    /**
     * Encrypts an RSA private key using a password.
     *
     * @param privateKey The RSA private key to be encrypted.
     * @param password   The password to encrypt the private key.
     * @return The encrypted RSA private key bytes.
     * @throws Exception If encryption fails due to invalid key or password issues.
     */
    public static byte[] encryptRSAPrivateKey(PrivateKey privateKey, char[] password) throws Exception {
        // Convert the private key to PrivateKeyInfo
        PrivateKeyInfo privateKeyInfo = PrivateKeyInfo.getInstance(privateKey.getEncoded());

        // Create an AES-256-CFB encryptor for the PKCS#8 private key
        JcePKCS8EncryptorBuilder encryptorBuilder = new JcePKCS8EncryptorBuilder(org.bouncycastle.asn1.x509.AlgorithmIdentifier.pbeWithSHA256And256BitAESBC);
        encryptorBuilder.setProvider("BC");
        encryptorBuilder.setPasssword(password);

        // Encrypt the PKCS#8 private key using PBE with SHA-256 and AES-256-CFB
        JcePKCSPBEOutputEncryptorBuilder pkcsEncryptorBuilder = encryptorBuilder.build();
        EncryptedPrivateKeyInfo encryptedPrivateKeyInfo = pkcsEncryptorBuilder.encrypt(privateKeyInfo.getEncoded());

        return encryptedPrivateKeyInfo.getEncoded();
    }



    /**
     * Decrypts an encrypted RSA private key using a password.
     *
     * @param encryptedPrivateKey The encrypted RSA private key bytes.
     * @param password            The password to decrypt the private key.
     * @return The decrypted RSA private key.
     * @throws Exception If decryption fails due to invalid key or password issues.
     */
    public static PrivateKey decryptRSAPrivateKey(byte[] encryptedPrivateKey, char[] password) throws Exception {
        // Create a PEM key converter
        JcaPEMKeyConverter converter = new JcaPEMKeyConverter().setProvider("BC");

        // Parse the encrypted PEM key pair
        PEMKeyPair pemKeyPair;
        try (PEMParser pemParser = new PEMParser(new InputStreamReader(new ByteArrayInputStream(encryptedPrivateKey)))) {
            // Read the PEM key pair from the parser (could be PEMEncryptedKeyPair or PEMKeyPair)
            Object object = pemParser.readObject();
            if (object instanceof PEMKeyPair) {
                pemKeyPair = (PEMKeyPair) object;
            } else {
                pemKeyPair = ((PEMEncryptedKeyPair) object).decryptKeyPair(new JcePEMDecryptorProviderBuilder().build(password));
            }
        }

        // Get the private key from the PEM key pair
        return converter.getPrivateKey(pemKeyPair.getPrivateKeyInfo());
    }

}
