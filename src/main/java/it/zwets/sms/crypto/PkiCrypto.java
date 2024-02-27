package it.zwets.sms.crypto;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.spec.AlgorithmParameterSpec;
import java.security.spec.MGF1ParameterSpec;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.CipherInputStream;
import javax.crypto.CipherOutputStream;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.OAEPParameterSpec;
import javax.crypto.spec.PSource;
import javax.crypto.spec.SecretKeySpec;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Encryption and decryption using public and private keys.
 * 
 * Plaintext is encrypted with a randomly generated secret symmetric key.
 * This key is encrypted with a public key and prepended to the ciphertext.
 * 
 * Upon decryption, the prepended key is read and decrypted with the private
 * key, and then used to decrypt the actual ciphertext.
 *
 * The crypto algorithms and parameters are the same as used in OdkCrypto.
 * The difference is only that ODK uses an additional parameter (instance ID),
 * and transports the PKI encrypted key separately from the ciphertext.
 */
public class PkiCrypto {
    
    private static Logger LOG = LoggerFactory.getLogger(PkiCrypto.class);

    // Size of the generated symmetric key in bytes
    private static final int KEY_SIZE = 256 / 8; // for AES

    // Parameters for the RSA encryption of the symmetric secret
    private static final String ASYMMETRIC_ALGORITHM = "RSA/ECB/OAEPWithSHA-256AndMGF1Padding";
    private static final AlgorithmParameterSpec ASYMMETRIC_PARAMETERS = new OAEPParameterSpec(
            "SHA-256", "MGF1", MGF1ParameterSpec.SHA256, PSource.PSpecified.DEFAULT);

    // Parameters for the symmetric encryption
    private static final String SYMMETRIC_ALGORITHM = "AES/CFB/PKCS5Padding";
    private static final String SYMMETRIC_KEYTYPE = "AES";
    private static final int IV_LENGTH = 16;

    // Magic bits to check that it is ciphertext generated by us.  Could be any
    // value, but these 18 bits give 'ENC' in base64, for ease of recognition.
    private static final int MAGIC = 0b000100001101000010;
    private static final int MAGIC_BITS = 18; // count the MAGIC

    // For generating a new symmetric key for every encryption
    private static SecureRandom SECURE_RANDOM = new SecureRandom();
    
    /**
     * Encrypt plaintext with a public key.
     * 
     * @param pubkey public key for encrypting the random symmetric key
     * @param plaintext the bytes to encode
     * @return byte array with the encrypted symmetric key followed by the ciphertext
     */
    public static byte[] encrypt(final PublicKey pubkey, final byte[] plaintext) {
        return new Encryptor(pubkey).encrypt(plaintext);
    }

    /**
     * Decrypt ciphertext with a private key.
     * 
     * @param privkey the private key for decrypting the symmetric key
     * @param ciphertext the encrypted symmetric key followed by the ciphertext
     * @return the decrypted payload
     */
    public static byte[] decrypt(final PrivateKey privkey, final byte[] ciphertext) {
        return new Decryptor(privkey).decrypt(ciphertext);
    }

    /**
     * Encryptor for the holder of the private key paired with the given public key.
     */
    public static final class Encryptor {

        private final PublicKey pubkey;

        /**
         * Create an encryptor for the specified public key.
         * @param pubkey
         */
        public Encryptor(PublicKey pubkey) {
            this.pubkey = pubkey;
        }

        /**
         * Encrypt content from is to ciphertext on os.
         * 
         * @param is an open {@link OutputStream}
         * @param os an open {@link InputStream}
         * @throws RuntimeException for any underlying exception
         */
        public void encrypt(InputStream is, OutputStream os) {
            LOG.debug("encrypting input stream");

            // Generate a new random key of KEY_SIZE
            byte[] key = new byte[KEY_SIZE];
            SECURE_RANDOM.nextBytes(key);

            // Encrypt the random key with the public key
            byte[] encKey = pkiEncrypt(pubkey, key);

            // Write the MAGIC and encrypted key
            writeHeader(os, encKey);

            // Encrypt the payload onto the output stream
            try (CipherOutputStream cos = new CipherOutputStream(os, getSymmetricCipher(Cipher.ENCRYPT_MODE, key))) {
                LOG.debug("write the ciphertext to the output stream");
                is.transferTo(cos);
                is.close();
            }
            catch (IOException e) {
                LOG.error("Failed to encrypt to output stream: {}", e);
                throw new RuntimeException("Failed to encrypt stream: %s".formatted(e.getMessage()), e);
            }
        }
        
        /**]
         * Encrypt plaintext to ciphertext
         * 
         * @param plaintext the payload to encode
         * @return the pk-encrypted key followed by the actual ciphertext
         */
        public byte[] encrypt(final byte[] plaintext) {
            LOG.debug("encrypting plaintext byte array");
            ByteArrayInputStream bis = new ByteArrayInputStream(plaintext);
            ByteArrayOutputStream bos = new ByteArrayOutputStream();
            encrypt(bis, bos);
            return bos.toByteArray();
        }
    };

    /**
     * Decryptor.
     */
    public static final class Decryptor {

        private final PrivateKey privateKey;

        /**
         * Create decryptor for the given privkey.
         * @param privkey the private key of the reciptient
         */
        public Decryptor(final PrivateKey privkey) {
            this.privateKey = privkey;
        }

        /**
         * Decrypt ciphertext from is to plaintext on os.
         *
         * @param is an open {@link InputStream}
         * @param os an open {@link OutputStream}
         */
        public void decrypt(InputStream is, OutputStream os) {
            LOG.debug("decrypting input stream");
            
            // Read the MAGIC header and decrypt the symmetric key
            byte[] encKey = parseHeader(is);
            byte[] key = pkiDecrypt(privateKey, encKey);

            try (CipherInputStream cis = new CipherInputStream(is, getSymmetricCipher(Cipher.DECRYPT_MODE, key))) {
                LOG.debug("decrypting the payload");
                cis.transferTo(os);
                cis.close();
            }
            catch (IOException e) {
                throw new RuntimeException("Failed to decrypt the ciphertext: %s".formatted(e.getMessage()), e);
            }
        }
        
        /**
         * Decrypt ciphertext to plaintext..
         * 
         * @param ciphertext the payload to decrypt
         * @return plaintext
         */
        public byte[] decrypt(final byte[] ciphertext) {
            LOG.debug("decrypting ciphertext from byte array");
            ByteArrayInputStream bis = new ByteArrayInputStream(ciphertext);
            ByteArrayOutputStream bos = new ByteArrayOutputStream();
            decrypt(bis, bos);
            return bos.toByteArray();
        }
    };

    /**
     * Helper to encrypt (a limited amount of) plaintext with a public key.
     * @param key the public key
     * @param plaintext the input
     * @return the ciphertext
     */
    private static byte[] pkiEncrypt(final PublicKey key, final byte[] plaintext)
    {
        try {
            Cipher cipher = Cipher.getInstance(ASYMMETRIC_ALGORITHM);
            cipher.init(Cipher.ENCRYPT_MODE, key, ASYMMETRIC_PARAMETERS);
            return cipher.doFinal(plaintext);
        } catch (NoSuchAlgorithmException | NoSuchPaddingException | InvalidKeyException | IllegalBlockSizeException | BadPaddingException | InvalidAlgorithmParameterException e) {
            throw new RuntimeException("PKI error during encryption: %s".formatted(e.getMessage()), e);
        }
    }

    /**
     * Helper to decrypt a ciphertext with a private key.
     * @param key the private key
     * @param ciphertext the input
     * @return the plaintext
     */
    private static byte[] pkiDecrypt(final PrivateKey key, final byte[] ciphertext) 
    {
        try {
            Cipher cipher = Cipher.getInstance(ASYMMETRIC_ALGORITHM);
            cipher.init(Cipher.DECRYPT_MODE, key, ASYMMETRIC_PARAMETERS);
            return cipher.doFinal(ciphertext);
        } catch (NoSuchAlgorithmException | NoSuchPaddingException | InvalidKeyException | IllegalBlockSizeException | BadPaddingException | InvalidAlgorithmParameterException e) {
            throw new RuntimeException("PKI error during decryption: %s".formatted(e.getMessage()), e);
        }
    }
    
    /**
     * Generates a new symmetric cipher based on key material.
     * @param mode Cipher.ENCRYPT or Cipher.DECRIPT
     * @param key the key material
     * @return the initialised symmetic cipher
     */
    private static Cipher getSymmetricCipher(int mode, final byte[] key) {
        LOG.debug("producing new symmetric encryption cipher");
        try {
            Cipher cipher = Cipher.getInstance(SYMMETRIC_ALGORITHM);
            cipher.init(mode,
                    new SecretKeySpec(key, SYMMETRIC_KEYTYPE), 
                    new IvParameterSpec(makeIV(key)));
            return cipher;
        } catch (NoSuchAlgorithmException | NoSuchPaddingException | InvalidKeyException | InvalidAlgorithmParameterException e) {
            throw new RuntimeException("Failed to create symmetric cipher: %s".formatted(e.getMessage()), e);
        }
    }
    
    /**
     * Creates an algorithm Initialisation Vector based on key material
     * @param key the key material
     * @return the IV_LENGTH sized IV
     */
    private static final byte[] makeIV(final byte[] key) {
        try {
            byte[] iv = new byte[IV_LENGTH];
            
            // Compute the MD5 of the key
            MessageDigest md = MessageDigest.getInstance("MD5");
            md.update(key);
            byte[] md5 = md.digest();
    
            // Fill the IV with the MD5
            for (int i = 0; i < IV_LENGTH; ++i) {
                iv[i] = md5[i % md5.length];
            }
            
            return iv;
        }
        catch (NoSuchAlgorithmException e) {
            throw new RuntimeException("Failed to create IV: %s".formatted(e.getMessage()), e);
        }
    }
    
    // Number of bits in the 4-bytes header after the MAGIC
    private static final int LOBITS = 32 - MAGIC_BITS;
    private static final int LOMASK = (1<<LOBITS) - 1;
    
    /**
     * Writes the MAGIC number and the enckey to os 
     * @param os the output stream to write to
     * @param enckey the encrypted symmetric key to write
     * @throws RuntimeException for any underlying exception
     */
    private static void writeHeader(OutputStream os, byte[] enckey) {
        LOG.debug("writing ciphertext header");
        
        if (enckey.length <= LOMASK) { // can encode up to 16 bits
            LOG.debug("write the 4-byte header");

            try {
                int header = (MAGIC << LOBITS) | (enckey.length & LOMASK);
                os.write(header >> 24);
                os.write(header >> 16);
                os.write(header >> 8);
                os.write(header);
                
                LOG.debug("write the {}-byte encrypted symmetric key", enckey.length);
                os.write(enckey);
            }
            catch (IOException e) {
                LOG.error("Failed to write header to output stream: {}", e);
                throw new RuntimeException("Failed to write header to output stream: %s".formatted(e.getMessage()), e);
            }
        }
        else {
            LOG.error("Encrypted key too large: {} bytes (max is {})", enckey.length, LOMASK);
            throw new RuntimeException("Encrypted key too large for format: %d bytes".formatted(enckey.length));
        }
    }
    
    /**
     * Parses the 4-byte header and variable length encrypted key off the stream.
     * 
     * @param is the input stream to read off
     * @return the PK encrypted symmetric key
     * @throws IOException from underlying operation
     * @throws RuntimeException if MAGIC not found or the encrypted key could not be read
     */
    private static byte[] parseHeader(InputStream is) {
        LOG.debug("parsing ciphertext header");
        
        try {
            byte[] b = is.readNBytes(4);                // 32 bit header
            int header = ((b[0]&0xFF) << 24) | ((b[1]&0xFF) << 16) | ((b[2]&0xFF) << 8) | (b[3]&0xFF);
            
            int magic = header >>> LOBITS;
            int encsz = header & LOMASK;
            
            if (magic != MAGIC) {
                throw new RuntimeException("Invalid ciphertext: MAGIC not found");
            }
            
            LOG.debug("reading the {}-byte encrypted symmetric key", encsz);
            byte[] enckey = is.readNBytes(encsz);
            if (enckey.length != encsz) {
                throw new RuntimeException("Failed to read the %d-byte encrypted symmetric key".formatted(encsz));
            }
            
            return enckey;
        }
        catch (IOException e) {
            LOG.error("Failed to read header from input stream: {}", e);
            throw new RuntimeException("Failed to read header from input stream: %s".formatted(e.getMessage()), e);
        }
    }
}
