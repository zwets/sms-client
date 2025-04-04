package it.zwets.sms.crypto;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.nio.charset.StandardCharsets;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.spec.AlgorithmParameterSpec;
import java.security.spec.MGF1ParameterSpec;
import java.util.Base64;

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
 * Implements the encryption and decryption used by XForms/ODK/Kobo/Enketo.
 * 
 * The mechanism is that a submission is encrypted by generating a random
 * symmetric encryption key.  This, plus the instance ID of the submission,
 * and a sequence number is used in the encryption algorithm.
 * 
 * The secret key is encrypted with the public key of the recipient, and
 * the result plus the instance ID is sent along with the encrypted
 * submission.
 * 
 * For multi-part submissions, the instamce ID and secret key are the same
 * for all parts, but the IV of the AES algorithm is (predictably) changed
 * for each submission, using the sequence number.
 */
public class OdkCrypto {
    
    private static Logger LOG = LoggerFactory.getLogger(OdkCrypto.class);

    // Byte size of the generated symmetric key and its encrypted size
    public static final int KEY_SIZE = 256 / 8; // for AES
    public static final int ENC_KEY_SIZE = 256; // for RSA with SHA256
    
    // The parameters for the RSA encryption of the symmetric secret
    private static final String ASYMMETRIC_ALGORITHM = "RSA/ECB/OAEPWithSHA-256AndMGF1Padding";
    private static final AlgorithmParameterSpec ASYMMETRIC_PARAMETERS = new OAEPParameterSpec(
            "SHA-256", "MGF1", MGF1ParameterSpec.SHA256, PSource.PSpecified.DEFAULT);

    // Parameters for the AES symmetric encryption of the body
    private static final String SYMMETRIC_ALGORITHM = "AES/CFB/PKCS5Padding";
    private static final String SYMMETRIC_KEYTYPE = "AES";
    private static final int IV_LENGTH = 16;
    
    private static SecureRandom SECURE_RANDOM = new SecureRandom();
    
    /**
     * Result of the encryption.
     * 
     * The encryption produces two items to give to the recipient: the
     * ciphertext and the public-key-encrypted decryption key.  This record
     * has that pair.
     * 
     * Note that In addition to the private key, the recipient needs to know
     * the instance ID that was used at encryption..
     * 
     * @param b64key the base64 encoded public-key encrypted decryption key
     * @param ciphertext the encryped payload
     */
    public record OdkResult(String b64key, byte[] ciphertext) { }

    /**
     * Encrypt payload read from is to ciphertext on os, returning the key.
     * @param pubkey the public key to encrypt the symmetric key with
     * @param payload the bytes to encode
     * @param instance optional instance ID of the submission
     * @param seqnum the one-based sequence number of the message
     * @param is the inputstream to read plaintext from
     * @param os the outputstream to write ciphertext to
     * @return the base64 encoded public-key encrypted decryption key
     */
    public static String encrypt(PublicKey pubkey, String instance, int seqnum, InputStream is, OutputStream os) {
        Encryptor enc = new Encryptor(pubkey, instance, seqnum);
        enc.encrypt(is, os);
        return enc.getBase64Key();
    }

    /**
     * Encrypt payload using the ODK encryption algorithm.
     * 
     * @param pubkey the public key to encrypt the symmetric key with
     * @param payload the bytes to encode
     * @param instance optional instance ID of the submission
     * @param seqnum the one-based sequence number of the message
     * @return see the {#link {@link EncryptResult} docuentation
     */
    public static OdkResult encrypt(PublicKey pubkey, byte[] payload, String instance, int seqnum) {
        Encryptor enc = new Encryptor(pubkey, instance, seqnum);
        return new OdkResult(enc.getBase64Key(), enc.encrypt(payload));
    }

    /**
     * Decrypt the ciphertext on is to plaintext on os
     * @param privkey the private key to decrypt key
     * @param b64key the key returned by the encryption algorithm
     * @param ciphertext the encrypted submission
     * @param instance the instance used at encryption
     * @param seqnum the one-based sequence number of the message
     * @param is an open inputstream
     * @param os an open outputstrem
     */
    public static void decrypt(PrivateKey privkey, String b64key, String instance, int seqnum, InputStream is, OutputStream os) {
        new Decryptor(privkey, b64key, instance, seqnum).decrypt(is, os);
    }

    /**
     * Decrypt the ciphertext using the ODK decryption algorithm.
     * 
     * @param privkey the private key to decrypt key
     * @param b64key the key returned by the encryption algorithm
     * @param ciphertext the encrypted submission
     * @param instance the instance used at encryption
     * @param seqnum the one-based sequence number of the message
     * @return the decrypted payload
     */
    public static byte[] decrypt(PrivateKey privkey, String b64key, byte[] ciphertext, String instance, int seqnum) {
        return new Decryptor(privkey, b64key, instance, seqnum).decrypt(ciphertext);
    }

    /**
     * Encryptor for one or more payloads that are part of a submission.
     * 
     * The ODK specification (predictably) changes the IV between successive
     * encryptions in a multi-part submission using the sequence number of
     * the part.  The counter in this class holds the number of encryptions
     * that have been done so far.
     * 
     * All this means you should not reuse an instance of this class to
     * encrypt multiple <i>independent</i> submissions.
     */
    public static final class Encryptor {

        private final String base64Key;
        private final byte[] key;
        private final byte[] instance;
        private int counter;

        /**
         * Creates an ODK encryptor for a (possibly multi-part) submission,
         * starting at (default) sequence number 1.
         * 
         * @param pubkey the public key of the recipient
         * @param instance the instance ID of the submission
         */
        public Encryptor(PublicKey pubkey, String instance) {
            this(pubkey, instance, 1);
        }


        /**
         * Creates an ODK encryptor for a multi-part submission that starts
         * at a given sequence number.
         * 
         * @param pubkey the public key of the recipient
         * @param instance the instance ID of the submission
         * @param seqnum the sequence number to start with (default 1)
         */
        public Encryptor(PublicKey pubkey, String instance, int seqnum) {
            this.key = new byte[KEY_SIZE];
            SECURE_RANDOM.nextBytes(this.key);
            this.base64Key = Base64.getEncoder().encodeToString(pkiEncrypt(pubkey, key));
            this.instance = instance.getBytes(StandardCharsets.UTF_8);
            this.counter = seqnum - 1;  // counter gets bumped upon encryption
        }

        /**
         * Returns the base64 encoded PKI encrypted symmetric key
         * @return
         */
        public String getBase64Key() {
            return this.base64Key;
        }

        /**
         * Encrypt the content of is to os using the ODK algorithm.
         * 
         * Can be invoked multiple times, but note that you should only do this
         * for multi-part submissions, as the IV of the symmetric encryption
         * changes for every part.
         * 
         * @param is an open {@link InputStream}
         * @param os an open {@link OutputStream}
         */
        public void encrypt(InputStream is, OutputStream os) {
            try (CipherOutputStream cos =  new CipherOutputStream(os,newCipher())) {
                is.transferTo(cos);
                cos.close();
            }
            catch (IOException e) {
                throw new RuntimeException("Failed to encrypt the ciphertext: %s".formatted(e.getMessage()), e);
            }
        }
        
        /**
         * Encrypt plaintext with ODK algorithm.
         * 
         * Can be invoked multiple times, but note that you should only do this
         * for multi-part submissions, as the IV of the symmetric encryption
         * changes for every part.
         * 
         * @param payload the payload to encode
         * @return the ciphertext
         */
        public byte[] encrypt(byte[] plaintext) {
            try {
                return newCipher().doFinal(plaintext);
            }
            catch (IllegalBlockSizeException | BadPaddingException e) {
                throw new RuntimeException("Failed to encrypt the ciphertext: %s".formatted(e.getMessage()), e);
            }
        }

        // Generates cipher with a different IV on every invocation
        private Cipher newCipher() {
            ++this.counter;
            try {
                LOG.trace("creating new encryption cipher at counter: {}", this.counter);
                Cipher cipher = Cipher.getInstance(SYMMETRIC_ALGORITHM);
                cipher.init(Cipher.ENCRYPT_MODE, 
                        new SecretKeySpec(this.key, SYMMETRIC_KEYTYPE), 
                        new IvParameterSpec(odkIV(this.instance, this.key, this.counter)));
                return cipher;
            }
            catch (NoSuchAlgorithmException | NoSuchPaddingException | InvalidKeyException | InvalidAlgorithmParameterException e) {
                throw new RuntimeException("Failed to create new encryption cipher: %s".formatted(e.getMessage()), e);
            }
        }
    };

    /**
     * Decryptor for one or more payloads that are part of one submission.
     * 
     * Note that the ODK specification (predictably) changes the IV between
     * successive decryptions in a multi-part submission, so you should not
     * use a single instance of Decryptor for multiple <i>independent</i>
     * submissions.
     */
    public static final class Decryptor {

        private final byte[] key;
        private final byte[] instance;
        private int counter;

        /**
         * Create decryptor for a (possibly multi-part) submission, starting
         * at default sequence number 1.
         * 
         * @param privkey the private key of the reciptient
         * @param b64key the key returned by the encryptor
         * @param instance the submission instance ID or null
         */
        public Decryptor(final PrivateKey privkey, final String b64key, final String instance) {
            this(pkiDecrypt(privkey, Base64.getDecoder().decode(b64key)), instance, 1);
        }

        /**
         * Create decryptor for a (possibly multi-part) submission, starting
         * at a given sequence number (rather than 1).
         * 
         * @param privkey the private key of the reciptient
         * @param b64key the key returned by the encryptor
         * @param instance the submission instance ID or null
         * @param seqnum the sequence number to start at
         */
        public Decryptor(final PrivateKey privkey, final String b64key, final String instance, int seqnum) {
            this(pkiDecrypt(privkey, Base64.getDecoder().decode(b64key)), instance, seqnum);
        }

        /**
         * Create decryptor for a (possibly multi-part) submission, starting
         * at a given sequence number (rather than 1)
         * @param symkey the bytes of the symmetric key
         * @param instance the submitssion instance ID
         * @param seqnum the sequence number to start at
         */
        public Decryptor(final byte[] symkey, final String instance, int seqnum) {
            this.key = symkey;
            this.instance = instance == null ? new byte[] {} : instance.getBytes(StandardCharsets.UTF_8);
            this.counter = seqnum - 1;  // gets bumped before each decryption
        }

        /**
         * Decrypt the ciphertext read from is to plaintext on os.
         * 
         * Can be invoked multiple times, but do this only for multi-part
         * submissions, and in the order they were encrypted, as the ODK spec
         * changes the IV for each next encryption.
         * 
         * @param is an open {@link InputStream}
         * @param os an open {@link OutputStream}
         */
        public void decrypt(InputStream is, OutputStream os) {
            try (CipherInputStream cis = new CipherInputStream(is, newCipher())) {
                cis.transferTo(os);
                cis.close();
            }
            catch (IOException e) {
                throw new RuntimeException("Failed to decrypt the ciphertext: %s".formatted(e.getMessage()), e);
            }
        }
        
        /**
         * Decrypt payload using the ODK algorithm.
         * 
         * Can be invoked multiple times, but do this only for multi-part
         * submissions, and in the order they were encrypted, as the ODK spec
         * changes the IV for each next encryption.
         * 
         * @param ciphertext the payload to decrypt
         * @return see the {@link EncryptResult} documentation
         */
        public byte[] decrypt(byte[] ciphertext) {
            try {
                return newCipher().doFinal(ciphertext);
            }
            catch (IllegalBlockSizeException | BadPaddingException e) {
                throw new RuntimeException("Failed to decrypt the ciphertext: %s".formatted(e.getMessage()), e);
            }
        }

        // Generates a new cipher with a different IV on every call
        private Cipher newCipher() {
            ++this.counter;
            LOG.trace("creating new decryption Cipher at counter: {}", this.counter);
            try {
                Cipher cipher = Cipher.getInstance(SYMMETRIC_ALGORITHM);
                cipher.init(Cipher.DECRYPT_MODE, 
                        new SecretKeySpec(this.key, SYMMETRIC_KEYTYPE), 
                        new IvParameterSpec(odkIV(this.instance, this.key, this.counter)));
                return cipher;
            }
            catch (NoSuchAlgorithmException | NoSuchPaddingException | InvalidKeyException | InvalidAlgorithmParameterException e) {
                throw new RuntimeException("Failed to create new decryption cipher: %s".formatted(e.getMessage()), e);
            }
        }
    };

    private static byte[] pkiEncrypt(PublicKey key, byte[] plaintext)
    {
        try {
            Cipher cipher = Cipher.getInstance(ASYMMETRIC_ALGORITHM);
            cipher.init(Cipher.ENCRYPT_MODE, key, ASYMMETRIC_PARAMETERS);  
            return cipher.doFinal(plaintext);
        }
        catch (NoSuchAlgorithmException | NoSuchPaddingException | InvalidKeyException | IllegalBlockSizeException | BadPaddingException | InvalidAlgorithmParameterException e) {
            throw new RuntimeException("PKI error during encryption: %s".formatted(e.getMessage()), e);
        }
    }

    private static byte[] pkiDecrypt(PrivateKey key, byte[] ciphertext) 
    {
        try {
            Cipher cipher = Cipher.getInstance(ASYMMETRIC_ALGORITHM);
            cipher.init(Cipher.DECRYPT_MODE, key, ASYMMETRIC_PARAMETERS);
            return cipher.doFinal(ciphertext);
        }
        catch (NoSuchAlgorithmException | NoSuchPaddingException | InvalidKeyException | IllegalBlockSizeException | BadPaddingException | InvalidAlgorithmParameterException e) {
            throw new RuntimeException("PKI error during decryption: %s".formatted(e.getMessage()), e);
        }
    }
    
    // returns IV initialised according to the ODK specification:
    // the MD5 of instance and symkey, bumped seqnum times
    private static final byte[] odkIV(final byte[] instance, final byte[] key, int seqnum) {
        try {
            byte[] iv = new byte[IV_LENGTH];
            
            // the seed IV is the MD5 of the instance and symkey
            MessageDigest md = MessageDigest.getInstance("MD5");
            md.update(instance);
            md.update(key);
            byte[] md5 = md.digest();
    
            // fill the IV with the MD5
            for (int i = 0; i < IV_LENGTH; ++i) {
                iv[i] = md5[i % md5.length];
            }
            
            // bump the array to match the seqnum
            for (int i = 0; i < seqnum; ++i) {
                ++iv[i % iv.length];
            }
            
            return iv;
        }
        catch (NoSuchAlgorithmException e) {
            throw new RuntimeException("Failed to create IV: %s".formatted(e.getMessage()), e);
        }
    }
}
