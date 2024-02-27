package it.zwets.sms.crypto;

import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;

/**
 * General helpers for PKI.
 * @author io@zwets.it
 */
public class PkiUtils {

	/**
	 * Read public key from bytes.
	 * 
	 * @param bytes byte array with the DER format key
     * @return the {@link PublicKey}
	 * @throws RuntimeException for any of the underlying exceptions
	 */
    public static PublicKey readPublicKey(byte[] bytes) {
        try {
            X509EncodedKeySpec publicSpec = new X509EncodedKeySpec(bytes, "RSA");
            KeyFactory keyFactory = KeyFactory.getInstance("RSA");
            return keyFactory.generatePublic(publicSpec);       
        } catch (NoSuchAlgorithmException | InvalidKeySpecException e) {
            throw new RuntimeException("PKI error reading public key: %s".formatted(e.getMessage()), e);
        }
    }

    /**
     * Read public key from an input stream.
     * @param is the input stream
     * @return the public key
     * @throws RuntimeException for any of the underlying exceptions
     */
    public static PublicKey readPublicKey(InputStream is) {
        try {
            return readPublicKey(is.readAllBytes());
        } catch (IOException e) {
            throw new RuntimeException("Failed to read public key from stream: %s".formatted(e.getMessage()), e);
        }
    }
    
	/**
	 * Read public key from file.
	 * 
	 * @param fileName file in DER format containing the the public key
	 * @return the {@link PublicKey}
	 * @throws RuntimeException for any of the underlying exceptions
	 */
	public static PublicKey readPublicKey(String fileName) {
		try {
			return readPublicKey(new FileInputStream(fileName));
		} catch (IOException e) {
			throw new RuntimeException("Failed to read public key from %s: %s".formatted(fileName, e.getMessage()), e);
		}
	}

	/**
	 * Read private key from bytes.
	 * 
	 * @param bytes byte arry with the DER format key
	 * @return the {@link PrivateKey}
     * @throws RuntimeException for any of the underlying exceptions
	 */
    public static PrivateKey readPrivateKey(byte[] bytes) {
        try {
            PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(bytes, "RSA");
            KeyFactory keyFactory = KeyFactory.getInstance("RSA");
            return keyFactory.generatePrivate(keySpec);     
        } catch (NoSuchAlgorithmException | InvalidKeySpecException e) {
            throw new RuntimeException("PKI error reading private key: %s".formatted(e.getMessage()), e);
        }
    }

    /**
     * Read private key from an input stream.
     * @param is the input stream
     * @return the private key
     * @throws RuntimeException for any of the underlying exceptions
     */
    public static PrivateKey readPrivateKey(InputStream is) {
        try {
            return readPrivateKey(is.readAllBytes());
        } catch (IOException e) {
            throw new RuntimeException("Failed to read private key from stream: %s".formatted(e.getMessage()), e);
        }
    }
    
	/**
	 * Read private key from file.
	 * 
	 * @param fileName file in DER format containing the private key
	 * @return the {@link PrivateKey}
	 * @throws RuntimeException for any of the underlying exceptions
	 */
	public static PrivateKey readPrivateKey(String fileName) {
		try {
			return readPrivateKey(new FileInputStream(fileName));
		} catch (IOException e) {
			throw new RuntimeException("Failed to read private key from %s: %s".formatted(fileName, e.getMessage()), e);
		}
	}
}
