package it.zwets.sms.crypto;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;

import java.nio.charset.StandardCharsets;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.Base64;

import org.junit.jupiter.api.Test;

public class PkiCryptoTest {
    
    private static final PrivateKey PRIVKEY = TestingKeys.PRIVKEY;
    private static final PublicKey PUBKEY = TestingKeys.PUBKEY;
    
    @Test
    public void testEncrypt() {
        String input = "Hello World";
        byte[] encrypted = PkiCrypto.encrypt(PUBKEY, input.getBytes());
        
        assertNotNull(encrypted);
    }

    @Test
    public void testBase64StartsWithENC() {
        String input = "Hello World";
        byte[] encrypted = PkiCrypto.encrypt(PUBKEY, input.getBytes());
        String b64string = Base64.getEncoder().encodeToString(encrypted);
        
        assertEquals("ENC", b64string.substring(0, 3));
    }
    
    @Test
    public void testEncryptAndDecrypt() {
        String input = "Hello World";
        byte[] encrypted = PkiCrypto.encrypt(PUBKEY, input.getBytes());
        byte[] decrypted = PkiCrypto.decrypt(PRIVKEY, encrypted);
        String output = new String(decrypted, StandardCharsets.UTF_8);
        
        assertEquals(output, input);
    }
}