package it.zwets.sms.crypto;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;

import java.nio.charset.StandardCharsets;
import java.security.PrivateKey;
import java.security.PublicKey;

import org.junit.jupiter.api.Test;

public class OdkCryptoTest {
    
    private static final PrivateKey PRIV_KEY = TestingKeys.PRIVKEY;
    private static final PublicKey PUB_KEY = TestingKeys.PUBKEY;
    
    @Test
    public void testEncryptAndDecrypt() {
        String input = "Hello World";
        OdkCrypto.OdkResult r = OdkCrypto.encrypt(PUB_KEY, input.getBytes(), "INST_1", 10);
        assertNotNull(r);
        assertNotNull(r.b64key());
        assertNotNull(r.ciphertext());
        
        byte[] decrypted = OdkCrypto.decrypt(PRIV_KEY, r.b64key(), r.ciphertext(), "INST_1", 10);
        String output = new String(decrypted, StandardCharsets.UTF_8);
        
        assertEquals(output, input);
    }

    @Test
    public void testEncryptAndDecryptWithSeqNumMismatch() {
        String input = "Hello World";
        OdkCrypto.OdkResult r = OdkCrypto.encrypt(PUB_KEY, input.getBytes(), "INST_1", 1);
        assertNotNull(r);
        assertNotNull(r.b64key());
        assertNotNull(r.ciphertext());

        try {
            byte[] decrypted = OdkCrypto.decrypt(PRIV_KEY, r.b64key(), r.ciphertext(), "INST_1", 2);
            String output = new String(decrypted, StandardCharsets.UTF_8);
            
            assertNotEquals(output, input);
        }
        catch (Exception e) { }
    }
}
