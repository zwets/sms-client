package it.zwets.sms.crypto;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;

import java.nio.charset.StandardCharsets;
import java.security.PrivateKey;
import java.security.PublicKey;

import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

public class OdkCryptoTest {
    
    public static final String PRIV_KEY_FNAME = "private.der";
    public static final String PUB_KEY_FNAME = "public.der";
    
    private static PrivateKey PRIV_KEY;
    private static PublicKey PUB_KEY;
    
    @BeforeAll
    static void loadKeys() {
        PRIV_KEY = PkiUtils.readPrivateKey(OdkCryptoTest.class.getClassLoader().getResourceAsStream(PRIV_KEY_FNAME));
        PUB_KEY = PkiUtils.readPublicKey(OdkCryptoTest.class.getClassLoader().getResourceAsStream(PUB_KEY_FNAME));
    }
    
    @Test
    void testEncryptAndDecrypt() {
        String input = "Hello World";
        OdkCrypto.OdkResult r = OdkCrypto.encrypt(PUB_KEY, input.getBytes(), "INST_1");
        assertNotNull(r);
        assertNotNull(r.b64key());
        assertNotNull(r.ciphertext());
        
        byte[] decrypted = OdkCrypto.decrypt(PRIV_KEY, r.b64key(), r.ciphertext(), "INST_1");
        String output = new String(decrypted, StandardCharsets.UTF_8);
        
        assertEquals(output, input);
    }
}
