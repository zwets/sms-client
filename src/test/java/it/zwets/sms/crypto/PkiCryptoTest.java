package it.zwets.sms.crypto;

import static org.junit.jupiter.api.Assertions.assertEquals;

import java.nio.charset.StandardCharsets;
import java.security.PrivateKey;
import java.security.PublicKey;

import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

public class PkiCryptoTest {
    
    public static final String PRIV_KEY_FNAME = "private.der";
    public static final String PUB_KEY_FNAME = "public.der";
    
    private static PrivateKey PRIV_KEY;
    private static PublicKey PUB_KEY;
    
    @BeforeAll
    static void loadKeys() {
        PRIV_KEY = PkiUtils.readPrivateKey(PkiCryptoTest.class.getClassLoader().getResourceAsStream(PRIV_KEY_FNAME));
        PUB_KEY = PkiUtils.readPublicKey(PkiCryptoTest.class.getClassLoader().getResourceAsStream(PUB_KEY_FNAME));
    }
    
    @Test
    void testEncryptAndDecrypt() {
        String input = "Hello World";
        byte[] encrypted = PkiCrypto.encrypt(PUB_KEY, input.getBytes());
        byte[] decrypted = PkiCrypto.decrypt(PRIV_KEY, encrypted);
        String output = new String(decrypted, StandardCharsets.UTF_8);
        
        assertEquals(output, input);
    }
}
