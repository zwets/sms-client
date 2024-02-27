package it.zwets.sms.crypto;

import static org.junit.jupiter.api.Assertions.assertEquals;

import java.nio.charset.StandardCharsets;
import java.security.PublicKey;

import org.junit.jupiter.api.Test;

public class VaultTest {
    
    public static final String VAULT_FNAME = "classpath:test.vault";
    public static final String TEST_PUB_FNAME = "test.pub";
    
    @Test
    public void testEncryptAndDecrypt() {
        String input = "Hello World";
        Vault vault = new Vault(VAULT_FNAME, "123456");
        PublicKey pubkey = vault.getPublicKey("test");
        byte[] encrypted = PkiCrypto.encrypt(pubkey, input.getBytes());
        byte[] decrypted = vault.decrypt("test", encrypted);
        String output = new String(decrypted, StandardCharsets.UTF_8);
        
        assertEquals(output, input);
    }
}
