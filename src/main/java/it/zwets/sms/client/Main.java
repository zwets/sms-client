package it.zwets.sms.client;

import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.PublicKey;
import java.util.Base64;

import it.zwets.sms.crock.PhoneNumberEncoder;
import it.zwets.sms.crypto.PkiUtils;
import it.zwets.sms.crypto.Vault;

public class Main {

    public static final String DEFAULT_KEYPASS = "123456";
    public static final PhoneNumberEncoder PHONE_ENCODER = new PhoneNumberEncoder();

    public static void main(String[] args) {

        try {
            if ((args.length == 3 || args.length == 4) && args[0].equals("pubkey"))
            {
                String keyStore = args[1];
                String keyPass = args.length == 4 ? args[2] : DEFAULT_KEYPASS;
                String alias = args[args.length - 1]; 
                
                Vault vault = new Vault(keyStore, keyPass);
                PublicKey key = vault.getPublicKey(alias);
                byte[] bytes = key.getEncoded();
                Files.write(Path.of("/dev/stdout"), Base64.getEncoder().encode(bytes));
            }
            else if ((args.length == 2 || args.length == 3) && args[0].equals("aliases"))
            {
                String keyStore = args[1];
                String keyPass = args.length == 3 ? args[2] : DEFAULT_KEYPASS;

                Vault vault = new Vault(keyStore, keyPass);
                vault.getAliases().forEachRemaining(System.out::println);
            }
            else if (args.length == 4 && args[0].equals("decrypt"))
            {
                String keyStore = args[1];
                String keyPass = args.length == 4 ? args[2] : DEFAULT_KEYPASS;
                String alias = args[args.length - 1]; 
                
                Vault vault = new Vault(keyStore, keyPass);
                byte[] bytes = Base64.getDecoder().decode(Files.readAllBytes(Path.of("/dev/stdin")));
                Files.write(Path.of("/dev/stdout"), vault.decrypt(alias, bytes));
            }
            else if (args.length == 2 && args[0].equals("encrypt"))
            {
                String pubKey64 = args[1];
                
                byte[] keyBytes = pubKey64.getBytes(StandardCharsets.UTF_8);
                keyBytes = Base64.getDecoder().decode(keyBytes);
                PublicKey key = PkiUtils.readPublicKey(keyBytes);
                byte[] bytes = PkiUtils.encrypt(key, Files.readAllBytes(Path.of("/dev/stdin")));
                Files.write(Path.of("/dev/stdout"), Base64.getEncoder().encode(bytes));
            }
            else if (args.length == 2 && args[0].equals("encrock"))
            {
                System.out.println(PHONE_ENCODER.encode(args[1]));
            }
            else if (args.length == 2 && args[0].equals("decrock"))
            {
                System.out.println(PHONE_ENCODER.decode(args[1]));
            }
            else {
                System.err.println("Usage: sms-client aliases KEYSTORE [KEYPASS]");
                System.err.println("       sms-client pubkey KEYSTORE [KEYPASS] ALIAS");
                System.err.println("       sms-client encrypt PUBKEY");
                System.err.println("       sms-client encrock PHONENUMBER");
                
                System.exit(1);
            }
        }
        catch (Exception e) {
            System.err.println("sms-client: %s".formatted(e.getMessage()));
            System.exit(1);
        }
    }
}
