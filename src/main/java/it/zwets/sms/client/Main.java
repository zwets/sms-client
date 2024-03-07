package it.zwets.sms.client;

import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.Arrays;
import java.util.Base64;

import it.zwets.sms.crock.PhoneNumberEncoder;
import it.zwets.sms.crypto.OdkCrypto;
import it.zwets.sms.crypto.PkiCrypto;
import it.zwets.sms.crypto.PkiUtils;
import it.zwets.sms.crypto.Vault;
import it.zwets.sms.message.SmsMessage;

public class Main {

    public static final String DEFAULT_KEYPASS = "123456";
    
    private static byte[] encryptWithPubkey(Path pubFile, byte[] plaintext) throws IOException {
        byte[] keyBytes = Files.readAllBytes(pubFile);
        keyBytes = Base64.getDecoder().decode(keyBytes);
        PublicKey key = PkiUtils.readPublicKey(keyBytes);
        byte[] ciphertext = PkiCrypto.encrypt(key, plaintext);
        return Base64.getEncoder().encode(ciphertext);
    }

    public static void main(String[] args) {

        try {
            if ((args.length == 3 || args.length == 4) && "pubkey".equals(args[0]))
            {
                String keyStore = args[1];
                String keyPass = args.length == 4 ? args[2] : DEFAULT_KEYPASS;
                String alias = args[args.length - 1]; 
                
                Vault vault = new Vault(keyStore, keyPass);
                PublicKey key = vault.getPublicKey(alias);
                byte[] bytes = key.getEncoded();
                Files.write(Path.of("/dev/stdout"), Base64.getEncoder().encode(bytes));
            }
            else if ((args.length == 2 || args.length == 3) &&  "aliases".equals(args[0]))
            {
                String keyStore = args[1];
                String keyPass = args.length == 3 ? args[2] : DEFAULT_KEYPASS;

                Vault vault = new Vault(keyStore, keyPass);
                vault.getAliases().forEachRemaining(System.out::println);
            }
            else if (args.length == 4 && "decrypt".equals(args[0]))
            {
                String keyStore = args[1];
                String keyPass = args.length == 4 ? args[2] : DEFAULT_KEYPASS;
                String alias = args[args.length - 1]; 
                
                Vault vault = new Vault(keyStore, keyPass);
                byte[] bytes = Base64.getDecoder().decode(Files.readAllBytes(Path.of("/dev/stdin")));
                Files.write(Path.of("/dev/stdout"), vault.decrypt(alias, bytes));
            }
            else if (args.length == 2 && "encrypt".equals(args[0]))
            {
                Files.write(Path.of("/dev/stdout"), 
                        encryptWithPubkey(Path.of(args[1]), Files.readAllBytes(Path.of("/dev/stdin"))));
            }
            else if ((args.length == 2 || args.length == 3) && "encrock".equals(args[0]))
            {
                PhoneNumberEncoder crocker = args.length == 3 ?
                        new PhoneNumberEncoder(Arrays.stream(args[1].split(" *, *")).mapToInt(Integer::parseInt).toArray()) :
                        new PhoneNumberEncoder();
                
                System.out.println(crocker.encode(args[args.length - 1]));
            }
            else if ((args.length == 2 || args.length == 3) && "decrock".equals(args[0]))
            {
                PhoneNumberEncoder crocker = args.length == 3 ?
                        new PhoneNumberEncoder(Arrays.stream(args[1].split(" *, *")).mapToInt(Integer::parseInt).toArray()) :
                        new PhoneNumberEncoder();
                
                System.out.println(crocker.decode(args[args.length - 1]));
            }
            else if (args.length == 2 && "alphabet".equals(args[0])) {
                System.out.println(new PhoneNumberEncoder(
                        Arrays.stream(args[1].split(" *, *")).mapToInt(Integer::parseInt).toArray())
                            .getAlphabet());                
            }
            else if (args.length == 5 && "enc-sms".equals(args[0]))
            {
                SmsMessage sms = new SmsMessage();
                sms.setHeader("To", args[2]);
                sms.setHeader("Sender", args[3]);
                sms.setBody(args[4]);

                Files.write(Path.of("/dev/stdout"), 
                        encryptWithPubkey(Path.of(args[1]), sms.asBytes()));
            }
            else if (args.length == 5 && "kobo-dec".equals(args[0]))
            {
                PrivateKey privKey = PkiUtils.readPrivateKey(args[1]);
                String base64EncKey = args[2];
                String instanceId = args[3];
                String inFile = args[4];

                FileInputStream is = new FileInputStream(new File(inFile.equals("-") ? "/dev/stdin" : inFile));
                OdkCrypto.Decryptor decryptor = new OdkCrypto.Decryptor(privKey, base64EncKey, instanceId);
                decryptor.decrypt(is, System.out);
            }
            else if ((args.length == 5 || args.length == 7) && "kobo-vault-dec".equals(args[0]))
            {
                int argc = 1;
                String keyStore = args[argc++];
                String keyPass = args.length == 5 ? "123456" : args[argc++];
                String alias = args.length == 5 ? "kobo" : args[argc++];
                String base64EncKey = args[argc++];
                String instanceId = args[argc++];
                String inFile = args[argc++];

                Vault vault = new Vault(keyStore, keyPass);
                PrivateKey privKey = vault.getPrivateKey(alias);
                FileInputStream is = new FileInputStream(new File(inFile.equals("-") ? "/dev/stdin" : inFile));
                OdkCrypto.Decryptor decryptor = new OdkCrypto.Decryptor(privKey, base64EncKey, instanceId);
                decryptor.decrypt(is, System.out);
            }
            else {
                System.err.println("Usage: sms-client aliases KEYSTORE [KEYPASS]");
                System.err.println("       sms-client pubkey KEYSTORE [KEYPASS] ALIAS");
                System.err.println("       sms-client encrypt PUBKEY");
                System.err.println("       sms-client encrock [SHUFFLEKEY] PHONENUMBER");
                System.err.println("       sms-client alphabet SHUFFLEKEY");
                System.err.println("       sms-client kobo-dec PKFILE B64SYMKEY INSTANCE INFILE");
                System.err.println("       sms-client kobo-vault-dec KEYSTORE [KEYPASS ALIAS] B64SYMKEY INSTANCE INFILE");
                System.err.println("       sms-client enc-sms PUBKEY RECIPIENT SENDER MESSAGE");
                
                System.exit(1);
            }
        }
        catch (Exception e) {
            System.err.println("sms-client: %s".formatted(e.getMessage()));
            e.printStackTrace();
            System.exit(1);
        }
    }
}
