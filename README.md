# sms-client 

CLI tools for managing and testing [SMS Gateway](https://github.com/zwets/sms-gateway)
and [SMS Scheduler](https://github.com/zwets/sms-scheduler).

This repository builds the **sms-client** JAR and holds scripts for managing
and testing the crypto for the [SMS Gateway](https://github.com/zwets/sms-gateway).


## Background

See the background documentation for [SMS Scheduler](https://github.com/zwets/sms-scheduler)
and [SMS Gateway](https://github.com/zwets/sms-gateway) for a general overview.

Clients of the SMS Gateway (directly or through the SMS Scheduler) must submit
requests with a payload that is encrypted with a public key for which the
gateway holds the private key in its 'vault'.

> The vault is a standard Java keystore in PKCS#12 format; see `man keytool`
> for extensive documentation.  The scripts and code in this repo are mostly
> convenience wrappers around keytool and the javax.security API.

The vault must hold a key pair for each client.  The sms-gateway jar comes
with a built-in vault with a default key pair for the 'test' client.  In
production you either copy and extend that vault, or create a new one.

The scripts in this repo are for:

 * Creating a new vault or adding key pairs to an existing vault
 * Retrieving from a vault the public key for a client
 * Encrypting content using a public key (for test and demo purposes)

#### Security

The built-in vault uses 123456 as the store and key password.  The location
and password for the vault are set in SMS Gateway's application properties.
You should restrict access to both files in your production environment.


## Installation

@TODO@


## Usage

Create a new vault KEYSTORE or extend existing KEYSTORE with a key pair for
alias CLIENT:

    bin/new-keypair KEYSTORE [STOREPASS] CLIENT

Obtain the public key (in base64 encoded DER format) for alias CLIENT in
KEYSTORE:

    bin/get-pubkey KEYSTORE [STOREPASS] CLIENT

Encrypt stdin with public key PUBKEY (a base64 string from previous step),
producing the base64 encoded ciphertext on stdout:

    echo "Plaintext" | bin/pubkey-encrypt PUBKEY

Combining the previous two commands:

    echo "Plaintext" | bin/pubkey-encrypt $(bin/get-pubkey KEYSTORE CLIENT)

