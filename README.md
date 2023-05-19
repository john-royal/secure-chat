# Secure Messaging Program

This is a secure messaging program created using C/C++.

Use the Makefile to compile the program. Then, use the following command to start the server:

```
./chat -l
```

To connect to the server, run the program in client mode:

```
./chat -c localhost
```

## Assumptions

1. Non-Secure Network: The program assumes that the network has no built-in security and that messages may be intercepted in transit.
2. Public Key Exchange: The program assumes that the parties have already exchanged public keys through a secure channel and that users are able to inspect and verify the public key fingerprint of the other party.
3. Private Key Secrecy: The program assumes that neither party’s private key has been compromised and that both parties are following best practices, such as regular key rotation.
4. Strong Encryption: The program assumes that the AES and RSA encryption standards, as well as the key lengths used, are sufficient for preventing brute-force attacks.
5. Program Integrity: The program assumes that it has not been tampered with and that all built-in security mechanisms are present.
6. Secure Dependencies: The program assumes that the device, operating system, and all third-party software dependencies are secure and have not been compromised.
7. Adversary Resources: The program assumes that adversaries have access to the network and may attempt to perform brute-force, man-in-the-middle, spoofing, and other attacks.

## Claims

1. Mutual Authentication: First, the user is asked to manually inspect and certify the RSA public key fingerprint of the other party. Then, the program uses a challenge-response mechanism to verify that the other party holds the corresponding RSA private key.
2. Key Derivation with Perfect Forward Secrecy: The program performs a Diffie-Hellman key exchange to establish a shared secret from which the cryptographic keys for the session are derived. An HMAC-based key derivation function (HKDF) is used to expand the shared secret into three separate keys: a 256-bit AES encryption key, a 128-bit AES initialization vector, and a 256-bit HMAC key. By performing a Diffie-Hellman key exchange and using a secure key derivation function, the program generates cryptographic keys with perfect forward secrecy.
3. Message Confidentiality: The program uses AES-256 encryption in CBC mode to ensure the secrecy of messages in transit. Because the encryption keys are derived from the Diffie-Hellman shared secret, only a party to the initial key exchange can successfully encrypt and decrypt messages.
4. Message Integrity: The program uses digital signatures to ensure that messages have not been tampered with in transit and were sent by the claimed sender. The digital signature is a message authentication code generated using HMAC-SHA512 and encrypted using the sender’s RSA private key. To authenticate incoming messages, the recipient decrypts the message signature using the sender’s RSA public key, recomputes the message authentication code, and verifies that the decrypted HMAC matches the recomputed one.

## Known Vulnerabilities

1. The program terminates when unexpected inputs are received. This ensures the security of the application by rejecting messages that have not been encrypted and signed correctly. However, this also leaves the program extremely vulnerable to denial-of-service attacks.
2. The program’s authentication mechanisms depend on the secrecy of each party’s private keys. If either party’s RSA private key is compromised, the party may be impersonated by an adversary.
3. The program does not include any defenses specifically against replay attacks. These were deemed unnecessary because of the other security mechanisms in place.
