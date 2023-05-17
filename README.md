# Secure Messaging Program

This is a secure chat program created for CSC 38000 (Computer Security). Written in C and C++, the program includes the following security measure:

- authentication of correspondents
- message secrecy (encryption)
- message integrity (HMACs)

## Usage

To run the program, use the Makefile to comp


Use the Makefile to compile the program. Then, to run the program as a server, use the following command:

```
./chat
```

To run the program as a client, use the following command:

```
.chat -c
```

## Authors

This program was written by Sumya Raha, John Royal, and Joseph Nicholas.

## Security

### Assumptions

1. **Public Key Exchange:** When initiating the chat session, the program exchanges RSA public keys with the other party, and the user is prompted to accept the other party’s RSA public key fingerprint. As a result, it is assumed that the parties have already exchanged public keys over a secure channel before initiating the chat session.
2. **Software and Hardware Integrity:** The program itself has not been tampered with and is running on a secure device. The program does not include defenses against a modified program or a compromised device. This is assumed for both communicating parties.
3. **Non-Secure Network:** The program assumes that adversaries may have access to the transmitted encrypted messages and may attempt to perform a range of attacks, including man-in-the-middle and brute-force attacks.

### Security Claims

Before initializing the chat session, the client and server perform a two-step handshake protocol to establish shared AES and HMAC keys for the session, as well as to authenticate each other. After this handshake, the parties can exchange messages securely using encryption and message signatures.

1. **Key Exchange with Perfect Forward Secrecy:** The program uses Diffie-Hellman to securely derive a shared secret key with perfect forward secrecy (PFS). This shared secret is used to compute three so-called “session keys”: the AES encryption key, the AES initialization vector (IV), and the HMAC key. The AES key and initialization vector are used to encrypt and decrypt messages and the HMAC key is used to compute HMACs for message integrity.
2. **Mutual Authentication:** After exchanging RSA public keys, the program uses a challenge-response mechanism to verify that the other party holds the corresponding RSA private key. Here is how this mechanism works:
    1. The server generates a random string, encrypts it using the client’s RSA public key, and sends the encrypted string to the client.
    2. The client decrypts the string using its RSA private key and sends the result back to the server.
    3. The server verifies that the client’s decrypted string matches the original string. If they match, then the client is authenticated. Otherwise, the server terminates the chat session.
    4. This procedure is repeated with the client generating a random string and the server decrypting it, thus accomplishing mutual authentication.
3. **Message Secrecy:** Using the shared AES key and initialization vector, the program encrypts the message using AES in CBC mode. The AES key and initialization vector are derived from the shared secret key using SHA-256. The program uses a 256-bit key size and a 128-bit block size. The encrypted message is then sent to the recipient, who can decrypt the message only if they have the shared secret key.
4. **Message Integrity:** To ensure message integrity, messages include a digital signature generated using a combination of HMAC-SHA256 and RSA private key encryption. The HMAC is computed from the unencrypted message using an HMAC key derived from the shared secret using SHA-256. The HMAC is then encrypted using the sender’s RSA private key and sent to the recipient along with the encrypted message. After decrypting the message contents using AES-256, the recipient decrypts the HMAC using the sender’s RSA public key and recomputes the HMAC from the decrypted message contents and HMAC key. If the re-computed HMAC matches the one received, this verifies that the message has not been tampered with and was sent by the claimed sender. Otherwise, the recipient terminates the chat session.

### Known Vulnerabilities

1. The program’s authentication mechanisms depend on the integrity of the RSA public key exchange. Although the program prompts each party to manually inspect the other party’s public key fingerprint, this assumes that the parties have already exchanged public keys through a secure channel. If an adversary tampers with the public key exchange, they can impersonate the other party by using their own RSA public key and fingerprint. In a real-world application, this would be mitigated using a public key infrastructure (PKI) and a trusted certificate authority (CA).
2. Likewise, the program’s authentication mechanisms additionally assume that no RSA private keys have been compromised. If an RSA private key is compromised, an adversary may impersonate a party to the conversation by passing the challenge-response mechanism used for mutual authentication and generating valid signatures for their messages.
3. If the Diffie-Hellman key exchange were to be compromised, the adversary would be able to derive the shared secret key and decrypt all messages sent during the session. However, the program’s authentication mechanisms should prevent them from impersonating another party.
4. The program does not include defenses against a modified program or a compromised device. By modifying the program, an adversary could disable or bypass the encryption and authentication mechanisms. By compromising the device, an adversary could gain access to the RSA private key and shared secret key, thus compromising the confidentiality and integrity of the messages.