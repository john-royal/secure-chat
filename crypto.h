#ifndef CRYPTO_H
#define CRYPTO_H

#include <string>
#include <openssl/rsa.h>
using namespace std;

struct Keys
{
    string aes_key;
    string aes_iv;
    string hmac_key;
};

Keys derive_aes_keys(const unsigned char *shared_secret, const size_t shared_secret_length);

string aes_encrypt(const string &key, const string &iv, const string &text);
string aes_decrypt(const string &key, const string &iv, const string &text);

string hmac_sha512(const string &key, const string &text);

RSA *rsa_generate_key();
string rsa_public_encrypt(RSA *public_key, const string &text);
string rsa_private_decrypt(RSA *private_key, const string &text);

#endif