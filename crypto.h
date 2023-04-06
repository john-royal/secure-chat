#ifndef CRYPTO_H
#define CRYPTO_H

#include <string>
using namespace std;

struct AESKeys
{
    string aes_key;
    string aes_iv;
};

AESKeys derive_aes_keys(const unsigned char *shared_secret, const size_t shared_secret_length);

string aes_encrypt(const string &key, const string &iv, const string &text);
string aes_decrypt(const string &key, const string &iv, const string &text);

#endif