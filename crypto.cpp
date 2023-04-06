#include <iostream>
#include <stdexcept>
#include <string>

#include <openssl/aes.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/kdf.h>
#include <openssl/sha.h>

#include "crypto.h"

using namespace std;

AESKeys derive_aes_keys(const unsigned char *shared_secret, const size_t shared_secret_length)
{
    AESKeys keys;
    const int AES_KEY_SIZE = 32; // 256 bits
    const int AES_IV_SIZE = 16;  // 128 bits
    const int KEY_MATERIAL_SIZE = AES_KEY_SIZE + AES_IV_SIZE;
    unsigned char key_material[KEY_MATERIAL_SIZE];

    // Create a new HKDF context
    EVP_PKEY_CTX *pctx = EVP_PKEY_CTX_new_id(EVP_PKEY_HKDF, nullptr);
    if (!pctx)
    {
        throw runtime_error("Error creating HKDF context");
        exit(1);
    }

    // Initialize the HKDF context
    if (EVP_PKEY_derive_init(pctx) <= 0)
    {
        throw runtime_error("Error initializing HKDF context");
        EVP_PKEY_CTX_free(pctx);
        exit(1);
    }

    // Set the HKDF algorithm to use HMAC-SHA256
    if (EVP_PKEY_CTX_set_hkdf_md(pctx, EVP_sha256()) <= 0)
    {
        throw runtime_error("Error setting HKDF algorithm");
        EVP_PKEY_CTX_free(pctx);
        exit(1);
    }

    // Set the shared secret as the HKDF input keying material
    if (EVP_PKEY_CTX_set1_hkdf_key(pctx, shared_secret, shared_secret_length) <= 0)
    {
        throw runtime_error("Error setting HKDF input keying material");
        EVP_PKEY_CTX_free(pctx);
        exit(1);
    }

    // Set the salt for the HKDF
    if (EVP_PKEY_CTX_set1_hkdf_salt(pctx, shared_secret, shared_secret_length) <= 0)
    {
        throw runtime_error("Error setting HKDF salt");
        EVP_PKEY_CTX_free(pctx);
        exit(1);
    }

    // Derive the key material using HKDF
    size_t key_material_len = KEY_MATERIAL_SIZE;
    if (EVP_PKEY_derive(pctx, key_material, &key_material_len) <= 0)
    {
        throw runtime_error("Error deriving key material");
        EVP_PKEY_CTX_free(pctx);
        exit(1);
    }

    // Clean up the HKDF context
    EVP_PKEY_CTX_free(pctx);

    // Populate the AESKeys structure
    keys.aes_key = string(reinterpret_cast<char *>(key_material), AES_KEY_SIZE);
    keys.aes_iv = string(reinterpret_cast<char *>(key_material + AES_KEY_SIZE), AES_IV_SIZE);

    return keys;
}

string aes_encrypt(const string &key, const string &iv, const string &text)
{
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (1 != EVP_EncryptInit_ex(ctx, EVP_aes_256_ctr(), nullptr, reinterpret_cast<const unsigned char *>(key.data()), reinterpret_cast<const unsigned char *>(iv.data())))
        ERR_print_errors_fp(stderr);

    int out_len1, out_len2;
    unsigned char outbuf[text.size() + EVP_MAX_BLOCK_LENGTH];

    if (1 != EVP_EncryptUpdate(ctx, outbuf, &out_len1, reinterpret_cast<const unsigned char *>(text.data()), text.size()))
        ERR_print_errors_fp(stderr);

    if (1 != EVP_EncryptFinal_ex(ctx, outbuf + out_len1, &out_len2))
        ERR_print_errors_fp(stderr);

    EVP_CIPHER_CTX_free(ctx);

    return string(reinterpret_cast<char *>(outbuf), out_len1 + out_len2);
}

string aes_decrypt(const string &key, const string &iv, const string &text)
{
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (1 != EVP_DecryptInit_ex(ctx, EVP_aes_256_ctr(), nullptr, reinterpret_cast<const unsigned char *>(key.data()), reinterpret_cast<const unsigned char *>(iv.data())))
        ERR_print_errors_fp(stderr);

    int out_len1, out_len2;
    unsigned char outbuf[text.size() + EVP_MAX_BLOCK_LENGTH];

    if (1 != EVP_DecryptUpdate(ctx, outbuf, &out_len1, reinterpret_cast<const unsigned char *>(text.data()), text.size()))
        ERR_print_errors_fp(stderr);

    if (1 != EVP_DecryptFinal_ex(ctx, outbuf + out_len1, &out_len2))
        ERR_print_errors_fp(stderr);

    EVP_CIPHER_CTX_free(ctx);

    return string(reinterpret_cast<char *>(outbuf), out_len1 + out_len2);
}