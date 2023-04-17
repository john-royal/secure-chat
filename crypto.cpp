#include <iostream>
#include <iomanip>
#include <sstream>
#include <stdio.h>
#include <stdexcept>
#include <string>

#include <openssl/aes.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/kdf.h>
#include <openssl/hmac.h>
#include <openssl/pem.h>
#include <openssl/sha.h>
#include <openssl/rand.h>

#include "crypto.h"

using namespace std;

Keys derive_aes_keys(const unsigned char *shared_secret, const size_t shared_secret_length)
{
    Keys keys;
    const int AES_KEY_SIZE = 32;  // 256 bits
    const int AES_IV_SIZE = 16;   // 128 bits
    const int HMAC_KEY_SIZE = 32; // 256 bits
    const int KEY_MATERIAL_SIZE = AES_KEY_SIZE + AES_IV_SIZE + HMAC_KEY_SIZE;
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
    keys.hmac_key = string(reinterpret_cast<char *>(key_material + AES_KEY_SIZE + AES_IV_SIZE), HMAC_KEY_SIZE);

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

string hmac_sha512(const string &key, const string &text)
{
    unsigned char mac[64];
    memset(mac, 0, 64);

    HMAC(EVP_sha512(), key.c_str(), key.size(), reinterpret_cast<const unsigned char *>(text.c_str()),
         text.size(), mac, nullptr);

    stringstream hmac_str;
    for (size_t i = 0; i < 64; i++)
    {
        hmac_str << hex << setw(2) << setfill('0') << static_cast<int>(mac[i]);
    }

    return hmac_str.str();
}

RSA *rsa_generate_key()
{
    return RSA_generate_key(2048, RSA_F4, nullptr, nullptr);
}

string rsa_public_encrypt(RSA *public_key, const string &text)
{
    int max_size = RSA_size(public_key);
    unsigned char encrypted[max_size];

    int encrypted_length = RSA_public_encrypt(text.size(),
                                              reinterpret_cast<const unsigned char *>(text.c_str()),
                                              encrypted,
                                              public_key,
                                              RSA_PKCS1_PADDING);

    if (encrypted_length == -1)
        throw runtime_error("RSA public key encryption failed");

    return string(reinterpret_cast<char *>(encrypted), encrypted_length);
}

string rsa_private_encrypt(RSA *private_key, const string &text)
{
    int max_size = RSA_size(private_key);
    unsigned char encrypted[max_size];

    int encrypted_length = RSA_private_encrypt(text.size(),
                                               reinterpret_cast<const unsigned char *>(text.c_str()),
                                               encrypted,
                                               private_key,
                                               RSA_PKCS1_PADDING);

    if (encrypted_length == -1)
        throw runtime_error("RSA private key encryption failed");

    return string(reinterpret_cast<char *>(encrypted), encrypted_length);
}

string rsa_public_decrypt(RSA *public_key, const string &text)
{
    int max_size = max(RSA_size(public_key), (int)text.size());
    unsigned char decrypted[max_size];

    if (public_key == nullptr)
        throw runtime_error("RSA public key is null");

    int decrypted_length = RSA_public_decrypt(text.size(),
                                              reinterpret_cast<const unsigned char *>(text.c_str()),
                                              decrypted,
                                              public_key,
                                              RSA_PKCS1_PADDING);

    if (decrypted_length == -1)
        throw runtime_error("RSA public key decryption failed");

    return string(reinterpret_cast<char *>(decrypted), decrypted_length);
}

string rsa_private_decrypt(RSA *private_key, const string &text)
{
    int max_size = max(RSA_size(private_key), (int)text.size());
    unsigned char decrypted[max_size];

    int decrypted_length = RSA_private_decrypt(text.size(),
                                               reinterpret_cast<const unsigned char *>(text.c_str()),
                                               decrypted,
                                               private_key,
                                               RSA_PKCS1_PADDING);

    if (decrypted_length == -1)
        throw runtime_error("RSA private key decryption failed");

    return string(reinterpret_cast<char *>(decrypted), decrypted_length);
}

string rsa_public_key_to_string(RSA *public_key)
{
    BIO *bio = BIO_new(BIO_s_mem());

    if (!PEM_write_bio_RSA_PUBKEY(bio, public_key))
    {
        BIO_free(bio);
        throw runtime_error("Failed to write RSA public key to BIO");
    }

    BUF_MEM *mem = nullptr;
    BIO_get_mem_ptr(bio, &mem);
    string public_key_str(mem->data, mem->length);

    BIO_free(bio);
    return public_key_str;
}

RSA *rsa_public_key_from_string(const string &public_key_string)
{
    BIO *bio = BIO_new_mem_buf(public_key_string.c_str(), -1);

    RSA *public_key = PEM_read_bio_RSA_PUBKEY(bio, nullptr, nullptr, nullptr);
    BIO_free(bio);

    if (public_key == nullptr)
    {
        throw runtime_error("Failed to read RSA public key from string");
    }

    return public_key;
}

string rsa_public_key_fingerprint(RSA *public_key)
{
    unsigned char digest[SHA256_DIGEST_LENGTH];

    // Convert RSA public key to byte array
    unsigned char *public_key_bytes = nullptr;
    int len = i2d_RSAPublicKey(public_key, &public_key_bytes);

    // Compute SHA-256 fingerprint
    SHA256(public_key_bytes, len, digest);
    OPENSSL_free(public_key_bytes);

    // Convert fingerprint to hexadecimal string
    stringstream fingerprint;
    for (int i = 0; i < SHA256_DIGEST_LENGTH; i++)
    {
        fingerprint << hex << setw(2) << setfill('0') << static_cast<int>(digest[i]);
    }

    return fingerprint.str();
}

string random_string(size_t length)
{
    unsigned char *rand_bytes = (unsigned char *)malloc(length);
    char *rand_string = (char *)malloc(length + 1);

    // Generate random bytes
    if (1 != RAND_bytes(rand_bytes, length))
    {
        // Failed to generate random bytes
        free(rand_bytes);
        free(rand_string);
        return NULL;
    }

    // Convert random bytes to a random string
    for (size_t i = 0; i < length; i++)
    {
        // Map each byte to a printable ASCII character (32 to 126)
        rand_string[i] = 32 + (rand_bytes[i] % 95);
    }
    rand_string[length] = '\0';

    free(rand_bytes);
    return string(reinterpret_cast<char *>(rand_string), length);
}