#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/evp.h>
#include <openssl/sha.h>
#include <openssl/rand.h>
#include <openssl/err.h>

#define KEY_LEN       32
#define IV_LEN_CBC    16
#define IV_LEN_GCM    12
#define GCM_TAG_LEN   16
#define BUFFER_SIZE   4096

static void cleanup_and_die(const char *msg, EVP_CIPHER_CTX *ctx, FILE *fin, FILE *fout) {
    fprintf(stderr, "Error: %s\n", msg);
    ERR_print_errors_fp(stderr);
    if (ctx)  EVP_CIPHER_CTX_free(ctx);
    if (fin)  fclose(fin);
    if (fout) fclose(fout);
    exit(EXIT_FAILURE);
}

static void derive_key_iv(const char *password, unsigned char *key, unsigned char *iv, int iv_len) {
    SHA256((const unsigned char *)password, strlen(password), key);
    unsigned char iv_input[512];
    memcpy(iv_input, "IV", 2);
    memcpy(iv_input + 2, password, strlen(password));
    unsigned char iv_hash[SHA256_DIGEST_LENGTH];
    SHA256(iv_input, 2 + strlen(password), iv_hash);
    memcpy(iv, iv_hash, iv_len);
}

static int encrypt_gcm(const char *password, const char *input_path, const char *output_path) {
    unsigned char key[KEY_LEN], iv[IV_LEN_GCM], tag[GCM_TAG_LEN];
    derive_key_iv(password, key, iv, IV_LEN_GCM);

    FILE *fin  = fopen(input_path,  "rb");
    FILE *fout = fopen(output_path, "wb");
    if (!fin || !fout) { perror("File open"); if (fin) fclose(fin); if (fout) fclose(fout); return -1; }

    fwrite(iv,  1, IV_LEN_GCM,  fout);
    fwrite(tag, 1, GCM_TAG_LEN, fout);

    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx) cleanup_and_die("EVP_CIPHER_CTX_new", NULL, fin, fout);
    if (EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL) != 1) cleanup_and_die("EncryptInit", ctx, fin, fout);
    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, IV_LEN_GCM, NULL) != 1) cleanup_and_die("Set IV len", ctx, fin, fout);
    if (EVP_EncryptInit_ex(ctx, NULL, NULL, key, iv) != 1) cleanup_and_die("EncryptInit key/iv", ctx, fin, fout);

    unsigned char inbuf[BUFFER_SIZE], outbuf[BUFFER_SIZE + EVP_MAX_BLOCK_LENGTH];
    int outlen;
    size_t bytes_read;

    while ((bytes_read = fread(inbuf, 1, BUFFER_SIZE, fin)) > 0) {
        if (EVP_EncryptUpdate(ctx, outbuf, &outlen, inbuf, (int)bytes_read) != 1) cleanup_and_die("EncryptUpdate", ctx, fin, fout);
        fwrite(outbuf, 1, outlen, fout);
    }

    if (EVP_EncryptFinal_ex(ctx, outbuf, &outlen) != 1) cleanup_and_die("EncryptFinal", ctx, fin, fout);
    fwrite(outbuf, 1, outlen, fout);
    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, GCM_TAG_LEN, tag) != 1) cleanup_and_die("Get tag", ctx, fin, fout);

    fseek(fout, IV_LEN_GCM, SEEK_SET);
    fwrite(tag, 1, GCM_TAG_LEN, fout);

    EVP_CIPHER_CTX_free(ctx);
    fclose(fin); fclose(fout);
    printf("[GCM] Encryption successful -> %s\n", output_path);
    return 0;
}

static int decrypt_gcm(const char *password, const char *input_path, const char *output_path) {
    unsigned char key[KEY_LEN], iv[IV_LEN_GCM], tag[GCM_TAG_LEN];

    FILE *fin  = fopen(input_path,  "rb");
    FILE *fout = fopen(output_path, "wb");
    if (!fin || !fout) { perror("File open"); if (fin) fclose(fin); if (fout) fclose(fout); return -1; }

    if (fread(iv,  1, IV_LEN_GCM,  fin) != IV_LEN_GCM)  { fputs("Short IV\n",  stderr); fclose(fin); fclose(fout); return -1; }
    if (fread(tag, 1, GCM_TAG_LEN, fin) != GCM_TAG_LEN) { fputs("Short tag\n", stderr); fclose(fin); fclose(fout); return -1; }

    derive_key_iv(password, key, iv, IV_LEN_GCM);

    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx) cleanup_and_die("EVP_CIPHER_CTX_new", NULL, fin, fout);
    if (EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL) != 1) cleanup_and_die("DecryptInit", ctx, fin, fout);
    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, IV_LEN_GCM, NULL) != 1) cleanup_and_die("Set IV len", ctx, fin, fout);
    if (EVP_DecryptInit_ex(ctx, NULL, NULL, key, iv) != 1) cleanup_and_die("DecryptInit key/iv", ctx, fin, fout);

    unsigned char inbuf[BUFFER_SIZE], outbuf[BUFFER_SIZE + EVP_MAX_BLOCK_LENGTH];
    int outlen;
    size_t bytes_read;

    while ((bytes_read = fread(inbuf, 1, BUFFER_SIZE, fin)) > 0) {
        if (EVP_DecryptUpdate(ctx, outbuf, &outlen, inbuf, (int)bytes_read) != 1) cleanup_and_die("DecryptUpdate", ctx, fin, fout);
        fwrite(outbuf, 1, outlen, fout);
    }

    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, GCM_TAG_LEN, tag) != 1) cleanup_and_die("Set tag", ctx, fin, fout);

    int ret = EVP_DecryptFinal_ex(ctx, outbuf, &outlen);
    if (ret <= 0) {
        fprintf(stderr, "[GCM] Authentication FAILED\n");
        EVP_CIPHER_CTX_free(ctx);
        fclose(fin); fclose(fout);
        return -1;
    }
    fwrite(outbuf, 1, outlen, fout);

    EVP_CIPHER_CTX_free(ctx);
    fclose(fin); fclose(fout);
    printf("[GCM] Decryption successful -> %s\n", output_path);
    return 0;
}

static int encrypt_cbc(const char *password, const char *input_path, const char *output_path) {
    unsigned char key[KEY_LEN], iv[IV_LEN_CBC];
    derive_key_iv(password, key, iv, IV_LEN_CBC);

    FILE *fin  = fopen(input_path,  "rb");
    FILE *fout = fopen(output_path, "wb");
    if (!fin || !fout) { perror("File open"); if (fin) fclose(fin); if (fout) fclose(fout); return -1; }

    fwrite(iv, 1, IV_LEN_CBC, fout);

    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx) cleanup_and_die("EVP_CIPHER_CTX_new", NULL, fin, fout);
    if (EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv) != 1) cleanup_and_die("EncryptInit", ctx, fin, fout);

    unsigned char inbuf[BUFFER_SIZE], outbuf[BUFFER_SIZE + EVP_MAX_BLOCK_LENGTH];
    int outlen;
    size_t bytes_read;

    while ((bytes_read = fread(inbuf, 1, BUFFER_SIZE, fin)) > 0) {
        if (EVP_EncryptUpdate(ctx, outbuf, &outlen, inbuf, (int)bytes_read) != 1) cleanup_and_die("EncryptUpdate", ctx, fin, fout);
        fwrite(outbuf, 1, outlen, fout);
    }

    if (EVP_EncryptFinal_ex(ctx, outbuf, &outlen) != 1) cleanup_and_die("EncryptFinal", ctx, fin, fout);
    fwrite(outbuf, 1, outlen, fout);

    EVP_CIPHER_CTX_free(ctx);
    fclose(fin); fclose(fout);
    printf("[CBC] Encryption successful -> %s\n", output_path);
    return 0;
}

static int decrypt_cbc(const char *password, const char *input_path, const char *output_path) {
    unsigned char key[KEY_LEN], iv[IV_LEN_CBC];

    FILE *fin  = fopen(input_path,  "rb");
    FILE *fout = fopen(output_path, "wb");
    if (!fin || !fout) { perror("File open"); if (fin) fclose(fin); if (fout) fclose(fout); return -1; }

    if (fread(iv, 1, IV_LEN_CBC, fin) != IV_LEN_CBC) { fputs("Short IV\n", stderr); fclose(fin); fclose(fout); return -1; }

    derive_key_iv(password, key, iv, IV_LEN_CBC);

    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx) cleanup_and_die("EVP_CIPHER_CTX_new", NULL, fin, fout);
    if (EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv) != 1) cleanup_and_die("DecryptInit", ctx, fin, fout);

    unsigned char inbuf[BUFFER_SIZE], outbuf[BUFFER_SIZE + EVP_MAX_BLOCK_LENGTH];
    int outlen;
    size_t bytes_read;

    while ((bytes_read = fread(inbuf, 1, BUFFER_SIZE, fin)) > 0) {
        if (EVP_DecryptUpdate(ctx, outbuf, &outlen, inbuf, (int)bytes_read) != 1) cleanup_and_die("DecryptUpdate", ctx, fin, fout);
        fwrite(outbuf, 1, outlen, fout);
    }

    if (EVP_DecryptFinal_ex(ctx, outbuf, &outlen) != 1) {
        fprintf(stderr, "[CBC] Decryption FAILED\n");
        EVP_CIPHER_CTX_free(ctx);
        fclose(fin); fclose(fout);
        return -1;
    }
    fwrite(outbuf, 1, outlen, fout);

    EVP_CIPHER_CTX_free(ctx);
    fclose(fin); fclose(fout);
    printf("[CBC] Decryption successful -> %s\n", output_path);
    return 0;
}

int main(int argc, char *argv[]) {
    if (argc != 6) {
        fprintf(stderr, "Usage: %s <enc|dec> <gcm|cbc> <password> <input> <output>\n", argv[0]);
        return EXIT_FAILURE;
    }

    const char *mode     = argv[1];
    const char *cipher   = argv[2];
    const char *password = argv[3];
    const char *infile   = argv[4];
    const char *outfile  = argv[5];
    int result = -1;

    if      (strcmp(mode,"enc")==0 && strcmp(cipher,"gcm")==0) result = encrypt_gcm(password, infile, outfile);
    else if (strcmp(mode,"dec")==0 && strcmp(cipher,"gcm")==0) result = decrypt_gcm(password, infile, outfile);
    else if (strcmp(mode,"enc")==0 && strcmp(cipher,"cbc")==0) result = encrypt_cbc(password, infile, outfile);
    else if (strcmp(mode,"dec")==0 && strcmp(cipher,"cbc")==0) result = decrypt_cbc(password, infile, outfile);
    else { fprintf(stderr, "Unknown: %s %s\n", mode, cipher); return EXIT_FAILURE; }

    return (result == 0) ? EXIT_SUCCESS : EXIT_FAILURE;
}