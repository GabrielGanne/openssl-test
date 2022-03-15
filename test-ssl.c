#include <openssl/conf.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include <string.h>


static void
handleErrors(void)
{
    ERR_print_errors_fp(stderr);
    abort();
}

static
int
encrypt(unsigned char *plaintext, int plaintext_len, unsigned char const *key,
    unsigned char const *iv, unsigned char *ciphertext)
{
    EVP_CIPHER_CTX *ctx;

    int len;

    int ciphertext_len;

    /* Create and initialise the context */
    if (!(ctx = EVP_CIPHER_CTX_new()))
        handleErrors();

    /*
     * Initialise the encryption operation. IMPORTANT - ensure you use a key
     * and IV size appropriate for your cipher
     * In this example we are using 256 bit AES (i.e. a 256 bit key). The
     * IV size for *most* modes is the same as the block size. For AES this
     * is 128 bits
     */
    if (1 != EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv))
        handleErrors();

    /*
     * Provide the message to be encrypted, and obtain the encrypted output.
     * EVP_EncryptUpdate can be called multiple times if necessary
     */
    if (1 != EVP_EncryptUpdate(ctx, ciphertext, &len, plaintext, plaintext_len))
        handleErrors();
    ciphertext_len = len;

    /*
     * Finalise the encryption. Further ciphertext bytes may be written at
     * this stage.
     */
    if (1 != EVP_EncryptFinal_ex(ctx, ciphertext + len, &len))
        handleErrors();
    ciphertext_len += len;

    /* Clean up */
    EVP_CIPHER_CTX_free(ctx);

    return ciphertext_len;
}

static
int
decrypt(unsigned char *ciphertext, int ciphertext_len, unsigned char const *key,
    unsigned char const *iv, unsigned char *plaintext)
{
    EVP_CIPHER_CTX *ctx;

    int len;

    int plaintext_len;

    /* Create and initialise the context */
    if (!(ctx = EVP_CIPHER_CTX_new()))
        handleErrors();

    /*
     * Initialise the decryption operation. IMPORTANT - ensure you use a key
     * and IV size appropriate for your cipher
     * In this example we are using 256 bit AES (i.e. a 256 bit key). The
     * IV size for *most* modes is the same as the block size. For AES this
     * is 128 bits
     */
    if (1 != EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv))
        handleErrors();

    /*
     * Provide the message to be decrypted, and obtain the plaintext output.
     * EVP_DecryptUpdate can be called multiple times if necessary.
     */
    if (1 != EVP_DecryptUpdate(ctx, plaintext, &len, ciphertext, ciphertext_len))
        handleErrors();
    plaintext_len = len;

    /*
     * Finalise the decryption. Further plaintext bytes may be written at
     * this stage.
     */
    if (1 != EVP_DecryptFinal_ex(ctx, plaintext + len, &len))
        handleErrors();
    plaintext_len += len;

    /* Clean up */
    EVP_CIPHER_CTX_free(ctx);

    return plaintext_len;
}

static void
hexdump(uint8_t *buffer, size_t buffer_len)
{
    size_t i;

    for (i = 0; i < buffer_len; i++) {
        printf("%02x", buffer[i]);
    }

    printf("\n");
}

int
main(int argc, char **argv)
{
    FILE *fp_in;
    FILE *fp_out;
    char *input;
    size_t inputlen;
    int rv = 1;
    unsigned char key[32] = {0};
    unsigned char iv[16] = {0};

    /*
     * Buffer for ciphertext. Ensure the buffer is long enough for the
     * ciphertext which may be longer than the plaintext, depending on the
     * algorithm and mode.
     */
    unsigned char *ciphertext;
    int ciphertext_len;

    /* Buffer for the decrypted text */
    unsigned char *decryptedtext;
    int decryptedtext_len;

    if (argc != 3) {
        printf("usage: %s: <infile> <outfile>\n", argv[0]);
        return 1;
    }

    fp_in = fopen(argv[1], "r");
    if (fp_in == NULL) {
        fprintf(stderr, "cannot open file: %s\n", argv[1]);
        goto exit;
    }

    fp_out = fopen(argv[2], "w");
    if (fp_in == NULL) {
        fprintf(stderr, "cannot open file: %s\n", argv[2]);
        goto exit;
    }

    fseek(fp_in, 0, SEEK_END);
    inputlen = ftell(fp_in);
    if (inputlen == -1) {
        fprintf(stderr, "cannot get file size\n");
        goto exit;
    }
    rewind(fp_in);

    input = malloc(inputlen);
    ciphertext = malloc(2 * inputlen);
    decryptedtext = malloc(2 * inputlen);
    if (input == NULL || ciphertext == NULL || decryptedtext == NULL) {
        fprintf(stderr, "Failed to alloc size: %zu\n", inputlen);
        goto exit;
    }

    if (fread(input, inputlen, 1, fp_in) != 1) {
        fprintf(stderr, "Failed to read input file\n");
        goto exit;
    }

    if (!EVP_BytesToKey(EVP_aes_256_cbc(), EVP_get_digestbyname("md5"),
            NULL  /* salt */,
            PASSWD, strlen(PASSWD), 1  /* count */,
            key, iv)) {
        fprintf(stderr, "Failed to derive key/iv from secret\n");
        goto exit;
    }
    printf("key=");
    hexdump(key, sizeof(key));
    printf("iv=");
    hexdump(iv, sizeof(iv));

    /* Encrypt the plaintext */
    ciphertext_len = encrypt(input, inputlen, key, iv, ciphertext);

    /* Do something useful with the ciphertext here */
    printf("Ciphertext is:\n");
    BIO_dump_fp(stdout, (const char *)ciphertext, ciphertext_len);
    fwrite(ciphertext, ciphertext_len, 1, fp_out);
    fflush(fp_out);

    /* Decrypt the ciphertext */
    decryptedtext_len = decrypt(ciphertext, ciphertext_len, key, iv,
            decryptedtext);

    /* Add a NULL terminator. We are expecting printable text */
    decryptedtext[decryptedtext_len] = '\0';

    /* Show the decrypted text */
    printf("Decrypted text is:\n");
    printf("%s\n", decryptedtext);

    rv = 0;

exit:
    free(ciphertext);
    free(decryptedtext);
    free(input);
    fclose(fp_in);
    fclose(fp_out);

    return rv;
}
