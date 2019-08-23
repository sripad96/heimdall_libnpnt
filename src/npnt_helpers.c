#include <npnt.h>
#define RFM_USE_WOLFSSL 
#ifdef RFM_USE_WOLFSSL
// #include <wolfssl/openssl/bio.h>
// #include <wolfssl/openssl/err.h>
// #include <wolfssl/openssl/ec.h>
// #include <wolfssl/openssl/pem.h>
#else
#include <openssl/bio.h>
#include <openssl/err.h>
#include <openssl/ec.h>
#include <openssl/pem.h>
#endif

#ifdef RFM_USE_WOLFSSL
#include <wolfssl/options.h>
#include <wolfssl/wolfcrypt/rsa.h>
#include <wolfssl/wolfcrypt/asn.h>
static DerBuffer converted;
static RsaKey         rsaKey;
static RsaKey*        pRsaKey = NULL;
int8_t npnt_check_authenticity(npnt_s *handle, uint8_t* raw_data, uint16_t raw_data_len, const uint8_t* signature, uint16_t signature_len)
{
        printf("wolfssl called");
    int ret = 0;

    if (pRsaKey == NULL) {
        /* Initialize the RSA key and decode the DER encoded public key. */
        FILE *fp = fopen("dgca_pubkey.pem", "r");
        if (fp == NULL) {
            printf("pub key read fail");
            return -1;
        }
        fseek(fp, 0L, SEEK_END);
        uint32_t sz = ftell(fp);
        rewind(fp);
        if (sz == 0) {
            printf("size error");
            return -1;
        }
        uint8_t *filebuf = (uint8_t*)malloc(sz);
        if (filebuf == NULL) {
            printf("filebuff error\n");
            return -1;
        }
        uint32_t idx = 0;
        DerBuffer* converted = NULL;

        fread(filebuf, 1, sz, fp);
        ret = wc_PemToDer(filebuf, sz, PUBLICKEY_TYPE, &converted, 0, NULL, NULL);

        if (ret == 0) {
            ret = wc_InitRsaKey(&rsaKey, 0);
            printf("Tried init. rsa key\n");
        }
        if (ret == 0) {
            ret = wc_RsaPublicKeyDecode(converted->buffer, &idx, &rsaKey, converted->length);
            printf("Tried decode. rsa key\n");
        }
        if (ret == 0) {
            pRsaKey = &rsaKey;
            printf("Tried pointing rsa key\n");
        }
        free(filebuf);
        close(fp);
    }

    if (ret < 0) {
            printf("ret error\n");
        return -1;
    }
    uint8_t* decSig = NULL;
    uint32_t decSigLen = 0;
    /* Verify the signature by decrypting the value. */
    if (ret == 0) {
        decSigLen = wc_RsaSSL_VerifyInline(signature, signature_len,
                                           &decSig, pRsaKey);
        if ((int)decSigLen < 0) {
            
            ret = (int)decSigLen;
            printf("decSigLen error  %d\n", ret);
        }
    }
    uint8_t enchash[64];
    raw_data_len = wc_EncodeSignature(enchash, raw_data, raw_data_len, SHA256h);

    /* Check the decrypted result matches the encoded digest. */
    if (ret == 0 && decSigLen != raw_data_len)
    {
        printf("sig len: %d\n " , signature_len );
        printf("data length error %d  %d\n", decSigLen , raw_data_len); 
        ret = -1;
    }
    if (ret == 0 && XMEMCMP(enchash, decSig, decSigLen) != 0)
    {
        ret = -1;
        printf("loop complete  %d\n",ret);
    }
    printf("finifhed  %d\n",ret);
    return ret;
}
static Sha sha;

void reset_sha1()
{
    wc_InitSha256(&sha);
}

void update_sha1(const char* data, uint16_t data_len)
{
    wc_Sha256Update(&sha, data, data_len);
}

void final_sha1(char* hash)
{
    wc_Sha256Final(&sha, (unsigned char*)hash);
}
#else
static SHA_CTX sha;

void reset_sha1()
{
    SHA1_Init(&sha);
}

void update_sha1(const char* data, uint16_t data_len)
{
    SHA1_Update(&sha, data, data_len);
}

void final_sha1(char* hash)
{
    SHA1_Final((unsigned char*)hash, &sha);
}
static EVP_PKEY *dgca_pkey = NULL;
static EVP_PKEY_CTX *dgca_pkey_ctx;
int8_t npnt_check_authenticity(npnt_s *handle, uint8_t* hashed_data, uint16_t hashed_data_len, const uint8_t* signature, uint16_t signature_len)
{
        printf("openssl called ");
    if (!handle || !raw_data || !signature) {
        printf("raw_data or error");
        return -1;
    }
    if (dgca_pkey == NULL) {
        FILE *fp = fopen("dgca_pubkey.pem", "r");
        if (fp == NULL) {
            printf("pub key error");
            return -1;
        }
        dgca_pkey = PEM_read_PUBKEY(fp, NULL, NULL, NULL);
    }
    dgca_pkey_ctx = EVP_PKEY_CTX_new(dgca_pkey, ENGINE_get_default_RSA());
    if (!dgca_pkey_ctx) {
        printf("EVP_PKEY_CTX_new error");
        return -1;
    }
    int ret = 0;
    if (EVP_PKEY_verify_init(dgca_pkey_ctx) <= 0) {
        ret = -1;
        printf("EVP_PKEY_verify_init error");
        goto fail;
    }
    if (EVP_PKEY_CTX_set_rsa_padding(dgca_pkey_ctx, RSA_PKCS1_PADDING) <= 0) {
        ret = -1;
        printf("EVP_PKEY_padding");
        goto fail;
    }
    if (EVP_PKEY_CTX_set_signature_md(dgca_pkey_ctx, EVP_sha1()) <= 0) {
        ret = -1;
        printf("EVP_PKEY_signature_md");
        goto fail;
    }

    /* Perform operation */
    ret = EVP_PKEY_verify(dgca_pkey_ctx, signature, signature_len, raw_data, raw_data_len);

fail:
    EVP_PKEY_CTX_free(dgca_pkey_ctx);
    printf("fail statement");
    return ret;
}
#endif
