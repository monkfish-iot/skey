/*
 * Copyright 2026 MonkFish IoT
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

/*
 * crypto.c - OpenSSL 3.x 加密原语封装
 *
 * 包含: SHA256、UUID V4、RSA-2048 密钥生成、DER 编码、RSA-SHA256 签名、
 *       AES-128-CBC(NoPadding)、HMAC-SHA256。
 *
 * 注意: OpenSSL 3.x 中 HMAC() 标记为 deprecated，但仍可用。
 *       编译时通过 -Wno-deprecated-declarations 抑制告警（见 Makefile）。
 */

#include "skey_internal.h"

#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/rsa.h>
#include <openssl/hmac.h>
#include <openssl/sha.h>
#include <openssl/x509.h>
#include <openssl/pem.h>
#include <string.h>

int crypto_sha256(const uint8_t *msg, size_t msglen, uint8_t out[32])
{
    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    if (!ctx)
        return -1;
    unsigned int hlen = 0;
    int ok = 0;
    if (EVP_DigestInit_ex(ctx, EVP_sha256(), NULL) != 1) goto done;
    if (EVP_DigestUpdate(ctx, msg, msglen) != 1) goto done;
    if (EVP_DigestFinal_ex(ctx, out, &hlen) != 1) goto done;
    ok = 1;
done:
    EVP_MD_CTX_free(ctx);
    return ok ? 0 : -1;
}

int crypto_uuid_v4(uint8_t uuid[16])
{
    if (RAND_bytes(uuid, 16) != 1)
        return -1;
    /* version 4 */
    uuid[6] = (uuid[6] & 0x0F) | 0x40;
    /* variant 10 */
    uuid[8] = (uuid[8] & 0x3F) | 0x80;
    return 0;
}

int crypto_rsa_generate(EVP_PKEY **out)
{
    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, NULL);
    if (!ctx)
        return -1;
    int ok = 0;
    EVP_PKEY *pkey = NULL;
    if (EVP_PKEY_keygen_init(ctx) <= 0) goto done;
    if (EVP_PKEY_CTX_set_rsa_keygen_bits(ctx, SKEY_RSA_BITS) <= 0) goto done;
    if (EVP_PKEY_keygen(ctx, &pkey) <= 0) goto done;
    *out = pkey;
    ok = 1;
done:
    EVP_PKEY_CTX_free(ctx);
    return ok ? 0 : -1;
}

int crypto_pubkey_der(EVP_PKEY *pkey, uint8_t *out, size_t outlen, size_t *written)
{
    unsigned char *p = out;
    int len = i2d_PUBKEY(pkey, &p);
    if (len < 0)
        return -1;
    if ((size_t)len > outlen)
        return -1;
    *written = (size_t)len;
    return 0;
}

int crypto_privkey_der(EVP_PKEY *pkey, uint8_t *out, size_t outlen, size_t *written)
{
    unsigned char *p = out;
    int len = i2d_PrivateKey(pkey, &p);
    if (len < 0)
        return -1;
    if ((size_t)len > outlen)
        return -1;
    *written = (size_t)len;
    return 0;
}

int crypto_aes_cbc_encrypt(const uint8_t *key, const uint8_t *iv,
                           const uint8_t *in, size_t inlen, uint8_t *out)
{
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx)
        return -1;
    int ok = 0;
    int outl = 0, finall = 0;
    if (EVP_EncryptInit_ex(ctx, EVP_aes_128_cbc(), NULL, key, iv) != 1) goto done;
    EVP_CIPHER_CTX_set_padding(ctx, 0);
    if (EVP_EncryptUpdate(ctx, out, &outl, in, (int)inlen) != 1) goto done;
    if (EVP_EncryptFinal_ex(ctx, out + outl, &finall) != 1) goto done;
    ok = 1;
done:
    EVP_CIPHER_CTX_free(ctx);
    return ok ? 0 : -1;
}

int crypto_aes_cbc_decrypt(const uint8_t *key, const uint8_t *iv,
                           const uint8_t *in, size_t inlen, uint8_t *out)
{
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx)
        return -1;
    int ok = 0;
    int outl = 0, finall = 0;
    if (EVP_DecryptInit_ex(ctx, EVP_aes_128_cbc(), NULL, key, iv) != 1) goto done;
    EVP_CIPHER_CTX_set_padding(ctx, 0);
    if (EVP_DecryptUpdate(ctx, out, &outl, in, (int)inlen) != 1) goto done;
    if (EVP_DecryptFinal_ex(ctx, out + outl, &finall) != 1) goto done;
    ok = 1;
done:
    EVP_CIPHER_CTX_free(ctx);
    return ok ? 0 : -1;
}

int crypto_hmac_sha256(const uint8_t *key, size_t keylen,
                       const uint8_t *msg, size_t msglen, uint8_t out[32])
{
    unsigned int outlen = 32;
    unsigned char *r = HMAC(EVP_sha256(), key, (int)keylen, msg, msglen, out, &outlen);
    return (r != NULL && outlen == 32) ? 0 : -1;
}

int crypto_sign(EVP_PKEY *privkey, const uint8_t *msg, size_t msglen,
                uint8_t *sig, size_t *siglen)
{
    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    if (!ctx)
        return -1;
    int ok = 0;
    EVP_PKEY_CTX *pctx = NULL;
    if (EVP_DigestSignInit(ctx, &pctx, EVP_sha256(), NULL, privkey) != 1) goto done;
    if (EVP_PKEY_CTX_set_rsa_padding(pctx, RSA_PKCS1_PADDING) <= 0) goto done;
    if (EVP_DigestSignUpdate(ctx, msg, msglen) != 1) goto done;
    size_t slen = *siglen;
    if (EVP_DigestSignFinal(ctx, sig, &slen) != 1) goto done;
    *siglen = slen;
    ok = 1;
done:
    EVP_MD_CTX_free(ctx);
    return ok ? 0 : -1;
}

/* RSA-SHA256 PKCS#1 v1.5 验签（crypto_sign 的逆运算）。
 * 返回 0 验签通过，1 签名不匹配，-1 其他错误。 */
int crypto_verify(EVP_PKEY *pubkey, const uint8_t *msg, size_t msglen,
                  const uint8_t *sig, size_t siglen)
{
    if (!pubkey || !msg || !sig)
        return -1;

    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    if (!ctx)
        return -1;
    int rc = -1;
    EVP_PKEY_CTX *pctx = NULL;
    if (EVP_DigestVerifyInit(ctx, &pctx, EVP_sha256(), NULL, pubkey) != 1) goto done;
    if (EVP_PKEY_CTX_set_rsa_padding(pctx, RSA_PKCS1_PADDING) <= 0) goto done;
    if (EVP_DigestVerifyUpdate(ctx, msg, msglen) != 1) goto done;
    int r = EVP_DigestVerifyFinal(ctx, sig, siglen);
    rc = (r == 1) ? 0 : (r == 0 ? 1 : -1);
done:
    EVP_MD_CTX_free(ctx);
    return rc;
}

/* 生成 PKCS#10 CSR（PEM 文本）。
 * Subject 仅含 CN（设备 ID），用设备私钥 RSA-SHA256 自签名；私钥不导出。 */
int crypto_csr_generate(EVP_PKEY *privkey, const char *cn,
                        char *out, size_t *outlen)
{
    if (!privkey || !cn || !out || !outlen)
        return -1;

    X509_REQ *req = X509_REQ_new();
    BIO *bio = NULL;
    int rc = -1;
    if (!req)
        return -1;

    if (X509_REQ_set_pubkey(req, privkey) != 1) goto done;

    X509_NAME *name = X509_REQ_get_subject_name(req);
    if (!name) goto done;
    if (X509_NAME_add_entry_by_txt(name, "CN", MBSTRING_ASC,
                                   (const unsigned char *)cn, -1, -1, 0) != 1)
        goto done;

    if (X509_REQ_sign(req, privkey, EVP_sha256()) <= 0) goto done;

    bio = BIO_new(BIO_s_mem());
    if (!bio) goto done;
    if (PEM_write_bio_X509_REQ(bio, req) != 1) goto done;

    BUF_MEM *bp = NULL;
    BIO_get_mem_ptr(bio, &bp);
    if (*outlen < bp->length + 1) goto done;
    memcpy(out, bp->data, bp->length);
    out[bp->length] = '\0';
    *outlen = bp->length;
    rc = 0;
done:
    X509_REQ_free(req);
    if (bio) BIO_free(bio);
    return rc;
}

/* 证书链校验。chain_pem 为对端出示的 PEM 证书拼接文本，第一张必须是
 * 叶子证书，其余为中间 CA；root 为本地信任锚（根 CA 证书）。
 * 校验内容：链签名、有效期、basicConstraints CA 层级与 pathlen。
 * 成功时 *leaf_pub 返回叶子证书公钥（引用计数+1，调用方释放）。 */
int crypto_x509_verify_chain(X509 *root, const char *chain_pem,
                             EVP_PKEY **leaf_pub)
{
    if (!root || !chain_pem || !leaf_pub)
        return -1;
    *leaf_pub = NULL;

    /* 解析链中全部证书 */
    STACK_OF(X509) *certs = sk_X509_new_null();
    BIO *bio = BIO_new_mem_buf(chain_pem, (int)strlen(chain_pem));
    if (!certs || !bio) {
        sk_X509_pop_free(certs, X509_free);
        if (bio) BIO_free(bio);
        return -1;
    }
    X509 *c;
    while ((c = PEM_read_bio_X509(bio, NULL, NULL, NULL)) != NULL)
        sk_X509_push(certs, c);
    BIO_free(bio);

    if (sk_X509_num(certs) < 1) {   /* 一张证书都没解析出来 */
        sk_X509_pop_free(certs, X509_free);
        return -1;
    }

    X509 *leaf = sk_X509_shift(certs);  /* 第一张为叶子；其余作为 untrusted */

    X509_STORE *store = X509_STORE_new();
    X509_STORE_CTX *sctx = X509_STORE_CTX_new();
    int rc = -1;
    if (!store || !sctx) goto done;
    if (X509_STORE_add_cert(store, root) != 1) goto done;
    if (X509_STORE_CTX_init(sctx, store, leaf, certs) != 1) goto done;
    X509_STORE_CTX_set_flags(sctx, X509_V_FLAG_X509_STRICT);

    if (X509_verify_cert(sctx) == 1) {
        EVP_PKEY *pk = X509_get_pubkey(leaf);
        if (pk) {
            *leaf_pub = pk;
            rc = 0;
        }
    } else {
        rc = 1;   /* 链不受信 / 证书过期 / 扩展非法 */
    }
done:
    X509_STORE_CTX_free(sctx);
    X509_STORE_free(store);
    X509_free(leaf);
    sk_X509_pop_free(certs, X509_free);
    return rc;
}

/* RSA PKCS#1 v1.5 公钥加密（密钥位数由 pubkey 决定）。
 * out 容量由 *outlen 给出，出参为实际密文长度（= 密钥字节数，RSA-2048 为 256）。
 * 明文最大长度: 密钥字节数 - 11（RSA-2048 为 245；PKCS#1 v1.5 padding 占 11 字节）。 */
int crypto_rsa_encrypt(EVP_PKEY *pubkey, const uint8_t *in, size_t inlen,
                       uint8_t *out, size_t *outlen)
{
    if (!pubkey || !in || !out || !outlen)
        return -1;

    int ksize = EVP_PKEY_get_size(pubkey);
    if (ksize <= 11)                      /* 密钥不可用 / 位数过小 */
        return -1;
    if (inlen > (size_t)ksize - 11)       /* PKCS#1 v1.5 上限 */
        return -1;

    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new(pubkey, NULL);
    if (!ctx)
        return -1;
    int ok = 0;
    if (EVP_PKEY_encrypt_init(ctx) <= 0) goto done;
    if (EVP_PKEY_CTX_set_rsa_padding(ctx, RSA_PKCS1_PADDING) <= 0) goto done;
    size_t olen = *outlen;
    if (EVP_PKEY_encrypt(ctx, out, &olen, in, inlen) <= 0) goto done;
    *outlen = olen;
    ok = 1;
done:
    EVP_PKEY_CTX_free(ctx);
    return ok ? 0 : -1;
}

/* RSA-2048 PKCS#1 v1.5 私钥解密。
 * out 容量由 *outlen 给出，出参为实际明文长度。 */
int crypto_rsa_decrypt(EVP_PKEY *privkey, const uint8_t *in, size_t inlen,
                       uint8_t *out, size_t *outlen)
{
    if (!privkey || !in || !out || !outlen)
        return -1;
    if (inlen != SKEY_RSA_BITS / 8)  /* 密文必须是 256 字节 */
        return -1;

    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new(privkey, NULL);
    if (!ctx)
        return -1;
    int ok = 0;
    if (EVP_PKEY_decrypt_init(ctx) <= 0) goto done;
    if (EVP_PKEY_CTX_set_rsa_padding(ctx, RSA_PKCS1_PADDING) <= 0) goto done;
    size_t olen = *outlen;
    if (EVP_PKEY_decrypt(ctx, out, &olen, in, inlen) <= 0) goto done;
    *outlen = olen;
    ok = 1;
done:
    EVP_PKEY_CTX_free(ctx);
    return ok ? 0 : -1;
}
