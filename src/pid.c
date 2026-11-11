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
 * pid.c - product-uid / product-backup 分区读写流程与库 API 实现
 *
 * 读取策略: 正常只读 product-uid；HMAC 校验失败回退 product-backup。
 * 写入策略: 先写 product-uid 并读回校验，成功后复制到 product-backup。
 * 初始化: 幂等，已有效初始化则直接返回。
 */

#include "skey_internal.h"

#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/x509.h>
#include <openssl/buffer.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <errno.h>

static const char *uid_names[]    = { "product-uid", NULL };
static const char *backup_names[] = { "product-backup", NULL };

/* 文件级（CA / 设备证书）错误诊断，MTD 错误优先于本消息。 */
static char g_pid_err[320];
static void pid_seterr(const char *fmt, ...)
{
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(g_pid_err, sizeof(g_pid_err), fmt, ap);
    va_end(ap);
}

/* 进程内缓存 */
static int       g_loaded = 0;
static int       g_in_init = 0;   /* 防止 skey_init <-> pid_load 自动初始化递归 */
static uint8_t   g_uuid[16];
static uint8_t   g_pubkey_der[SKEY_PUBKEY_AREA];
static uint8_t   g_privkey_der[SKEY_PRIVKEY_AREA];
static EVP_PKEY *g_pubkey = NULL;
static EVP_PKEY *g_privkey = NULL;

/* 对端公钥加密的密文缓冲区上限：RSA-4096 = 512 字节 */
#define SKEY_PEER_CT_MAX 512

/* ---- CA 信任材料（存放于文件系统，随固件发布/更新，不占用 pid 分区） ---- */
#define CA_FILE_MAX  8192
static char      g_ca_path[256] = SKEY_CA_PATH_DEFAULT;
static EVP_PKEY *g_ca_pubkey = NULL;
static X509     *g_ca_cert = NULL;   /* ca.pem 为证书时非 NULL（链校验需要） */
static int       g_ca_state = 0;     /* 0 未加载, 1 已加载, -1 加载失败 */

/* ---- 设备证书链（工厂 CA 签发烧录，每设备一份） ---- */
static char      g_devcert_path[256] = SKEY_DEVICE_CERT_PATH_DEFAULT;

static skey_err_t skey_init_locked(void);   /* skey_init 的实现（见下方） */

static int read_pid_partition(const char *name, uint8_t buf[SKEY_PID_LEN])
{
    char dev[64];
    if (mtd_find_by_name(name, dev, sizeof(dev)) < 0)
        return -1;
    if (mtd_read(dev, 0, buf, SKEY_PID_LEN) < 0)
        return -1;
    return 0;
}

static int write_pid_partition(const char *name, const uint8_t buf[SKEY_PID_LEN])
{
    char dev[64];
    if (mtd_find_by_name(name, dev, sizeof(dev)) < 0)
        return -1;
    if (mtd_erase(dev, 0, SKEY_PID_LEN) < 0)
        return -1;
    if (mtd_write(dev, 0, buf, SKEY_PID_LEN) < 0)
        return -1;
    return 0;
}

static int load_keys_from_der(void)
{
    const unsigned char *p;
    p = (const unsigned char *)g_pubkey_der;
    EVP_PKEY *pub = d2i_PUBKEY(NULL, &p, SKEY_PUBKEY_AREA);
    if (!pub)
        return -1;

    p = (const unsigned char *)g_privkey_der;
    EVP_PKEY *priv = d2i_AutoPrivateKey(NULL, &p, SKEY_PRIVKEY_AREA);
    if (!priv) {
        EVP_PKEY_free(pub);
        return -1;
    }

    if (g_pubkey)  EVP_PKEY_free(g_pubkey);
    if (g_privkey) EVP_PKEY_free(g_privkey);
    g_pubkey = pub;
    g_privkey = priv;
    return 0;
}

int pid_load(void)
{
    if (g_loaded)
        return 0;

    uint8_t mac[6];
    uint8_t aes_key[16];
    if (factory_read_mac(mac) < 0)
        return -1;
    if (factory_derive_aes_key(aes_key) < 0)
        return -1;

    uint8_t buf[SKEY_PID_LEN];
    size_t publen, privlen;
    int rc = -1;

    /* 先读 product-uid */
    if (read_pid_partition(uid_names[0], buf) == 0) {
        rc = pid_unpack(buf, mac, aes_key, g_uuid, g_pubkey_der, &publen,
                        g_privkey_der, &privlen);
    }
    /* 失败则回退 product-backup */
    if (rc != 0 && read_pid_partition(backup_names[0], buf) == 0) {
        rc = pid_unpack(buf, mac, aes_key, g_uuid, g_pubkey_der, &publen,
                        g_privkey_der, &privlen);
    }
    if (rc == 0 && load_keys_from_der() == 0) {
        g_loaded = 1;
        return 0;
    }

    /* 分区未初始化 / 数据无效：首次使用自动执行初始化（等价 skey init，
     * 幂等：已有效分区会修复另一份而不重新生成身份）。
     * 注意：Factory 分区不可读时上方已返回 -1，不会走到这里。
     * g_in_init 用于阻止 skey_init 内部回读校验时再次递归自动初始化。 */
    if (!g_in_init && skey_init() == SKEY_OK && g_loaded)
        return 0;
    return -1;
}

void skey_set_ca_path(const char *path)
{
    snprintf(g_ca_path, sizeof(g_ca_path), "%s",
             path ? path : SKEY_CA_PATH_DEFAULT);
    if (g_ca_pubkey) {
        EVP_PKEY_free(g_ca_pubkey);
        g_ca_pubkey = NULL;
    }
    if (g_ca_cert) {
        X509_free(g_ca_cert);
        g_ca_cert = NULL;
    }
    g_ca_state = 0;
}

void skey_set_device_cert_path(const char *path)
{
    snprintf(g_devcert_path, sizeof(g_devcert_path), "%s",
             path ? path : SKEY_DEVICE_CERT_PATH_DEFAULT);
}

/* 加载 CA PEM 文件（惰性调用，结果缓存）。
 * 文件内容支持证书（BEGIN CERTIFICATE，同时保留 X509 供证书链校验）
 * 或裸公钥（BEGIN PUBLIC KEY，仅支持直接验签）。
 * 返回 0 成功，-1 文件不存在/不可读，-2 PEM 解析失败。 */
static int ca_load(void)
{
    if (g_ca_state == 1)
        return 0;
    if (g_ca_state == -1)
        return -1;

    FILE *f = fopen(g_ca_path, "rb");
    if (!f) {
        pid_seterr("open CA file %s: %s", g_ca_path, strerror(errno));
        g_ca_state = -1;
        return -1;
    }

    uint8_t *buf = malloc(CA_FILE_MAX);
    if (!buf) {
        fclose(f);
        pid_seterr("out of memory loading CA file");
        g_ca_state = -1;
        return -1;
    }
    size_t n = fread(buf, 1, CA_FILE_MAX, f);
    fclose(f);
    if (n == 0 || n >= CA_FILE_MAX) {
        free(buf);
        pid_seterr("read CA file %s: empty or larger than %d bytes",
                   g_ca_path, CA_FILE_MAX);
        g_ca_state = -1;
        return -1;
    }

    EVP_PKEY *pk = NULL;
    X509 *cert = NULL;
    BIO *bio = BIO_new_mem_buf(buf, (int)n);
    if (bio) {
        /* 优先按证书读取（证书链校验需要完整 X509 对象） */
        cert = PEM_read_bio_X509(bio, NULL, NULL, NULL);
        if (cert) {
            pk = X509_get_pubkey(cert);  /* 返回引用计数 +1 的新对象 */
        } else {
            /* 退化为裸公钥（仅支持 skey_verify 直接验签） */
            BIO_reset(bio);
            pk = PEM_read_bio_PUBKEY(bio, NULL, NULL, NULL);
        }
        BIO_free(bio);
    }
    free(buf);

    if (!pk) {
        if (cert)
            X509_free(cert);
        pid_seterr("parse CA PEM %s failed: not an X.509 certificate "
                   "nor a public key", g_ca_path);
        g_ca_state = -1;
        return -2;
    }

    if (g_ca_pubkey)
        EVP_PKEY_free(g_ca_pubkey);
    if (g_ca_cert)
        X509_free(g_ca_cert);
    g_ca_pubkey = pk;
    g_ca_cert = cert;   /* 裸公钥材料时为 NULL */
    g_ca_state = 1;
    return 0;
}

static int try_unpack_from(const char *name, const uint8_t mac[6],
                           const uint8_t aes_key[16],
                           uint8_t uuid[16],
                           uint8_t pubder[SKEY_PUBKEY_AREA],
                           uint8_t privder[SKEY_PRIVKEY_AREA])
{
    uint8_t buf[SKEY_PID_LEN];
    size_t publen, privlen;
    if (read_pid_partition(name, buf) < 0)
        return -1;
    return pid_unpack(buf, mac, aes_key, uuid, pubder, &publen, privder, &privlen);
}

skey_err_t skey_init(void)
{
    g_in_init = 1;
    skey_err_t r = skey_init_locked();
    g_in_init = 0;
    return r;
}

static skey_err_t skey_init_locked(void)
{
    uint8_t mac[6], aes_key[16];
    if (factory_read_mac(mac) < 0)
        return SKEY_ERR_NOT_FOUND;
    if (factory_derive_aes_key(aes_key) < 0)
        return SKEY_ERR_IO;

    uint8_t uuid[16];
    uint8_t pubder[SKEY_PUBKEY_AREA];
    uint8_t privder[SKEY_PRIVKEY_AREA];

    /* 检查是否已初始化 */
    int rc = try_unpack_from(uid_names[0], mac, aes_key, uuid, pubder, privder);
    if (rc == 0) {
        /* uid 已有效，确认 backup 一致；若 backup 缺失/损坏则用 uid 修复 */
        uint8_t buuid[16], bpub[SKEY_PUBKEY_AREA], bpriv[SKEY_PRIVKEY_AREA];
        int brc = try_unpack_from(backup_names[0], mac, aes_key, buuid, bpub, bpriv);
        if (brc != 0) {
            /* 从 uid 复制到 backup */
            uint8_t buf[SKEY_PID_LEN];
            if (read_pid_partition(uid_names[0], buf) == 0)
                write_pid_partition(backup_names[0], buf);
        }
        g_loaded = 0;
        return (pid_load() == 0) ? SKEY_OK : SKEY_ERR_CRYPTO;
    }

    /* uid 无效，尝试从 backup 恢复 */
    rc = try_unpack_from(backup_names[0], mac, aes_key, uuid, pubder, privder);
    if (rc == 0) {
        uint8_t buf[SKEY_PID_LEN];
        if (read_pid_partition(backup_names[0], buf) == 0 &&
            write_pid_partition(uid_names[0], buf) == 0) {
            g_loaded = 0;
            return (pid_load() == 0) ? SKEY_OK : SKEY_ERR_CRYPTO;
        }
        return SKEY_ERR_IO;
    }

    /* 两份都无效，生成新密钥 */
    if (crypto_uuid_v4(uuid) < 0)
        return SKEY_ERR_CRYPTO;

    EVP_PKEY *pkey = NULL;
    if (crypto_rsa_generate(&pkey) < 0)
        return SKEY_ERR_CRYPTO;

    size_t publen2 = 0, privlen2 = 0;
    if (crypto_pubkey_der(pkey, pubder, SKEY_PUBKEY_AREA, &publen2) < 0 ||
        crypto_privkey_der(pkey, privder, SKEY_PRIVKEY_AREA, &privlen2) < 0) {
        EVP_PKEY_free(pkey);
        return SKEY_ERR_CRYPTO;
    }

    uint8_t buf[SKEY_PID_LEN];
    if (pid_pack(mac, aes_key, uuid, pubder, publen2, privder, privlen2, buf) < 0) {
        EVP_PKEY_free(pkey);
        return SKEY_ERR_CRYPTO;
    }

    /* 先写 uid 并读回校验 */
    if (write_pid_partition(uid_names[0], buf) < 0) {
        EVP_PKEY_free(pkey);
        return SKEY_ERR_IO;
    }
    uint8_t vbuf[SKEY_PID_LEN];
    if (read_pid_partition(uid_names[0], vbuf) < 0 ||
        memcmp(vbuf, buf, SKEY_PID_LEN) != 0) {
        EVP_PKEY_free(pkey);
        return SKEY_ERR_IO;
    }

    /* 成功后复制到 backup */
    if (write_pid_partition(backup_names[0], buf) < 0) {
        EVP_PKEY_free(pkey);
        return SKEY_ERR_IO;
    }

    EVP_PKEY_free(pkey);

    g_loaded = 0;
    return (pid_load() == 0) ? SKEY_OK : SKEY_ERR_CRYPTO;
}

const char *skey_last_error(void)
{
    const char *e = mtd_last_error();
    if (e)
        return e;
    return g_pid_err[0] ? g_pid_err : NULL;
}

skey_err_t skey_get_mac(char out[SKEY_MAC_STR_LEN])
{
    uint8_t mac[6];
    if (factory_read_mac(mac) < 0)
        return SKEY_ERR_NOT_FOUND;
    snprintf(out, SKEY_MAC_STR_LEN, "%02X:%02X:%02X:%02X:%02X:%02X",
             mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
    return SKEY_OK;
}

skey_err_t skey_get_device_id(char out[SKEY_DEVICE_ID_BUF])
{
    if (pid_load() != 0)
        return SKEY_ERR_NOT_INIT;
    base62_encode(g_uuid, SKEY_UUID_LEN, out);
    return SKEY_OK;
}

skey_err_t skey_get_uuid(char out[SKEY_UUID_BUF])
{
    if (pid_load() != 0)
        return SKEY_ERR_NOT_INIT;
    urlsafe_b64_encode(g_uuid, SKEY_UUID_LEN, out);
    return SKEY_OK;
}

skey_err_t skey_get_pubkey_pem(char *out, size_t *out_len)
{
    if (!out || !out_len)
        return SKEY_ERR_ARGS;
    if (pid_load() != 0)
        return SKEY_ERR_NOT_INIT;

    BIO *bio = BIO_new(BIO_s_mem());
    if (!bio)
        return SKEY_ERR_CRYPTO;
    if (PEM_write_bio_PUBKEY(bio, g_pubkey) != 1) {
        BIO_free(bio);
        return SKEY_ERR_CRYPTO;
    }

    BUF_MEM *bptr = NULL;
    BIO_get_mem_ptr(bio, &bptr);
    if (*out_len < bptr->length + 1) {
        BIO_free(bio);
        return SKEY_ERR_ARGS;
    }
    memcpy(out, bptr->data, bptr->length);
    out[bptr->length] = '\0';
    *out_len = bptr->length;
    BIO_free(bio);
    return SKEY_OK;
}

skey_err_t skey_sign(const char *input, char *sig_b64, size_t *sig_len)
{
    if (!input || !sig_b64 || !sig_len)
        return SKEY_ERR_ARGS;
    if (pid_load() != 0)
        return SKEY_ERR_NOT_INIT;

    size_t inlen = strlen(input);
    uint8_t sig[SKEY_RSA_BITS / 8];  /* 256 */
    size_t slen = sizeof(sig);
    if (crypto_sign(g_privkey, (const uint8_t *)input, inlen, sig, &slen) < 0)
        return SKEY_ERR_CRYPTO;

    size_t need = ((slen + 2) / 3) * 4 + 1;
    if (*sig_len < need)
        return SKEY_ERR_ARGS;

    size_t olen = 0;
    b64_encode(sig, slen, sig_b64, &olen);
    *sig_len = olen;
    return SKEY_OK;
}

/* 自加密：用本设备公钥加密，只能由本设备私钥解开。 */
skey_err_t skey_encrypt(const char *plaintext, char *ct_b64, size_t *ct_len)
{
    if (!plaintext || !ct_b64 || !ct_len)
        return SKEY_ERR_ARGS;
    if (pid_load() != 0)
        return SKEY_ERR_NOT_INIT;

    size_t ptlen = strlen(plaintext);
    if (ptlen > SKEY_PLAINTEXT_MAX)
        return SKEY_ERR_ARGS;

    uint8_t ct[SKEY_RSA_BITS / 8];  /* 256 */
    size_t ctlen = sizeof(ct);
    if (crypto_rsa_encrypt(g_pubkey, (const uint8_t *)plaintext, ptlen, ct, &ctlen) < 0)
        return SKEY_ERR_CRYPTO;

    size_t need = ((ctlen + 2) / 3) * 4 + 1;
    if (*ct_len < need)
        return SKEY_ERR_ARGS;

    size_t olen = 0;
    b64_encode(ct, ctlen, ct_b64, &olen);
    *ct_len = olen;
    return SKEY_OK;
}

/* 内存 PEM 解析对端公钥：支持裸公钥，或 X.509 证书（取证书公钥）。
 * 失败返回 NULL。 */
static EVP_PKEY *parse_peer_pubkey(const char *pem)
{
    BIO *bio = BIO_new_mem_buf(pem, -1);
    if (!bio)
        return NULL;

    EVP_PKEY *pk = PEM_read_bio_PUBKEY(bio, NULL, NULL, NULL);
    if (!pk) {
        BIO_reset(bio);   /* 回到起始位置，按证书再试一次 */
        X509 *cert = PEM_read_bio_X509(bio, NULL, NULL, NULL);
        if (cert) {
            pk = X509_get_pubkey(cert);   /* 引用计数 +1 */
            X509_free(cert);
        }
    }
    BIO_free(bio);
    return pk;
}

skey_err_t skey_encrypt_with_pubkey(const char *pubkey_pem, const char *plaintext,
                                    char *ct_b64, size_t *ct_len)
{
    if (!pubkey_pem || !plaintext || !ct_b64 || !ct_len)
        return SKEY_ERR_ARGS;

    EVP_PKEY *peer = parse_peer_pubkey(pubkey_pem);
    if (!peer) {
        pid_seterr("parse peer public key PEM failed: "
                   "not a public key nor an X.509 certificate");
        return SKEY_ERR_CRYPTO;
    }

    if (EVP_PKEY_base_id(peer) != EVP_PKEY_RSA) {
        pid_seterr("peer public key is not RSA");
        EVP_PKEY_free(peer);
        return SKEY_ERR_ARGS;
    }

    /* 支持到 RSA-4096（512 字节密文）；更长的密钥需扩展缓冲区 */
    size_t ksize = (size_t)EVP_PKEY_get_size(peer);
    if (ksize < 32 || ksize > SKEY_PEER_CT_MAX) {
        pid_seterr("unsupported peer RSA key size: %zu bytes", ksize);
        EVP_PKEY_free(peer);
        return SKEY_ERR_ARGS;
    }

    size_t ptlen = strlen(plaintext);
    if (ptlen > ksize - 11) {
        pid_seterr("plaintext too long for peer key: %zu > %zu bytes",
                   ptlen, ksize - 11);
        EVP_PKEY_free(peer);
        return SKEY_ERR_ARGS;
    }

    uint8_t ct[SKEY_PEER_CT_MAX];
    size_t ctlen = sizeof(ct);
    if (crypto_rsa_encrypt(peer, (const uint8_t *)plaintext, ptlen, ct, &ctlen) < 0) {
        pid_seterr("RSA encrypt with peer public key failed");
        EVP_PKEY_free(peer);
        return SKEY_ERR_CRYPTO;
    }
    EVP_PKEY_free(peer);

    size_t need = ((ctlen + 2) / 3) * 4 + 1;
    if (*ct_len < need)
        return SKEY_ERR_ARGS;

    size_t olen = 0;
    b64_encode(ct, ctlen, ct_b64, &olen);
    *ct_len = olen;
    return SKEY_OK;
}

skey_err_t skey_decrypt(const char *ct_b64, char *plaintext, size_t *pt_len)
{
    if (!ct_b64 || !plaintext || !pt_len)
        return SKEY_ERR_ARGS;
    if (pid_load() != 0)
        return SKEY_ERR_NOT_INIT;

    /* Base64 解码密文 */
    uint8_t ct[SKEY_RSA_BITS / 8];
    size_t ctlen = sizeof(ct);
    if (b64_decode(ct_b64, ct, &ctlen) < 0)
        return SKEY_ERR_ARGS;

    /* RSA 解密 */
    uint8_t pt[SKEY_DEC_BUF_MAX];
    size_t ptlen = sizeof(pt);
    if (crypto_rsa_decrypt(g_privkey, ct, ctlen, pt, &ptlen) < 0)
        return SKEY_ERR_CRYPTO;

    if (*pt_len < ptlen + 1)  /* +1 给结尾 '\0' */
        return SKEY_ERR_ARGS;

    memcpy(plaintext, pt, ptlen);
    plaintext[ptlen] = '\0';
    *pt_len = ptlen;
    return SKEY_OK;
}

skey_err_t skey_verify(const char *input, const char *sig_b64)
{
    if (!input || !sig_b64)
        return SKEY_ERR_ARGS;

    int crc = ca_load();
    if (crc == -1)
        return SKEY_ERR_NOT_FOUND;   /* CA 文件不存在/不可读 */
    if (crc == -2)
        return SKEY_ERR_CRYPTO;      /* PEM 解析失败 */

    /* Base64 解码签名 */
    uint8_t sig[SKEY_RSA_BITS / 8];  /* 256 */
    size_t siglen = sizeof(sig);
    if (b64_decode(sig_b64, sig, &siglen) < 0)
        return SKEY_ERR_ARGS;

    int rc = crypto_verify(g_ca_pubkey, (const uint8_t *)input, strlen(input),
                           sig, siglen);
    if (rc < 0)
        return SKEY_ERR_CRYPTO;
    if (rc > 0)
        return SKEY_ERR_VERIFY;
    return SKEY_OK;
}

skey_err_t skey_get_ca_pubkey_pem(char *out, size_t *out_len)
{
    if (!out || !out_len)
        return SKEY_ERR_ARGS;

    int crc = ca_load();
    if (crc == -1)
        return SKEY_ERR_NOT_FOUND;
    if (crc == -2)
        return SKEY_ERR_CRYPTO;

    BIO *bio = BIO_new(BIO_s_mem());
    if (!bio)
        return SKEY_ERR_CRYPTO;
    if (PEM_write_bio_PUBKEY(bio, g_ca_pubkey) != 1) {
        BIO_free(bio);
        return SKEY_ERR_CRYPTO;
    }

    BUF_MEM *bptr = NULL;
    BIO_get_mem_ptr(bio, &bptr);
    if (*out_len < bptr->length + 1) {
        BIO_free(bio);
        return SKEY_ERR_ARGS;
    }
    memcpy(out, bptr->data, bptr->length);
    out[bptr->length] = '\0';
    *out_len = bptr->length;
    BIO_free(bio);
    return SKEY_OK;
}

skey_err_t skey_gen_csr(char *out, size_t *out_len)
{
    if (!out || !out_len)
        return SKEY_ERR_ARGS;
    if (pid_load() != 0)
        return SKEY_ERR_NOT_INIT;

    /* CN 使用设备 ID（BASE62），与设备身份一致 */
    char cn[SKEY_DEVICE_ID_BUF];
    base62_encode(g_uuid, SKEY_UUID_LEN, cn);

    size_t olen = *out_len;
    if (crypto_csr_generate(g_privkey, cn, out, &olen) < 0)
        return SKEY_ERR_CRYPTO;
    *out_len = olen;
    return SKEY_OK;
}

skey_err_t skey_get_device_cert_pem(char *out, size_t *out_len)
{
    if (!out || !out_len || *out_len < 2)
        return SKEY_ERR_ARGS;

    g_pid_err[0] = '\0';
    FILE *f = fopen(g_devcert_path, "rb");
    if (!f) {
        pid_seterr("device cert not provisioned (%s). Scheme D uses public "
                   "key pinning, not device certs. "
                   "Use: skey get-device-id / skey get-pubkey / skey sign "
                   "(C API: skey_get_device_id / skey_get_pubkey_pem / skey_sign)",
                   strerror(errno));
        return SKEY_ERR_NOT_FOUND;
    }
    size_t n = fread(out, 1, *out_len - 1, f);
    fclose(f);
    if (n == 0) {
        pid_seterr("device cert %s is empty", g_devcert_path);
        return SKEY_ERR_NOT_FOUND;
    }
    out[n] = '\0';
    *out_len = n;
    return SKEY_OK;
}

skey_err_t skey_verify_cert(const char *input, const char *sig_b64,
                            const char *chain_pem)
{
    if (!input || !sig_b64 || !chain_pem)
        return SKEY_ERR_ARGS;

    int crc = ca_load();
    if (crc == -1)
        return SKEY_ERR_NOT_FOUND;   /* 根 CA 文件不存在 */
    if (crc == -2)
        return SKEY_ERR_CRYPTO;      /* PEM 解析失败 */
    if (!g_ca_cert)
        return SKEY_ERR_ARGS;        /* ca.pem 为裸公钥，不支持证书链校验 */

    /* 以根 CA 为信任锚校验对端证书链，取得叶子证书公钥 */
    EVP_PKEY *leaf = NULL;
    int vr = crypto_x509_verify_chain(g_ca_cert, chain_pem, &leaf);
    if (vr < 0)
        return SKEY_ERR_ARGS;        /* 链 PEM 解析失败 */
    if (vr > 0)
        return SKEY_ERR_VERIFY;      /* 链不受信 / 证书过期 / 扩展非法 */

    /* Base64 解码签名 */
    uint8_t sig[SKEY_RSA_BITS / 8];  /* 256 */
    size_t siglen = sizeof(sig);
    if (b64_decode(sig_b64, sig, &siglen) < 0) {
        EVP_PKEY_free(leaf);
        return SKEY_ERR_ARGS;
    }

    int rc = crypto_verify(leaf, (const uint8_t *)input, strlen(input),
                           sig, siglen);
    EVP_PKEY_free(leaf);
    if (rc < 0)
        return SKEY_ERR_CRYPTO;
    if (rc > 0)
        return SKEY_ERR_VERIFY;
    return SKEY_OK;
}
