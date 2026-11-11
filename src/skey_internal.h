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

#ifndef SKEY_INTERNAL_H
#define SKEY_INTERNAL_H

/*
 * skey 内部接口，不对外暴露（不随 libskey.a 一起发布给用户的 skey.h 之外）。
 * 各 .c 模块之间通过此头协作。
 */

#include "skey.h"

#include <stdint.h>
#include <stddef.h>
#include <sys/types.h>

#include <openssl/evp.h>

/* ---- mtd.c ---- */
/* 按 /proc/mtd 中的名字查找分区，输出 "/dev/mtdN"。成功返回 0。 */
int mtd_find_by_name(const char *name, char *devpath, size_t len);
int mtd_read(const char *dev, off_t off, void *buf, size_t len);
int mtd_erase(const char *dev, off_t off, size_t len);
int mtd_write(const char *dev, off_t off, const void *buf, size_t len);
/* 最近一次 MTD 操作的错误描述（含 errno），无错误返回 NULL。 */
const char *mtd_last_error(void);

/* ---- factory.c ---- */
int factory_get_dev(char *out, size_t len);
/* 读取 MAC（6字节，偏移随分区类型：Factory=0x4，art=0x1002），同时缓存。 */
int factory_read_mac(uint8_t mac[6]);
/* 从 Factory[0:16] + salt 派生 16 字节 AES 密钥，同时缓存。 */
int factory_derive_aes_key(uint8_t key[16]);
/* 缓存访问（已由上面两个函数填充） */
const uint8_t *factory_mac_cache(void);
const uint8_t *factory_aeskey_cache(void);

/* ---- crypto.c ---- */
int crypto_sha256(const uint8_t *msg, size_t msglen, uint8_t out[32]);
int crypto_uuid_v4(uint8_t uuid[16]);
int crypto_rsa_generate(EVP_PKEY **out);
/* 导出 DER 到固定区，尾部补 0x00。返回实际写入长度。 */
int crypto_pubkey_der(EVP_PKEY *pkey, uint8_t *out, size_t outlen, size_t *written);
int crypto_privkey_der(EVP_PKEY *pkey, uint8_t *out, size_t outlen, size_t *written);
/* RSA-SHA256 PKCS#1 v1.5 签名，sig 容量由 *siglen 给出，返回实际长度。 */
int crypto_sign(EVP_PKEY *privkey, const uint8_t *msg, size_t msglen,
                uint8_t *sig, size_t *siglen);
/* RSA-SHA256 PKCS#1 v1.5 验签。返回 0 验签通过，1 签名不匹配，-1 其他错误。 */
int crypto_verify(EVP_PKEY *pubkey, const uint8_t *msg, size_t msglen,
                  const uint8_t *sig, size_t siglen);
/* 生成 PKCS#10 CSR（PEM），CN=cn，设备私钥 RSA-SHA256 自签名。
 * *outlen 入参为缓冲区容量，出参为写入字节数（不含 '\0'）。 */
int crypto_csr_generate(EVP_PKEY *privkey, const char *cn,
                        char *out, size_t *outlen);
/* 以 root 根证书为信任锚，校验 chain_pem（第一张叶子证书，其余为中间 CA）。
 * 链校验通过后 *leaf_pub 返回叶子证书公钥（引用计数+1，调用方 EVP_PKEY_free）。
 * 返回 0 成功，1 链不受信/过期/扩展非法，-1 其他错误（PEM 解析失败等）。 */
int crypto_x509_verify_chain(X509 *root, const char *chain_pem,
                             EVP_PKEY **leaf_pub);
/* RSA-2048 PKCS#1 v1.5 公钥加密，out 容量由 *outlen 给出，返回实际密文长度。 */
int crypto_rsa_encrypt(EVP_PKEY *pubkey, const uint8_t *in, size_t inlen,
                       uint8_t *out, size_t *outlen);
/* RSA-2048 PKCS#1 v1.5 私钥解密，out 容量由 *outlen 给出，返回实际明文长度。 */
int crypto_rsa_decrypt(EVP_PKEY *privkey, const uint8_t *in, size_t inlen,
                       uint8_t *out, size_t *outlen);
/* AES-128-CBC NoPadding，inlen 必须是 16 的倍数。 */
int crypto_aes_cbc_encrypt(const uint8_t *key, const uint8_t *iv,
                           const uint8_t *in, size_t inlen, uint8_t *out);
int crypto_aes_cbc_decrypt(const uint8_t *key, const uint8_t *iv,
                           const uint8_t *in, size_t inlen, uint8_t *out);
int crypto_hmac_sha256(const uint8_t *key, size_t keylen,
                       const uint8_t *msg, size_t msglen, uint8_t out[32]);

/* ---- encoding.c ---- */
/* 16 字节大端整数转 BASE62，补齐 22 字符 + '\0' */
int base62_encode(const uint8_t *data, size_t len, char out[SKEY_DEVICE_ID_BUF]);
/* 16 字节转 URL-safe Base64（去 padding），22 字符 + '\0' */
int urlsafe_b64_encode(const uint8_t *data, size_t len, char out[SKEY_UUID_BUF]);
/* 标准 Base64，*outlen 入参为缓冲区容量，出参为写入长度(不含\0) */
int b64_encode(const uint8_t *data, size_t len, char *out, size_t *outlen);
/* 标准 Base64 解码，*outlen 入参为缓冲区容量，出参为实际字节数。非法字符返回 -1。 */
int b64_decode(const char *in, uint8_t *out, size_t *outlen);

/* ---- pid_struct.c ---- */
/* 组装并加密 struct，输出 1584 字节。 */
int pid_pack(const uint8_t mac[6], const uint8_t aes_key[16],
             const uint8_t uuid[16],
             const uint8_t *pubkey_der, size_t pubkey_len,
             const uint8_t *privkey_der, size_t privkey_len,
             uint8_t out[SKEY_PID_LEN]);
/* 解密并校验 struct。返回 0 成功，-2 magic/hmac 不匹配，-1 其他错误。
 * pubkey_der/privkey_der 输出固定区（调用方提供 SKEY_PUBKEY_AREA/PRIVKEY_AREA 缓冲），
 * 实际 DER 长度由 d2i 解析时确定。 */
int pid_unpack(const uint8_t in[SKEY_PID_LEN],
               const uint8_t mac[6], const uint8_t aes_key[16],
               uint8_t uuid[16],
               uint8_t *pubkey_der, size_t *pubkey_len,
               uint8_t *privkey_der, size_t *privkey_len);

/* ---- pid.c ---- */
/* 加载并解密分区到进程内缓存。已加载则直接返回。 */
int pid_load(void);

#endif /* SKEY_INTERNAL_H */
