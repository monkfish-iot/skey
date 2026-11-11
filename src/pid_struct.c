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
 * pid_struct.c - struct 的组装、加密、HMAC、解密、校验
 *
 * 分区字节布局（总 1584 字节）:
 *   偏移 0     magic(4)        = SHA256(MAC)[0:4]，明文
 *   偏移 4     version(1)      = 1，明文
 *   偏移 5     rsv_hdr(11)     = 0x00，明文（凑结构对齐）
 *   偏移 16    iv(16)          随机，明文
 *   偏移 32    加密主体(1520)  = uuid(16) + pubkey(300) + privkey(1200) + rsv(4)
 *   偏移 1552  hmac(32)        = HMAC-SHA256(AES_key, iv || ciphertext)
 *
 * 加密: AES-128-CBC NoPadding，IV 取自 struct.iv
 * HMAC 输入: iv(16) || ciphertext(1520)
 */

#include "skey_internal.h"

#include <openssl/rand.h>
#include <string.h>

#define OFF_MAGIC      0
#define OFF_VERSION    4
#define OFF_RSV_HDR    5
#define OFF_IV         16
#define OFF_BODY       32    /* 加密主体起始 */
#define OFF_PUBKEY     48    /* 主体内偏移 16 */
#define OFF_PRIVKEY    348   /* 主体内偏移 316 */
#define OFF_RSV_BODY   1748  /* 主体内偏移 1716 */
#define OFF_HMAC       1760

#define BODY_OFF_UUID     0
#define BODY_OFF_PUBKEY   16
#define BODY_OFF_PRIVKEY  (16 + SKEY_PUBKEY_AREA)   /* 316 */
#define BODY_OFF_RSV      (16 + SKEY_PUBKEY_AREA + SKEY_PRIVKEY_AREA) /* 1716 */
#define BODY_RSV_LEN      (SKEY_BODY_LEN - 16 - SKEY_PUBKEY_AREA - SKEY_PRIVKEY_AREA) /* 12 */

_Static_assert(SKEY_BODY_LEN == 16 + SKEY_PUBKEY_AREA + SKEY_PRIVKEY_AREA + BODY_RSV_LEN,
               "body length mismatch");
_Static_assert(SKEY_PID_LEN == 16 + 16 + SKEY_BODY_LEN + SKEY_HMAC_LEN,
               "pid length mismatch");
_Static_assert(OFF_HMAC + SKEY_HMAC_LEN == SKEY_PID_LEN, "hmac offset mismatch");

int pid_pack(const uint8_t mac[6], const uint8_t aes_key[16],
             const uint8_t uuid[16],
             const uint8_t *pubkey_der, size_t pubkey_len,
             const uint8_t *privkey_der, size_t privkey_len,
             uint8_t out[SKEY_PID_LEN])
{
    if (pubkey_len > SKEY_PUBKEY_AREA || privkey_len > SKEY_PRIVKEY_AREA)
        return -1;

    memset(out, 0, SKEY_PID_LEN);

    /* magic */
    uint8_t mhash[32];
    if (crypto_sha256(mac, 6, mhash) < 0)
        return -1;
    memcpy(out + OFF_MAGIC, mhash, SKEY_MAGIC_LEN);

    /* version */
    out[OFF_VERSION] = SKEY_VERSION;

    /* iv 随机 */
    if (RAND_bytes(out + OFF_IV, SKEY_IV_LEN) != 1)
        return -1;

    /* 组装明文主体 */
    uint8_t body[SKEY_BODY_LEN];
    memset(body, 0, sizeof(body));
    memcpy(body + BODY_OFF_UUID, uuid, SKEY_UUID_LEN);
    memcpy(body + BODY_OFF_PUBKEY, pubkey_der, pubkey_len);
    memcpy(body + BODY_OFF_PRIVKEY, privkey_der, privkey_len);
    /* BODY_OFF_RSV 保持 0 */

    /* AES-128-CBC 加密 */
    if (crypto_aes_cbc_encrypt(aes_key, out + OFF_IV, body, SKEY_BODY_LEN,
                               out + OFF_BODY) < 0)
        return -1;

    /* HMAC-SHA256 over (iv || ciphertext) */
    uint8_t hmac_in[SKEY_IV_LEN + SKEY_BODY_LEN];
    memcpy(hmac_in, out + OFF_IV, SKEY_IV_LEN);
    memcpy(hmac_in + SKEY_IV_LEN, out + OFF_BODY, SKEY_BODY_LEN);
    if (crypto_hmac_sha256(aes_key, SKEY_AES_KEY_LEN, hmac_in, sizeof(hmac_in),
                           out + OFF_HMAC) < 0)
        return -1;

    return 0;
}

int pid_unpack(const uint8_t in[SKEY_PID_LEN],
               const uint8_t mac[6], const uint8_t aes_key[16],
               uint8_t uuid[16],
               uint8_t *pubkey_der, size_t *pubkey_len,
               uint8_t *privkey_der, size_t *privkey_len)
{
    /* 校验 magic */
    uint8_t mhash[32];
    if (crypto_sha256(mac, 6, mhash) < 0)
        return -1;
    if (memcmp(in + OFF_MAGIC, mhash, SKEY_MAGIC_LEN) != 0)
        return -2;  /* 未初始化或 magic 不匹配 */

    /* 校验 HMAC */
    uint8_t hmac_in[SKEY_IV_LEN + SKEY_BODY_LEN];
    memcpy(hmac_in, in + OFF_IV, SKEY_IV_LEN);
    memcpy(hmac_in + SKEY_IV_LEN, in + OFF_BODY, SKEY_BODY_LEN);
    uint8_t hcalc[SKEY_HMAC_LEN];
    if (crypto_hmac_sha256(aes_key, SKEY_AES_KEY_LEN, hmac_in, sizeof(hmac_in),
                           hcalc) < 0)
        return -1;
    if (memcmp(hcalc, in + OFF_HMAC, SKEY_HMAC_LEN) != 0)
        return -2;  /* 数据损坏 */

    /* 解密主体 */
    uint8_t body[SKEY_BODY_LEN];
    if (crypto_aes_cbc_decrypt(aes_key, in + OFF_IV, in + OFF_BODY, SKEY_BODY_LEN,
                               body) < 0)
        return -1;

    memcpy(uuid, body + BODY_OFF_UUID, SKEY_UUID_LEN);
    memcpy(pubkey_der, body + BODY_OFF_PUBKEY, SKEY_PUBKEY_AREA);
    memcpy(privkey_der, body + BODY_OFF_PRIVKEY, SKEY_PRIVKEY_AREA);
    /* 实际 DER 长度由 d2i 在解析时确定，此处返回整个区域长度 */
    *pubkey_len = SKEY_PUBKEY_AREA;
    *privkey_len = SKEY_PRIVKEY_AREA;
    return 0;
}
