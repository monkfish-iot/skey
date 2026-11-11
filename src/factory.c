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
 * factory.c - Factory/ART 分区查找、MAC 读取、AES 密钥派生
 *
 * 搜索表大小写敏感，按顺序匹配：{"Factory", "art"}，各分区 MAC 偏移不同：
 *   - "Factory"（MTK）：MAC 在偏移 0x4。
 *   - "art"（QCA ART）：MAC 在偏移 0x1002（第二个校准块内，
 *     块首 2 字节为类型标记，其后 6 字节为 MAC）。
 * MAC 均按原始字节顺序输出。
 * AES 密钥 = SHA256( 分区[0:16] || salt )[0:16]。
 */

#include "skey_internal.h"

#include <openssl/evp.h>
#include <openssl/sha.h>
#include <string.h>

/* 大小写敏感的搜索顺序表，各分区的 MAC 存放偏移不同 */
static const struct {
    const char *name;
    off_t       mac_off;
} factory_names[] = {
    { "Factory", 0x4 },     /* MTK Factory: MAC 在偏移 4 */
    { "art",     0x1002 },  /* QCA ART:     MAC 在偏移 0x1002 */
    { NULL, 0 },
};

static int    g_factory_inited = 0;
static char   g_factory_dev[64];
static off_t  g_mac_off;
static uint8_t g_mac[6];
static uint8_t g_aes_key[16];

/* 固定盐，由函数返回以方便后续扩展（如改为由 Factory 派生）。
 * 注意：变更盐会导致旧分区无法解密，需配合 version 升级。 */
const char *get_salt(void)
{
    return "skey-v1-salt";
}

static int factory_locate(void)
{
    if (g_factory_inited)
        return 0;
    for (int i = 0; factory_names[i].name; i++) {
        if (mtd_find_by_name(factory_names[i].name, g_factory_dev, sizeof(g_factory_dev)) == 0) {
            g_mac_off = factory_names[i].mac_off;
            g_factory_inited = 1;
            return 0;
        }
    }
    return -1;
}

int factory_get_dev(char *out, size_t len)
{
    if (factory_locate() < 0)
        return -1;
    strncpy(out, g_factory_dev, len - 1);
    out[len - 1] = '\0';
    return 0;
}

int factory_read_mac(uint8_t mac[6])
{
    if (factory_locate() < 0)
        return -1;
    uint8_t raw[6];
    if (mtd_read(g_factory_dev, g_mac_off, raw, 6) < 0)
        return -1;
    memcpy(mac, raw, 6);
    memcpy(g_mac, mac, 6);
    return 0;
}

int factory_derive_aes_key(uint8_t key[16])
{
    if (factory_locate() < 0)
        return -1;
    uint8_t raw16[16];
    if (mtd_read(g_factory_dev, 0, raw16, 16) < 0)
        return -1;

    const char *salt = get_salt();
    size_t saltlen = strlen(salt);

    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    if (!ctx)
        return -1;
    unsigned char hash[SHA256_DIGEST_LENGTH];
    unsigned int hlen = 0;
    int ok = 0;
    if (EVP_DigestInit_ex(ctx, EVP_sha256(), NULL) != 1) goto done;
    if (EVP_DigestUpdate(ctx, raw16, 16) != 1) goto done;
    if (EVP_DigestUpdate(ctx, salt, saltlen) != 1) goto done;
    if (EVP_DigestFinal_ex(ctx, hash, &hlen) != 1) goto done;
    memcpy(key, hash, 16);
    memcpy(g_aes_key, key, 16);
    ok = 1;
done:
    EVP_MD_CTX_free(ctx);
    return ok ? 0 : -1;
}

const uint8_t *factory_mac_cache(void)
{
    return g_mac;
}

const uint8_t *factory_aeskey_cache(void)
{
    return g_aes_key;
}
