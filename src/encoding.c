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
 * encoding.c - BASE62、URL-safe Base64、标准 Base64 编码
 *
 * BASE62: 将 16 字节当作大端无符号整数，长除法除以 62 取余，
 *         结果补齐到 22 字符（62^22 > 2^128，足够表示）。
 * URL-safe Base64: 标准 Base64 后 '+'->'-', '/'->'_', 去掉 '=' padding。
 */

#include "skey_internal.h"

#include <string.h>

static const char b62_chars[] =
    "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";

static const char b64_std[] =
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

int base62_encode(const uint8_t *data, size_t len, char out[SKEY_DEVICE_ID_BUF])
{
    uint8_t num[16];
    size_t n = (len < 16) ? len : 16;
    memset(num, 0, sizeof(num));
    memcpy(num, data, n);

    char tmp[32];
    int tlen = 0;

    for (;;) {
        /* num /= 62, rem 为本次最低位 */
        uint32_t rem = 0;
        int all_zero = 1;
        for (int i = 0; i < 16; i++) {
            uint32_t cur = (rem << 8) | num[i];
            num[i] = (uint8_t)(cur / 62);
            rem = cur % 62;
            if (num[i])
                all_zero = 0;
        }
        if (tlen < (int)sizeof(tmp))
            tmp[tlen++] = b62_chars[rem];
        if (all_zero)
            break;
    }

    /* 左侧补 '0' 到 22 字符，再翻转 */
    while (tlen < SKEY_DEVICE_ID_LEN)
        tmp[tlen++] = '0';
    for (int i = 0; i < SKEY_DEVICE_ID_LEN; i++)
        out[i] = tmp[SKEY_DEVICE_ID_LEN - 1 - i];
    out[SKEY_DEVICE_ID_LEN] = '\0';
    return 0;
}

int b64_encode(const uint8_t *data, size_t len, char *out, size_t *outlen)
{
    size_t olen = 0;
    size_t i;
    for (i = 0; i + 2 < len; i += 3) {
        uint32_t v = ((uint32_t)data[i] << 16) | ((uint32_t)data[i + 1] << 8) | data[i + 2];
        out[olen++] = b64_std[(v >> 18) & 0x3f];
        out[olen++] = b64_std[(v >> 12) & 0x3f];
        out[olen++] = b64_std[(v >> 6) & 0x3f];
        out[olen++] = b64_std[v & 0x3f];
    }
    if (i < len) {
        uint32_t v = (uint32_t)data[i] << 16;
        if (i + 1 < len)
            v |= (uint32_t)data[i + 1] << 8;
        out[olen++] = b64_std[(v >> 18) & 0x3f];
        out[olen++] = b64_std[(v >> 12) & 0x3f];
        if (i + 1 < len) {
            out[olen++] = b64_std[(v >> 6) & 0x3f];
            out[olen++] = '=';
        } else {
            out[olen++] = '=';
            out[olen++] = '=';
        }
    }
    out[olen] = '\0';
    if (outlen)
        *outlen = olen;
    return 0;
}

int urlsafe_b64_encode(const uint8_t *data, size_t len, char out[SKEY_UUID_BUF])
{
    char tmp[32];
    size_t olen = 0;
    b64_encode(data, len, tmp, &olen);

    size_t j = 0;
    for (size_t i = 0; i < olen && j < SKEY_UUID_B64_LEN; i++) {
        char c = tmp[i];
        if (c == '=')
            continue;
        if (c == '+')
            c = '-';
        else if (c == '/')
            c = '_';
        out[j++] = c;
    }
    /* 16 字节 Base64 去 padding 后恰为 22 字符，不足则补 '0'（不应发生） */
    while (j < SKEY_UUID_B64_LEN)
        out[j++] = '0';
    out[SKEY_UUID_B64_LEN] = '\0';
    return 0;
}

/* 标准 Base64 解码。*outlen 入参为缓冲区容量，出参为实际写入字节数。
 * 遇到非法字符或缓冲区不足返回 -1。 */
int b64_decode(const char *in, uint8_t *out, size_t *outlen)
{
    if (!in || !out || !outlen)
        return -1;

    static const int8_t b64_rev[256] = {
        -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
        -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
        -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,62,-1,-1,-1,63,
        52,53,54,55,56,57,58,59,60,61,-1,-1,-1,-2,-1,-1,
        -1, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9,10,11,12,13,14,
        15,16,17,18,19,20,21,22,23,24,25,-1,-1,-1,-1,-1,
        -1,26,27,28,29,30,31,32,33,34,35,36,37,38,39,40,
        41,42,43,44,45,46,47,48,49,50,51,-1,-1,-1,-1,-1,
        -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
        -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
        -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
        -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
        -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
        -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
        -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
        -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
    };

    size_t inlen = strlen(in);
    size_t olen = 0;
    uint32_t acc = 0;
    int bits = 0;

    for (size_t i = 0; i < inlen; i++) {
        uint8_t c = (uint8_t)in[i];
        int8_t v = b64_rev[c];
        if (v == -2)  /* '=' padding */
            break;
        if (v == -1)  /* 非法字符 */
            return -1;
        acc = (acc << 6) | (uint32_t)v;
        bits += 6;
        if (bits >= 8) {
            bits -= 8;
            if (olen >= *outlen)
                return -1;
            out[olen++] = (uint8_t)((acc >> bits) & 0xFF);
        }
    }
    *outlen = olen;
    return 0;
}
