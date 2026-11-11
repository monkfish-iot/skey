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

#ifndef SKEY_H
#define SKEY_H

/*
 * skey - 设备密钥与签名工具公共头
 *
 * 仅暴露 skey_get_* / skey_sign / skey_init 接口，供 skey CLI 与外部程序
 * 链接 libskey.a 使用。内部函数见 skey_internal.h。
 */

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* ---- 常量 ---- */
#define SKEY_MAGIC_LEN      4
#define SKEY_VERSION        1
#define SKEY_IV_LEN         16
#define SKEY_AES_KEY_LEN    16
#define SKEY_UUID_LEN       16
#define SKEY_RSA_BITS       2048
#define SKEY_PUBKEY_AREA    300   /* RSA-2048 SubjectPublicKeyInfo DER 约 294 字节 */
#define SKEY_PRIVKEY_AREA   1400  /* RSA-2048 PKCS#8 PrivateKeyInfo DER 约 1218 字节 */
#define SKEY_HMAC_LEN       32
#define SKEY_DEVICE_ID_LEN  22    /* BASE62 编码长度 */
#define SKEY_UUID_B64_LEN   22    /* URL-safe Base64 编码长度 */

/* struct 总长 = 头(32) + 加密主体(1728) + hmac(32) = 1792 */
#define SKEY_BODY_LEN       1728
#define SKEY_PID_LEN        1792

#define SKEY_MAC_STR_LEN    18    /* "AA:BB:CC:DD:EE:FF\0" */
#define SKEY_DEVICE_ID_BUF  23    /* 22 + '\0' */
#define SKEY_UUID_BUF       23
#define SKEY_PUBKEY_PEM_MAX 512
#define SKEY_SIG_B64_MAX    512   /* 256 字节签名 -> 344 字符 Base64 + 余量 */
#define SKEY_PLAINTEXT_MAX  245   /* RSA-2048 PKCS#1 v1.5 最大明文: 256-11 */
#define SKEY_ENC_B64_MAX    512   /* 256 字节密文 -> 344 字符 Base64 + 余量 */
#define SKEY_DEC_BUF_MAX    256   /* 解密输出缓冲区上限 */
#define SKEY_CA_PATH_DEFAULT "/etc/skey/ca.pem"  /* 根 CA 公钥/证书 PEM 默认路径 */
#define SKEY_DEVICE_CERT_PATH_DEFAULT "/etc/skey/device.cert.pem" /* 设备证书链默认路径 */
#define SKEY_CA_PUBKEY_PEM_MAX 1024  /* CA 公钥 PEM 输出缓冲区上限（覆盖 RSA-4096） */
#define SKEY_CSR_PEM_MAX      1024 /* PKCS#10 CSR PEM 输出缓冲区上限 */
#define SKEY_CERT_CHAIN_MAX   6144 /* 证书链 PEM（叶子+中间CA）缓冲区上限 */

/* 最近一次底层（MTD 读写擦）错误的描述字符串，含操作位置与 errno 原因，
 * 用于日志与诊断；没有错误细节时返回 NULL。非线程安全，出错后立即取用。 */
const char *skey_last_error(void);

/* ---- 错误码 ---- */
typedef enum {
    SKEY_OK = 0,
    SKEY_ERR_NOT_FOUND = -1,   /* 找不到分区 */
    SKEY_ERR_IO       = -2,    /* MTD 读写错误 */
    SKEY_ERR_CORRUPT  = -3,    /* HMAC 校验失败 / 数据损坏 */
    SKEY_ERR_CRYPTO   = -4,    /* OpenSSL 操作失败 */
    SKEY_ERR_NOT_INIT = -5,    /* 分区未初始化 */
    SKEY_ERR_ARGS     = -6,    /* 参数错误 / 缓冲区不足 */
    SKEY_ERR_VERIFY   = -7,    /* 验签失败：签名不匹配 */
} skey_err_t;

/* ---- 库 API ---- */

/* 获取 MAC，输出 "AA:BB:CC:DD:EE:FF" */
skey_err_t skey_get_mac(char out[SKEY_MAC_STR_LEN]);

/* 获取设备 ID：UUID 的 BASE62 编码（22 字符） */
skey_err_t skey_get_device_id(char out[SKEY_DEVICE_ID_BUF]);

/* 获取 UUID 的 URL-safe Base64 编码（22 字符） */
skey_err_t skey_get_uuid(char out[SKEY_UUID_BUF]);

/* 获取 RSA 公钥 PEM 字符串。
 * 入参 *out_len 为缓冲区容量，出参为写入字节数（不含结尾 \0）。
 * 缓冲区不足返回 SKEY_ERR_ARGS。 */
skey_err_t skey_get_pubkey_pem(char *out, size_t *out_len);

/* 用 RSA 私钥对 input 签名（RSA-SHA256 PKCS#1 v1.5），返回 Base64 字符串。
 * 入参 *sig_len 为缓冲区容量，出参为写入字节数（不含结尾 \0）。 */
skey_err_t skey_sign(const char *input, char *sig_b64, size_t *sig_len);

/* 用【本设备】RSA 公钥加密明文 plaintext，输出标准 Base64 密文字符串。
 * 注意：密文只能由本设备私钥（skey_decrypt）解开，属于"自加密"，
 * 不能用于向对端发送机密数据（对端没有本设备私钥）。发给对端请用
 * skey_encrypt_with_pubkey。
 * 明文最大长度 SKEY_PLAINTEXT_MAX（245 字节）。
 * 入参 *ct_len 为缓冲区容量，出参为写入字节数（不含结尾 \0）。 */
skey_err_t skey_encrypt(const char *plaintext, char *ct_b64, size_t *ct_len);

/* 用【对端】公钥加密明文，输出标准 Base64 密文字符串，只有持有对应私钥的
 * 对端能解密。
 * pubkey_pem 支持两种 PEM：
 *   - 裸公钥（BEGIN PUBLIC KEY）
 *   - X.509 证书（BEGIN CERTIFICATE，取其中公钥；PEM 为证书链时取第一张）
 * 明文上限 = RSA 密钥字节数 - 11（RSA-2048 为 245 字节），超长返回 SKEY_ERR_ARGS。
 * 不读取本机 pid 分区，未初始化也可调用。
 * 入参 *ct_len 为缓冲区容量，出参为写入字节数（不含结尾 \0）。 */
skey_err_t skey_encrypt_with_pubkey(const char *pubkey_pem, const char *plaintext,
                                    char *ct_b64, size_t *ct_len);

/* 用 RSA 私钥解密 Base64 密文 ct_b64，输出明文字符串（自动补 '\0'）。
 * 入参 *pt_len 为缓冲区容量，出参为实际写入字节数（不含结尾 \0）。 */
skey_err_t skey_decrypt(const char *ct_b64, char *plaintext, size_t *pt_len);

/* 设置 CA 信任材料 PEM 文件路径（默认 SKEY_CA_PATH_DEFAULT）。
 * 传 NULL 恢复默认路径。文件内容可为裸公钥（BEGIN PUBLIC KEY）
 * 或 CA 证书（BEGIN CERTIFICATE，自动提取其中公钥）。
 * 非线程安全，建议在程序初始化阶段调用一次。 */
void skey_set_ca_path(const char *path);

/* 用 CA 公钥验证 input 的 Base64 签名（RSA-SHA256 PKCS#1 v1.5）。
 * 返回 SKEY_OK 验签通过；SKEY_ERR_VERIFY 签名不匹配；
 * SKEY_ERR_NOT_FOUND 找不到 CA 文件；SKEY_ERR_CRYPTO PEM 解析失败。 */
skey_err_t skey_verify(const char *input, const char *sig_b64);

/* 获取当前加载的 CA 公钥 PEM 字符串（若 CA 文件为证书则提取其中公钥）。
 * 入参 *out_len 为缓冲区容量，出参为写入字节数（不含结尾 \0）。 */
skey_err_t skey_get_ca_pubkey_pem(char *out, size_t *out_len);

/* 生成设备证书签名请求（CSR, PKCS#10 PEM）。
 * 用 pid 分区内设备私钥签名，CN 为设备 ID；私钥不出分区。
 *
 * 【兼容保留】方案 D（公钥钉扎）下不使用此接口：设备身份通过首次联网
 * 注册公钥获得，不需要 CA 签发的设备证书。保留用于需要 X.509 设备证书
 * 的特殊场景。
 * 入参 *out_len 为缓冲区容量（建议 >= SKEY_CSR_PEM_MAX），出参为写入字节数。 */
skey_err_t skey_gen_csr(char *out, size_t *out_len);

/* 读取设备证书链 PEM。
 *
 * 【兼容保留】方案 D 下不使用此接口。设备身份通过公钥钉扎实现。
 * 入参 *out_len 为缓冲区容量（建议 >= SKEY_CERT_CHAIN_MAX），出参为写入字节数。 */
skey_err_t skey_get_device_cert_pem(char *out, size_t *out_len);

/* 设置设备证书链文件路径（默认 SKEY_DEVICE_CERT_PATH_DEFAULT）。
 * 传 NULL 恢复默认路径。 */
void skey_set_device_cert_path(const char *path);

/* 证书链验签：以内置根 CA（ca.pem）为信任锚校验 chain_pem
 * （PEM 文本，第一张为叶子证书，其余为中间 CA，可多张拼接），
 * 链校验通过（链签名、有效期、basicConstraints/pathlen）后，
 * 用叶子证书公钥验证 input 的 Base64 签名。
 * 注意：ca.pem 必须是根证书（裸公钥不支持证书链校验）。
 * 返回 SKEY_OK 通过；SKEY_ERR_VERIFY 链不受信/过期或签名不匹配；
 * SKEY_ERR_NOT_FOUND 根 CA 文件缺失；SKEY_ERR_ARGS chain_pem 解析失败。 */
skey_err_t skey_verify_cert(const char *input, const char *sig_b64,
                            const char *chain_pem);

/* 初始化分区（幂等：已初始化则直接返回 SKEY_OK） */
skey_err_t skey_init(void);

#ifdef __cplusplus
}
#endif

#endif /* SKEY_H */
