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
 * skey_cli.c - skey 命令行入口
 *
 * 子命令:
 *   init
 *   get-mac
 *   get-device-id
 *   get-uuid
 *   get-pubkey
 *   sign <input-string>
 *   encrypt <plaintext>                (self: own public key)
 *   encrypt-to <pubkey.pem> <plaintext> (peer public key / certificate)
 *   decrypt <ciphertext-base64>
 *   get-ca-pubkey
 *   verify <input-string> <signature-base64>
 *   gen-csr
 *   get-device-cert
 *   verify-cert <input-string> <signature-base64> <chain-pem-file>
 *
 * 输入参数全部按字符串处理，错误输出到 stderr 并返回非 0 退出码。
 */

#include "skey.h"

#include <stdio.h>
#include <string.h>
#include <stdlib.h>

/* 读取整个文件到 malloc 缓冲区（调用方 free），失败返回 NULL。 */
static char *read_text_file(const char *path, size_t max)
{
    FILE *f = fopen(path, "rb");
    if (!f)
        return NULL;
    char *buf = malloc(max + 1);
    if (!buf) {
        fclose(f);
        return NULL;
    }
    size_t n = fread(buf, 1, max, f);
    fclose(f);
    buf[n] = '\0';
    return buf;
}

/* 统一错误输出：错误码 + 底层原因（如 MTD 操作与 errno）。 */
static int fail(const char *cmd, skey_err_t r)
{
    const char *e = skey_last_error();
    fprintf(stderr, "%s failed: %d%s%s\n", cmd, (int)r,
            e ? ": " : "", e ? e : "");
    return 1;
}

static void usage(const char *prog)
{
    fprintf(stderr,
        "Usage: %s <command> [args]\n"
        "Commands:\n"
        "  init              initialize product-uid/backup (idempotent)\n"
        "  get-mac           print MAC address\n"
        "  get-device-id     print device id (BASE62)\n"
        "  get-uuid          print UUID (URL-safe Base64)\n"
        "  get-pubkey        print RSA public key in PEM\n"
        "  sign <input>      sign input string, print Base64 signature\n"
        "  encrypt <pt>      encrypt with OWN public key (self-encrypt), print Base64\n"
        "  encrypt-to <pub.pem> <pt>  encrypt with PEER public key/cert, print Base64\n"
        "  decrypt <ct_b64>  decrypt Base64 ciphertext with own private key, print plaintext\n"
        "  get-ca-pubkey     print built-in CA public key in PEM\n"
        "  verify <input> <sig_b64>  verify Base64 signature with CA public key\n"
        "  gen-csr           print device CSR (PKCS#10 PEM), CN=device-id\n"
        "  get-device-cert   print device certificate chain PEM\n"
        "  verify-cert <input> <sig_b64> <chain.pem>  verify with cert chain\n",
        prog);
}

int main(int argc, char **argv)
{
    if (argc < 2) {
        usage(argv[0]);
        return 1;
    }

    const char *cmd = argv[1];

    if (strcmp(cmd, "init") == 0) {
        skey_err_t r = skey_init();
        if (r != SKEY_OK) {
            fprintf(stderr, "init failed: %d\n", r);
            return 1;
        }
        printf("OK\n");
        return 0;
    }

    if (strcmp(cmd, "get-mac") == 0) {
        char mac[SKEY_MAC_STR_LEN];
        skey_err_t r = skey_get_mac(mac);
        if (r != SKEY_OK) {
            fprintf(stderr, "get-mac failed: %d\n", r);
            return 1;
        }
        printf("%s\n", mac);
        return 0;
    }

    if (strcmp(cmd, "get-device-id") == 0) {
        char id[SKEY_DEVICE_ID_BUF];
        skey_err_t r = skey_get_device_id(id);
        if (r != SKEY_OK) {
            fprintf(stderr, "get-device-id failed: %d\n", r);
            return 1;
        }
        printf("%s\n", id);
        return 0;
    }

    if (strcmp(cmd, "get-uuid") == 0) {
        char u[SKEY_UUID_BUF];
        skey_err_t r = skey_get_uuid(u);
        if (r != SKEY_OK) {
            fprintf(stderr, "get-uuid failed: %d\n", r);
            return 1;
        }
        printf("%s\n", u);
        return 0;
    }

    if (strcmp(cmd, "get-pubkey") == 0) {
        char pem[SKEY_PUBKEY_PEM_MAX];
        size_t len = sizeof(pem);
        skey_err_t r = skey_get_pubkey_pem(pem, &len);
        if (r != SKEY_OK)
            return fail("get-pubkey", r);
        printf("%s", pem);
        return 0;
    }

    if (strcmp(cmd, "sign") == 0) {
        if (argc < 3) {
            fprintf(stderr, "sign needs input string\n");
            return 1;
        }
        char sig[SKEY_SIG_B64_MAX];
        size_t slen = sizeof(sig);
        skey_err_t r = skey_sign(argv[2], sig, &slen);
        if (r != SKEY_OK)
            return fail("sign", r);
        printf("%s\n", sig);
        return 0;
    }

    if (strcmp(cmd, "encrypt") == 0) {
        if (argc < 3) {
            fprintf(stderr, "encrypt needs plaintext string (max %d bytes)\n", SKEY_PLAINTEXT_MAX);
            return 1;
        }
        char ct[SKEY_ENC_B64_MAX];
        size_t clen = sizeof(ct);
        skey_err_t r = skey_encrypt(argv[2], ct, &clen);
        if (r != SKEY_OK)
            return fail("encrypt", r);
        printf("%s\n", ct);
        return 0;
    }

    if (strcmp(cmd, "encrypt-to") == 0) {
        if (argc < 4) {
            fprintf(stderr, "encrypt-to needs <pubkey.pem> <plaintext>\n");
            return 1;
        }
        char *pem = read_text_file(argv[2], 8192);
        if (!pem) {
            fprintf(stderr, "cannot read public key file: %s\n", argv[2]);
            return 1;
        }
        char ct[1024];   /* 覆盖 RSA-4096 密文的 Base64（684 字符） */
        size_t clen = sizeof(ct);
        skey_err_t r = skey_encrypt_with_pubkey(pem, argv[3], ct, &clen);
        free(pem);
        if (r != SKEY_OK)
            return fail("encrypt-to", r);
        printf("%s\n", ct);
        return 0;
    }

    if (strcmp(cmd, "decrypt") == 0) {
        if (argc < 3) {
            fprintf(stderr, "decrypt needs Base64 ciphertext\n");
            return 1;
        }
        char pt[SKEY_DEC_BUF_MAX];
        size_t plen = sizeof(pt);
        skey_err_t r = skey_decrypt(argv[2], pt, &plen);
        if (r != SKEY_OK)
            return fail("decrypt", r);
        printf("%s\n", pt);
        return 0;
    }

    if (strcmp(cmd, "get-ca-pubkey") == 0) {
        char pem[SKEY_CA_PUBKEY_PEM_MAX];
        size_t len = sizeof(pem);
        skey_err_t r = skey_get_ca_pubkey_pem(pem, &len);
        if (r != SKEY_OK)
            return fail("get-ca-pubkey", r);
        printf("%s", pem);
        return 0;
    }

    if (strcmp(cmd, "verify") == 0) {
        if (argc < 4) {
            fprintf(stderr, "verify needs <input> <sig_b64>\n");
            return 1;
        }
        skey_err_t r = skey_verify(argv[2], argv[3]);
        if (r == SKEY_OK) {
            printf("OK\n");
            return 0;
        }
        return fail("verify", r);
    }

    if (strcmp(cmd, "gen-csr") == 0) {
        char csr[SKEY_CSR_PEM_MAX];
        size_t len = sizeof(csr);
        skey_err_t r = skey_gen_csr(csr, &len);
        if (r != SKEY_OK)
            return fail("gen-csr", r);
        printf("%s", csr);
        return 0;
    }

    if (strcmp(cmd, "get-device-cert") == 0) {
        char pem[SKEY_CERT_CHAIN_MAX];
        size_t len = sizeof(pem);
        skey_err_t r = skey_get_device_cert_pem(pem, &len);
        if (r != SKEY_OK)
            return fail("get-device-cert", r);
        printf("%s", pem);
        return 0;
    }

    if (strcmp(cmd, "verify-cert") == 0) {
        if (argc < 5) {
            fprintf(stderr, "verify-cert needs <input> <sig_b64> <chain.pem>\n");
            return 1;
        }
        char *chain = read_text_file(argv[4], SKEY_CERT_CHAIN_MAX);
        if (!chain) {
            fprintf(stderr, "cannot read chain file: %s\n", argv[4]);
            return 1;
        }
        skey_err_t r = skey_verify_cert(argv[2], argv[3], chain);
        free(chain);
        if (r == SKEY_OK) {
            printf("OK\n");
            return 0;
        }
        return fail("verify-cert", r);
    }

    usage(argv[0]);
    return 1;
}
