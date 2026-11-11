# skey

> MonkFish IoT 设备密钥与签名工具 —— 身份根来自硬件分区，私钥加密落盘，换板即失效。

**项目文档网站：<http://monkfish.cn>**

`skey` 是运行在 MonkFish IoT 设备上的轻量级设备身份组件。它从 Factory / ART 分区读取
硬件 MAC，派生出仅本机可得的 AES 密钥，生成 UUID v4 与 RSA-2048 密钥对，加密写入
`product-uid` 与 `product-backup` 两个 MTD 分区，并对外提供获取设备标识、签名、
加解密与验签的 CLI 和 C 静态库。

- 语言：C（C99）· 平台：OpenWrt · 依赖：`libopenssl`（OpenSSL 3.x）
- 产物：`/usr/bin/skey`、`/usr/lib/libskey.a`、`/usr/include/skey.h`
- 归属：MonkFish IoT 设备侧组件，服务于云端集中管理平台的设备身份体系

## 解决什么问题

批量部署的 MonkFish IoT 设备需要一个**无法复制、无法伪造、重启不丢**的身份。把私钥放在
rootfs 里，固件一刷就没；把私钥明文存分区，拷走分区就能冒用。`skey` 的做法是把密钥
材料和硬件绑定：AES 密钥由 Factory 分区内容派生，分区数据整体加密并带 HMAC 校验，
同一份镜像烧到另一台设备上无法解出可用身份。

## 核心特性

| 特性 | 说明 |
|------|------|
| 硬件绑定 | AES 密钥 = `SHA256(Factory分区[0:16] ‖ salt)[0:16]`，离开本机分区无法复现 |
| 加密存储 | UUID 与 RSA-2048 密钥对经 AES-128-CBC 加密，HMAC-SHA256 校验完整性 |
| 双分区冗余 | 主用 `product-uid`，镜像写 `product-backup`，主分区损坏时自动回退 |
| 幂等初始化 | `skey init` 重复执行安全；已初始化直接返回 `OK`，不重写分区 |
| 身份查询 | 输出 MAC、22 字符 BASE62 设备 ID、22 字符 URL-safe Base64 UUID |
| 签名验签 | RSA-SHA256（PKCS#1 v1.5）签名，支持本机公钥与 CA 公钥/证书链验签 |
| 数据加解密 | `encrypt` / `encrypt-to` / `decrypt` 三条路径，私钥不出分区 |
| 两种形态 | 命令行工具 + `libskey.a` 静态库，其他 C 程序可直接链接 |
| 免产线烧录 | 身份在设备首次启动时自生成，不需要逐台签发设备证书 |

## 工作流程

```
首次启动（skey init，幂等）
  Factory / ART 分区
        │ 读取 MAC（Factory@0x4 / art@0x1002，字内字节交换）
        ▼
  派生 AES-128 密钥 + 魔术字 SHA256(MAC)[0:4]
        ▼
  生成 UUID v4 + RSA-2048 密钥对
        ▼
  打包 1792 字节结构 → AES-CBC 加密 → HMAC-SHA256
        ▼
  product-uid  ←→  product-backup

运行期读取（只读）
  product-uid 校验通过 → 直接使用
  校验失败 / 缺失     → 回退 product-backup
```

初始化有两条自动途径：开机脚本 `/etc/init.d/skey`（`S99skey`，仅执行一次）与库的
惰性初始化（首次调用需要密钥的接口时自动完成）。仅当两个分区都无效时才会重新生成
身份，单份损坏时用另一份修复，设备 ID 不变。

## 分区与存储结构

依赖的 MTD 分区按 `/proc/mtd` 中的名字查找，大小写敏感：

| 分区名 | 必需 | 用途 |
|--------|------|------|
| `Factory`（MTK）或 `art`（高通） | 是 | 读取 MAC、派生 AES 密钥 |
| `product-uid` | 是 | 主存储区 |
| `product-backup` | 否 | 备份区，内容与主区一致 |

每个分区固定存储 1792 字节：

```
偏移    长度    字段
0       4       Magic = SHA256(MAC)[0:4]（明文）
4       1       Version = 1（明文）
5       11      Reserved（明文）
16      16      IV（明文）
32      16      UUID V4（加密主体起始）
48      300     RSA 公钥 SubjectPublicKeyInfo DER（加密）
348     1400    RSA 私钥 PKCS#8 PrivateKeyInfo DER（加密）
1748    12      Reserved（加密，补齐到 1728 字节）
1760    32      HMAC-SHA256(iv ‖ ciphertext)
```

写入顺序为先 `product-uid`、校验通过后镜像到 `product-backup`；读取时 Magic 不匹配
视为未初始化，HMAC 失败则回退 backup。

## 实现要点

- **MTD 操作**：解析 `/proc/mtd` 定位设备节点，`pread` 读取；擦写前 `MEMUNLOCK`，
  按 `MEMGETINFO` 返回的 erasesize 分块 `MEMERASE`，不硬编码块大小。
- **密钥派生**：`AES_key = SHA256(Factory[0:16] ‖ 固定盐)[0:16]`，
  `magic = SHA256(MAC)[0:4]`，盐由函数返回，便于后续换版本。
- **加密**：AES-128-CBC + NoPadding（主体已按 16 字节对齐），HMAC 复用 AES 密钥。
- **编码**：设备 ID 把 UUID 当大端 128 位整数做 BASE62 长除法，左补 `0` 到 22 字符；
  UUID 字符串为 URL-safe Base64（`-`/`_` 替换 `+`/`/`、去掉 `=`）。
- **密钥管理**：公钥存 SPKI DER、私钥存 PKCS#8 DER，固定区不足补零，超长直接报错不截断。
- **签名**：`EVP_DigestSign` + SHA-256 + PKCS#1 v1.5，输出标准 Base64（256 字节签名）。

## 命令行

| 子命令 | 说明 |
|--------|------|
| `skey init` | 幂等初始化分区 |
| `skey get-mac` | 输出 `E4:67:1E:85:08:AE` |
| `skey get-device-id` | 22 字符 BASE62 设备 ID，可作云端主键 |
| `skey get-uuid` | 22 字符 URL-safe Base64 UUID |
| `skey get-pubkey` | RSA-2048 公钥 PEM |
| `skey sign <str>` | RSA-SHA256 签名，输出 Base64 |
| `skey encrypt <str>` | 用本机公钥加密（自加密，只有本机能解） |
| `skey encrypt-to <pub.pem> <str>` | 用对端公钥或 X.509 证书加密 |
| `skey decrypt <b64>` | 用本机私钥解密 |
| `skey get-ca-pubkey` | 输出内置 CA 公钥 PEM |
| `skey verify <str> <sig>` | 用 CA 公钥验签 |
| `skey gen-csr` / `get-device-cert` / `verify-cert` | X.509 设备证书场景（兼容保留） |

无参数执行 `skey` 查看完整帮助。`encrypt` 是"自己加密给自己"，向上游发送机密数据
必须用 `encrypt-to` 并传入对端公钥或证书。

## C 库接口

第三方程序链接 `libskey.a`（头文件已带 `extern "C"`，支持 C/C++）：

```c
#include <skey.h>

char mac[18], devid[23], uuid[23];
skey_get_mac(mac);
skey_get_device_id(devid);
skey_get_uuid(uuid);

char sig[SKEY_SIG_B64_MAX]; size_t sig_len = sizeof(sig);
skey_sign("hello", sig, &sig_len);
```

```bash
gcc -o myapp myapp.c -lskey -lcrypto
```

核心接口：`skey_init`、`skey_get_mac`、`skey_get_device_id`、`skey_get_uuid`、
`skey_get_pubkey_pem`、`skey_sign`、`skey_encrypt`、`skey_encrypt_with_pubkey`、
`skey_decrypt`、`skey_set_ca_path`、`skey_verify`、`skey_verify_cert`。
所有函数返回 `skey_err_t`，字符串由调用方分配缓冲区。RSA PKCS#1 v1.5 单条明文
上限 245 字节（RSA-2048），更长数据需自行做混合加密。

| 错误码 | 值 | 含义 |
|--------|-----|------|
| `SKEY_OK` | 0 | 成功 |
| `SKEY_ERR_NOT_FOUND` | -1 | 找不到 MTD 分区 / CA 文件 |
| `SKEY_ERR_IO` | -2 | MTD 读写错误 |
| `SKEY_ERR_CORRUPT` | -3 | HMAC 校验失败 / 数据损坏 |
| `SKEY_ERR_CRYPTO` | -4 | OpenSSL 操作失败 |
| `SKEY_ERR_NOT_INIT` | -5 | 分区未初始化 |
| `SKEY_ERR_ARGS` | -6 | 参数错误 / 缓冲区不足 |
| `SKEY_ERR_VERIFY` | -7 | 验签失败或证书链不受信 |

## 服务器集成

采用**方案 D：混合双向认证**，服务器不需要给每台设备签发证书。

```
设备验证服务器：设备内置根 CA（/etc/skey/ca.pem）校验服务器证书链
服务器验证设备：首次注册公钥（公钥钉扎），此后 nonce 挑战 + 签名验签
```

- **公钥注册** `POST /device/register`：提交 `device_id`（22 字符 BASE62）、
  `pubkey_pem`、`signature`（对 `device_id + pubkey_pem` 的签名）。服务端校验格式、
  用公钥验签后写入 `device_pubkey` 表；同 ID 同公钥幂等，公钥不同返回冲突。
- **身份认证**：`POST /auth/challenge` 下发一次性 nonce（建议 ≥16 字节、TTL 120 秒），
  设备用 `skey_sign` 签 nonce，`POST /auth/verify` 提交后服务端查库验签并颁发 token。
- **运维建议**：`device_pubkey` 建 `device_id` 主键与状态索引；nonce 用 Redis 或内存
  缓存存储并在验签后立即删除；验签算法固定 RSA-SHA256 PKCS#1 v1.5。

## CA 部署与运维

- CA 私钥只保存在**物理隔离的离线主机**，既不上设备也不上服务器；设备只信任
  `/etc/skey/ca.pem` 中的 CA 公钥（证书或裸公钥，程序自动识别）。
- 服务器证书由该 CA 签发（`server.chain.pem` = 服务器证书 + CA 证书，叶子在前），
  设备用 `skey verify-cert` 走完整链校验（签名、有效期、basicConstraints）。
- CA 材料放在文件系统，不占 `product-uid` 分区；更换 CA 只需替换固件中的 `ca.pem`。
- 必须备份 CA 私钥与证书（离线介质双份）；私钥丢失将无法再签发新服务器证书，
  只能轮换 CA 并下发新的 `ca.pem`。

## 构建与安装

```bash
# 在 OpenWrt SDK 根目录
make package/monkfish/skey/compile V=s
opkg install bin/targets/*/packages/skey_1.0-1_*.ipk
```

安装后提供 `/usr/bin/skey`、`/usr/lib/libskey.a`、`/usr/include/skey.h`、
`/etc/init.d/skey`，并在镜像内创建 `S99skey` 软链以保证首启自动初始化。

## 约束

- 需要 root 权限访问 `/dev/mtdN`；分区名固定且大小写敏感。
- 设计上只在首次烧录后写入，运行期只读，不考虑并发写入与残留数据处理。
- 设备身份一经生成即与硬件绑定，整片擦除两个分区会导致设备 ID 变化。
- 目标平台为 OpenWrt（mipsel / arm / aarch64 交叉编译），加密原语依赖 OpenSSL 3.x。

## 许可证

Copyright 2026 MonkFish IoT

本项目以 **Apache License 2.0** 发布，许可证全文见 `LICENSE`，第三方组件与归属声明见
`NOTICE`。使用、修改与再分发须遵守许可证条款，并保留版权、许可与归属声明。

