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
 * mtd.c - MTD 分区查找与读写擦
 *
 * 通过 /proc/mtd 按名字查找分区，用 /dev/mtdN + ioctl 读写。
 * 不使用 mtdblock，避开 page cache 一致性问题。
 *
 * 诊断：所有失败点会记录"操作 + 设备 + errno 原因"，
 * 可通过 mtd_last_error() / skey_last_error() 取到最近一条错误描述。
 */

#include "skey_internal.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <fcntl.h>
#include <unistd.h>
#include <errno.h>
#include <sys/ioctl.h>
#include <mtd/mtd-user.h>

static char g_mtd_err[320];

const char *mtd_last_error(void)
{
    return g_mtd_err[0] ? g_mtd_err : NULL;
}

static void mtd_seterr(const char *fmt, ...)
{
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(g_mtd_err, sizeof(g_mtd_err), fmt, ap);
    va_end(ap);
}

int mtd_find_by_name(const char *name, char *devpath, size_t len)
{
    g_mtd_err[0] = '\0';

    FILE *fp = fopen("/proc/mtd", "r");
    if (!fp) {
        mtd_seterr("open /proc/mtd: %s", strerror(errno));
        return -1;
    }

    char line[256];
    int idx = -1;
    while (fgets(line, sizeof(line), fp)) {
        int i;
        char nm[128];
        /* 形如: mtd2: 00200000 00020000 "Factory" */
        if (sscanf(line, "mtd%d: %*x %*x \"%127[^\"]\"", &i, nm) == 2) {
            if (strcmp(nm, name) == 0) {
                idx = i;
                break;
            }
        }
    }
    fclose(fp);

    if (idx < 0) {
        mtd_seterr("partition \"%s\" not found in /proc/mtd", name);
        return -1;
    }
    snprintf(devpath, len, "/dev/mtd%d", idx);
    return 0;
}

int mtd_read(const char *dev, off_t off, void *buf, size_t len)
{
    g_mtd_err[0] = '\0';

    int fd = open(dev, O_RDONLY);
    if (fd < 0) {
        mtd_seterr("open %s O_RDONLY: %s", dev, strerror(errno));
        return -1;
    }
    ssize_t r = pread(fd, buf, len, off);
    close(fd);
    if (r != (ssize_t)len) {
        mtd_seterr("pread %s off=0x%lx len=%u: short read (%zd): %s",
                   dev, (unsigned long)off, (unsigned)len, r,
                   strerror(errno));
        return -1;
    }
    return 0;
}

static int mtd_get_erasesize(const char *dev, size_t *erasesize)
{
    int fd = open(dev, O_RDONLY);
    if (fd < 0) {
        mtd_seterr("open %s O_RDONLY: %s", dev, strerror(errno));
        return -1;
    }
    mtd_info_t info;
    if (ioctl(fd, MEMGETINFO, &info) < 0) {
        mtd_seterr("MEMGETINFO %s: %s", dev, strerror(errno));
        close(fd);
        return -1;
    }
    *erasesize = info.erasesize;
    close(fd);
    return 0;
}

int mtd_erase(const char *dev, off_t off, size_t len)
{
    g_mtd_err[0] = '\0';

    size_t erasesize;
    if (mtd_get_erasesize(dev, &erasesize) < 0)
        return -1;   /* 错误已由 mtd_get_erasesize 记录 */
    if (erasesize == 0) {
        mtd_seterr("%s: invalid erasesize 0", dev);
        return -1;
    }

    int fd = open(dev, O_RDWR);
    if (fd < 0) {
        mtd_seterr("open %s O_RDWR: %s", dev, strerror(errno));
        return -1;
    }

    /* 先解锁（部分平台不支持，忽略返回值） */
    struct erase_info_user eu;
    eu.start = off;
    eu.length = len;
    ioctl(fd, MEMUNLOCK, &eu);

    /* 按擦除块大小分块擦除；末块长度向上对齐到 erasesize
     * （MEMERASE 多数平台要求长度为 erasesize 整数倍） */
    size_t done = 0;
    while (done < len) {
        struct erase_info_user ein;
        ein.start = off + done;
        ein.length = erasesize;
        if (ioctl(fd, MEMERASE, &ein) < 0) {
            mtd_seterr("MEMERASE %s @0x%lx len=%u: %s",
                       dev, (unsigned long)ein.start, (unsigned)ein.length,
                       strerror(errno));
            close(fd);
            return -1;
        }
        done += erasesize;
    }
    close(fd);
    return 0;
}

int mtd_write(const char *dev, off_t off, const void *buf, size_t len)
{
    g_mtd_err[0] = '\0';

    int fd = open(dev, O_RDWR);
    if (fd < 0) {
        mtd_seterr("open %s O_RDWR: %s", dev, strerror(errno));
        return -1;
    }
    /* 解锁（幂等，erase 已解锁，这里再保险；不支持则忽略） */
    struct erase_info_user eu;
    eu.start = off;
    eu.length = len;
    ioctl(fd, MEMUNLOCK, &eu);

    if (lseek(fd, off, SEEK_SET) < 0) {
        mtd_seterr("lseek %s off=0x%lx: %s", dev, (unsigned long)off,
                   strerror(errno));
        close(fd);
        return -1;
    }
    ssize_t w = write(fd, buf, len);
    if (w != (ssize_t)len) {
        mtd_seterr("write %s off=0x%lx len=%u: short write (%zd): %s",
                   dev, (unsigned long)off, (unsigned)len, w,
                   strerror(errno));
        close(fd);
        return -1;
    }
    close(fd);
    return 0;
}
