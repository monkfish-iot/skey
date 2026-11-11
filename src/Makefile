# Copyright 2026 MonkFish IoT
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

# src/Makefile - 编译 skey 命令与 libskey.a 静态库
#
# 由 OpenWrt package Makefile 通过 CC/CFLAGS/LDFLAGS/AR 注入交叉编译工具链。
# 也可在宿主机直接 make 用于本地语法/单元测试（需 OpenSSL 与 mtd-user.h）。

CC      ?= gcc
AR      ?= ar
CFLAGS  ?= -O2 -Wall -Wextra
CFLAGS  += -I. -Wno-deprecated-declarations
override LDFLAGS += -lcrypto

LIB_OBJS = mtd.o factory.o crypto.o encoding.o pid_struct.o pid.o

HEADERS = skey.h skey_internal.h

all: skey libskey.a

skey: skey_cli.o libskey.a
	$(CC) $(CFLAGS) -o $@ skey_cli.o libskey.a $(LDFLAGS)

libskey.a: $(LIB_OBJS)
	$(AR) rcs $@ $(LIB_OBJS)

%.o: %.c $(HEADERS)
	$(CC) $(CFLAGS) -c -o $@ $<

clean:
	rm -f skey libskey.a *.o

install: all
	install -D -m 0755 skey $(DESTDIR)/usr/bin/skey
	install -D -m 0644 libskey.a $(DESTDIR)/usr/lib/libskey.a
	install -D -m 0644 skey.h $(DESTDIR)/usr/include/skey.h

.PHONY: all clean install
