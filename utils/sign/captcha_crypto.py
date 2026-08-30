#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""滑块验证码 ``verifyParam`` 的纯 Python 实现（对应 encrypt.js 里的 ``$encrypt``）。

来源是第四套 vm.js 引擎的 AST 反编译（``reverse/vm/`` 默认不入库）。
整体是「32 字节定长头 + 流密码密文」：

===========  ====  ====================================================
偏移          长度  内容
===========  ====  ====================================================
0             4    ``R(0xDEADC0DE)`` 魔数，小端
4             2    ``c(32)`` 头长度，小端
6            10    ``x("00000000000000000003")`` 协议版本，hex 直转
16            2    ``c(4097)`` = 0x1001，小端
18            1    常量 6
19            4    ``R(crc32(appId))`` 小端
23            1    常量 2
24            4    ``R(crc32(密文))`` 小端
28            4    ``R(len(密文))`` 小端
32            n    密文
===========  ====  ====================================================

密文是逐字节 ``out = b ^ keystream``，keystream 来自三路 LFSR 组合生成器
（``z``/f28），和 ``__NS_hxfalcon`` 里的 ``jmpOnw_cts`` 同构，区别有两点：

1. 密钥是硬编码的 ``"ks-seed"``（``q``/f27 里无条件覆盖入参），补齐到 12 字节；
2. 不做 sig4 那个 ``+3`` 偏移，直接异或。

整个过程**没有随机数也没有时间戳**，同一输入恒定产出同一密文，因此可以和
预言机逐字节对拍。
"""

from __future__ import annotations

import base64
import binascii
import urllib.parse
from typing import Iterable

M32 = 0xFFFFFFFF

# z()/f28 里的九个字面量：三条 LFSR 各自的反馈多项式、右移掩码、回填高位
_FEEDBACK = (0x80000062, 0x40000020, 0x10000002)
_MASK = (0x7FFFFFFF, 0x3FFFFFFF, 0x0FFFFFFF)
_HIGH = (0x80000000, 0xC0000000, 0xF0000000)
# q()/f27 里的种子；只有当密钥装填后寄存器为 0 才会用到
_SEED = (324508639, 610839776, 4256789809)

# 顶层闭包变量 v，$encrypt 调 q(payload, v) 时传进去。
# q() 里的 "ks-seed" 只是 a = a || "ks-seed" 的兜底，线上走不到。
CIPHER_KEY = "BvWTr0uRBGH366Yb"
HEADER_LEN = 32
MAGIC = 0xDEADC0DE
_VERSION_HEX = "00000000000000000003"
_FIELD_1001 = 4097
_CONST_6 = 6
_CONST_2 = 2

# 页面 d702 包装器传进来的 appId。AST 里另有一个 "3291d33a-44e7-47f7-a612-301514aa10c8"，
# 但那是 l === "5446" 分支专用的，线上走不到。
APP_ID = "c7b645db-65e8-401f-b38c-4c07c5fff247"


def _crc32(data: bytes) -> int:
    """j()/f25：标准 IEEE CRC-32（表由 Y()/f24 用 0xEDB88320 现场生成）。"""
    return binascii.crc32(data) & M32


def _u16le(value: int) -> bytes:
    """c()/f15：取低 2 字节，小端。"""
    return bytes(((value >> (i * 8)) & 0xFF) for i in range(2))


def _u32le(value: int) -> bytes:
    """R()/f17：取低 4 字节，小端。"""
    return bytes(((value >> (i * 8)) & 0xFF) for i in range(4))


class _Lfsr3:
    """q()+z()：三路 LFSR 组合生成器，每字节输出 8 bit 的钥匙流。"""

    def __init__(self, key: str = CIPHER_KEY):
        # 密钥循环补齐到 12 字节；三条寄存器都用 key[4..7] 装填（AST 如此）
        raw = [ord(ch) & 0xFF for ch in key]
        while len(raw) < 12:
            raw.append(raw[len(raw) - len(key)])
        regs = list(_SEED)
        for i in range(4):
            byte = raw[i + 4]
            for r in range(3):
                regs[r] = ((regs[r] << 8) & M32) | byte
        self.r = [regs[i] or _SEED[i] for i in range(3)]

    def _next(self) -> int:
        r = self.r
        b1, b2 = r[1] & 1, r[2] & 1
        out = 0
        for _ in range(8):
            if r[0] & 1:
                r[0] = ((r[0] ^ (_FEEDBACK[0] >> 1)) | _HIGH[0]) & M32
                if r[1] & 1:
                    r[1] = ((r[1] ^ (_FEEDBACK[1] >> 1)) | _HIGH[1]) & M32
                    b1 = 1
                else:
                    r[1] = (r[1] >> 1) & _MASK[1]
                    b1 = 0
            else:
                r[0] = (r[0] >> 1) & _MASK[0]
                if r[2] & 1:
                    r[2] = ((r[2] ^ (_FEEDBACK[2] >> 1)) | _HIGH[2]) & M32
                    b2 = 1
                else:
                    r[2] = (r[2] >> 1) & _MASK[2]
                    b2 = 0
            out = ((out << 1) | (b1 ^ b2)) & 0xFF
        return out

    def apply(self, data: Iterable[int]) -> bytes:
        return bytes((b ^ self._next()) & 0xFF for b in data)


def _utf16_units(text: str) -> list[int]:
    """W()/f23：``charCodeAt`` 逐位取 UTF-16 码元（非 BMP 会拆成代理对）。"""
    units = []
    for ch in text:
        cp = ord(ch)
        if cp > 0xFFFF:                      # 非 BMP：JS 里存成一对代理
            cp -= 0x10000
            units.append(0xD800 + (cp >> 10))
            units.append(0xDC00 + (cp & 0x3FF))
        else:
            units.append(cp)
    return units


def to_bytes(payload: str) -> bytes:
    """页面包装层 d702 的 ``h()``：``charCodeAt`` 逐位截低 8 位塞进 Uint8Array。

    注意这不是 UTF-8 编码——非 ASCII 字符只保留 UTF-16 码元的低字节，
    和浏览器一样会「丢字」，这里必须照抄这个行为。
    """
    return bytes(u & 0xFF for u in _utf16_units(payload))


def encrypt(payload: str | bytes, app_id: str = APP_ID) -> bytes:
    """$encrypt：明文 -> 带 32 字节头的密文块。"""
    plain = to_bytes(payload) if isinstance(payload, str) else bytes(payload)
    cipher = _Lfsr3().apply(plain)
    return b"".join((
        _u32le(MAGIC),
        _u16le(HEADER_LEN),
        bytes.fromhex(_VERSION_HEX),
        _u16le(_FIELD_1001),
        bytes([_CONST_6]),
        _u32le(_crc32(app_id.encode("utf-8"))),
        bytes([_CONST_2]),
        _u32le(_crc32(cipher)),
        _u32le(len(cipher)),
        cipher,
    ))


def decrypt(blob: bytes) -> str:
    """$encrypt 的逆：剥掉 32 字节头，用同一钥匙流还原明文。"""
    if len(blob) < HEADER_LEN:
        raise ValueError(f"密文块太短：{len(blob)} < {HEADER_LEN}")
    magic = int.from_bytes(blob[:4], "little")
    if magic != MAGIC:
        raise ValueError(f"魔数不对：0x{magic:08X}，应为 0x{MAGIC:08X}")
    declared = int.from_bytes(blob[28:32], "little")
    cipher = blob[HEADER_LEN:]
    if declared != len(cipher):
        raise ValueError(f"长度字段 {declared} 与实际密文 {len(cipher)} 不符")
    checksum = int.from_bytes(blob[24:28], "little")
    if checksum != _crc32(cipher):
        raise ValueError("密文 CRC32 校验失败")
    return _Lfsr3().apply(cipher).decode("latin-1")


def qs_stringify(params: dict) -> str:
    """d702 里的 ``a.a.stringify``，即 npm ``qs`` 包的默认行为。

    要点：按插入顺序输出、键和值都做 ``encodeURIComponent``、空格编成 ``%20``、
    ``null``/``undefined`` 跳过。和 ``JSON.stringify`` 完全是两回事。
    """
    parts = []
    for key, value in params.items():
        if value is None:
            continue
        if isinstance(value, bool):
            value = "true" if value else "false"
        parts.append(f"{_qs_escape(str(key))}={_qs_escape(str(value))}")
    return "&".join(parts)


def _qs_escape(text: str) -> str:
    return urllib.parse.quote(text, safe="*-._", encoding="utf-8")


def verify_param(params: dict, app_id: str = APP_ID) -> str:
    """业务入口：参数字典 -> 可直接放进请求体的 base64 ``verifyParam``。"""
    return base64.b64encode(encrypt(qs_stringify(params), app_id)).decode("ascii")
