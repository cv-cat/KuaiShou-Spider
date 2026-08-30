#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""``__NS_sig3`` 纯算签名器（cp.kuaishou.com 侧）。

作用域：url 命中 ``/rest/cp`` / ``rest/v2/creator`` / ``/rest/kd`` 的请求（发布链路）。
产物写入 query ``__NS_sig3``，是 56 个 hex 字符（28 字节）。

签名输入（onvideo-index-secondary 明文源码，**非 VMP，权威**）：
    const request2SortedString = eo =>
        sortObjKeyByAscii(eo).reduce((_i, ro) => _i + ro + "=" + encodeURI(eo[ro]), "");
    function request2Md5(type, params, query){
        let no = {...query}, io = "";
        switch(type){
            case "form-data": no = {...no, ...params}; break;   // body 并入 query 一起排序
            case "json":      io = "".concat(JSON.stringify(params)); break;
        }
        return md5(request2SortedString(no) + io);
    }
    function request2Sig3(type, params, query){
        en.call("$encode", [request2Md5(type, params, query), {suc, err}]);  // en = kwf VMP
    }
    async function getUrlWithSig3({url, type, params}){
        if (url.indexOf("/rest/cp") < 0 && url.indexOf("rest/v2/creator") < 0
            && url.indexOf("/rest/kd") < 0) return url;
        const query = parseQuery(url);      // 无 "?" 时为 {}
        ...  url + (has"?" ? "&" : "?") + "__NS_sig3=" + sig
    }

**关键：签名输入里没有 path，也没有 method**——只有 query + body。实测印证：4 个不同路径、
相同 body（都只有 api_ph）的请求，摘要字节完全一致。

``en`` 引擎（app bundle 内联的 vm.js 解释器 + LZW 压缩的序列化 AST，非 VMP 字节码）已完整
反编译。``reverse/vm/`` 默认不入库，本地需要的话自己从 bundle 解。``$encode`` 原样如下：

    function $encode(input, cb) {
        var o = j(p(d(D(p(d($(input)), l[0].slice()))), l[1].slice())[0], true);
        var f = "5445" + "0130"
              + j(this.startupRandom || 100, false)   // 引擎构造时刻的 unix 秒
              + j(this.count || 100, false)           // 调用序号，构造时 100
              + o                                     // 4 字节摘要
              + j(1653548225, false) + "01000100" + "000000";
        this.count += 1;
        return s(f + g(f));                           // g = 校验字节，s = 异或容器
    }

28 字节明文布局（见 SIG3_LAYOUT）：魔数 "TE" / 版本 0130 / startupRandom(LE) / count(LE) /
摘要(BE) / 常量 1653548225(LE) / 01 00 01 00 00 00 00 / 校验字节。
容器 ``s()``：以末字节（校验字节）为密钥，``out[i] = plain[i] ^ key ^ i``，末字节原样保留。
摘要 ``o``：两轮**自定义初始向量**的 SHA-256，第二轮直接吃第一轮的大端字节串（不再 UTF-8 编码），
且消息长度字段写的是 ``(len + 63) * 8`` 而非标准的原文比特数。

所以明文里没有任何设备/会话令牌，全部可自产：``startupRandom`` 与 ``count`` 由签名器自己维护。

校验（reverse/tools/）：
    ✅ 5 条真实抓包 —— decode 后魔数/版本/常量/尾部/校验字节全中，且能逐字节重放
    ✅ 300 条 Node 预言机基准（真实 en 引擎，sig3_oracle.js）—— 端到端逐字节一致

对外统一门面在 ``utils.ks_util.generate_sig3(url, query, body, req_type)``。
"""

from __future__ import annotations

import hashlib
import math
import time
import urllib.parse

from utils.sign.falcon_pure import cp_need_sign
from utils.sign.jsval import encode_uri, js_json_stringify, js_sorted

# url 命中任一标记才走 sig3（getUrlWithSig3 的前置判断）。
SIG3_URL_MARKERS = ("/rest/cp", "rest/v2/creator", "/rest/kd")


def need_sig3(url: str) -> bool:
    """该 url 是否需要 ``__NS_sig3``（命中 sig3 域且不属于 cp sig4 名单）。"""
    if not url or not any(marker in url for marker in SIG3_URL_MARKERS):
        return False
    return not cp_need_sign(url)


def parse_query(url: str) -> dict:
    """对齐 JS ``parseQuery``：取 url 最后一个 ``?`` 之后的部分解析为 dict。

    :param url: 完整 url 或 ``path?query``；无 ``?`` 时返回空 dict。
    :return: 解码后的 query dict。
    """
    parts = (url or "").split("?")
    tail = parts[-1]
    if tail == url:
        return {}
    query = {}
    for item in tail.split("&"):
        pair = item.split("=")
        if not pair[0]:
            continue
        key = urllib.parse.unquote(pair[0])
        query[key] = urllib.parse.unquote(pair[1] if len(pair) > 1 else "")
    return query


def request2_sorted_string(obj: dict) -> str:
    """对齐 JS ``request2SortedString``：key 升序后拼 ``k=encodeURI(v)``（无分隔符）。

    排序用 JS 默认序（UTF-16 码元），与 Python 的码点序在星平面字符上不同。
    """
    if not isinstance(obj, dict):
        return ""
    by_str = {str(k): v for k, v in obj.items()}
    return "".join(f"{k}={encode_uri(by_str[k])}" for k in js_sorted(by_str))


def request2_md5(query: dict = None, body=None, req_type: str = "json") -> str:
    """对齐 JS ``request2Md5``，产出送入 ``en.call("$encode")`` 的 32 位小写 hex。

    :param query: url 上的 query dict（parse_query 的产物）。
    :param body: 请求体（cp 侧恒为 dict，且已并入 ``kuaishou.web.cp.api_ph``）。
    :param req_type: ``json``（POST JSON）或 ``form-data``（postFormUrlencoded）。
    :return: 32 位小写 md5 hex。
    """
    merged = dict(query or {})
    suffix = ""
    if req_type == "form-data":
        merged.update(body or {})
    elif req_type == "json":
        suffix = js_json_stringify(body if body is not None else {})
    plain = request2_sorted_string(merged) + suffix
    return hashlib.md5(plain.encode("utf-8")).hexdigest()


# --------------------------------------------------------------------------- #
# 4 字节摘要 o：双轮自定义 IV 的 SHA-256                                        #
# --------------------------------------------------------------------------- #
_MASK32 = 0xFFFFFFFF

# 标准 SHA-256 轮常量（引擎变量 b）。
_SHA256_K = (
    0x428A2F98, 0x71374491, 0xB5C0FBCF, 0xE9B5DBA5, 0x3956C25B, 0x59F111F1, 0x923F82A4, 0xAB1C5ED5,
    0xD807AA98, 0x12835B01, 0x243185BE, 0x550C7DC3, 0x72BE5D74, 0x80DEB1FE, 0x9BDC06A7, 0xC19BF174,
    0xE49B69C1, 0xEFBE4786, 0x0FC19DC6, 0x240CA1CC, 0x2DE92C6F, 0x4A7484AA, 0x5CB0A9DC, 0x76F988DA,
    0x983E5152, 0xA831C66D, 0xB00327C8, 0xBF597FC7, 0xC6E00BF3, 0xD5A79147, 0x06CA6351, 0x14292967,
    0x27B70A85, 0x2E1B2138, 0x4D2C6DFC, 0x53380D13, 0x650A7354, 0x766A0ABB, 0x81C2C92E, 0x92722C85,
    0xA2BFE8A1, 0xA81A664B, 0xC24B8B70, 0xC76C51A3, 0xD192E819, 0xD6990624, 0xF40E3585, 0x106AA070,
    0x19A4C116, 0x1E376C08, 0x2748774C, 0x34B0BCB5, 0x391C0CB3, 0x4ED8AA4A, 0x5B9CCA4F, 0x682E6FF3,
    0x748F82EE, 0x78A5636F, 0x84C87814, 0x8CC70208, 0x90BEFFFA, 0xA4506CEB, 0xBEF9A3F7, 0xC67178F2,
)

# 两轮各自的自定义初始向量（引擎变量 l），非标准 SHA-256 IV。
# 保留源码里的有符号十进制原值，避免手工转 hex 出错。
_SIG3_IV = tuple(
    tuple(v & _MASK32 for v in row) for row in (
        (1201087869, 728038316, -1247317401, -375217708, -1820116536, 395408228, 1482956210, -1904517706),
        (-932960537, -839864669, 895983619, 323220038, 1908748190, 778712444, -2022813415, -1089440689),
    )
)


def _rotr(x: int, n: int) -> int:
    return ((x >> n) | (x << (32 - n))) & _MASK32


def _sha256_blocks(msg: str) -> list:
    """对齐引擎的 ``d()``：追加 0x80，切 16 字大端块，末尾写比特长度。

    注意长度字段是 ``(len + 63) * 8``（len 已含 0x80），而非标准 SHA-256 的原文比特数。
    """
    msg += chr(0x80)
    total = math.ceil((len(msg) / 4 + 2) / 16)
    out = []
    for i in range(total):
        block = []
        for j in range(16):
            word = 0
            for b in range(4):
                idx = i * 64 + j * 4 + b
                # JS 里越界的 charCodeAt 返回 NaN，移位后等价于 0
                word |= (ord(msg[idx]) if idx < len(msg) else 0) << (24 - 8 * b)
            block.append(word & _MASK32)
        out.append(block)
    bits = (len(msg) + 63) * 8
    out[-1][14] = (bits >> 32) & _MASK32
    out[-1][15] = bits & _MASK32
    return out


def _sha256_compress(blocks: list, iv: tuple) -> list:
    """对齐引擎的 ``p()``：标准 SHA-256 压缩，仅初始向量被替换。"""
    h = list(iv)
    for block in blocks:
        w = list(block)
        for t in range(16, 64):
            s0 = _rotr(w[t - 15], 7) ^ _rotr(w[t - 15], 18) ^ (w[t - 15] >> 3)
            s1 = _rotr(w[t - 2], 17) ^ _rotr(w[t - 2], 19) ^ (w[t - 2] >> 10)
            w.append((w[t - 16] + s0 + w[t - 7] + s1) & _MASK32)
        a, b, c, d, e, f, g, hh = h
        for t in range(64):
            t1 = (hh + (_rotr(e, 6) ^ _rotr(e, 11) ^ _rotr(e, 25))
                  + ((e & f) ^ ((~e & _MASK32) & g)) + _SHA256_K[t] + w[t]) & _MASK32
            t2 = ((_rotr(a, 2) ^ _rotr(a, 13) ^ _rotr(a, 22))
                  + ((a & b) ^ (a & c) ^ (b & c))) & _MASK32
            hh, g, f, e, d, c, b, a = g, f, e, (d + t1) & _MASK32, c, b, a, (t1 + t2) & _MASK32
        h = [(x + y) & _MASK32 for x, y in zip(h, (a, b, c, d, e, f, g, hh))]
    return h


def sig3_digest(md5hex: str) -> bytes:
    """引擎 ``$encode`` 里的 4 字节摘要 o。

    ``o = BE4( SHA256_IV1( BE_bytes( SHA256_IV0( utf8(md5hex) ) ) )[0] )``
    第二轮直接吃上一轮的二进制串，不再做 UTF-8 编码。

    :param md5hex: request2_md5 的 32 位小写 hex。
    :return: 4 字节大端摘要。
    """
    first = _sha256_compress(_sha256_blocks(md5hex.encode("utf-8").decode("latin-1")), _SIG3_IV[0])
    mid = "".join(chr((w >> (24 - 8 * b)) & 0xFF) for w in first for b in range(4))
    second = _sha256_compress(_sha256_blocks(mid), _SIG3_IV[1])
    return second[0].to_bytes(4, "big")


# --------------------------------------------------------------------------- #
# 28 字节明文与容器                                                             #
# --------------------------------------------------------------------------- #
SIG3_PAYLOAD_LEN = 28

# 明文分段（下标基于 28 字节明文，最后一字节既是校验和也是 XOR 密钥）。
SIG3_LAYOUT = {
    "magic": (0, 2),          # b"TE"
    "version": (2, 4),        # 0x01 0x30
    "startup_random": (4, 8),  # 引擎初始化的 unix 秒，小端
    "count": (8, 12),         # 调用序号，引擎初始 100，每次 +1，小端
    "digest": (12, 16),       # sig3_digest 的 4 字节
    "build": (16, 20),        # 常量 1653548225，小端
    "flags": (20, 27),        # 01 00 01 00 00 00 00
    "checksum": (27, 28),     # 前 27 字节的校验和
}

SIG3_MAGIC = b"TE"
SIG3_VERSION = bytes.fromhex("0130")
SIG3_BUILD = 1653548225
SIG3_FLAGS = bytes.fromhex("01000100000000")

# 2026-08-08 单次会话实测样本（cp 发布页 reload），用于差分与回归校验。
SIG3_SAMPLES = {
    "/rest/cp/works/v2/common/pc/current/user": "31216656bf801508196c6f6e5e1ec0e5b450f814707072727d7c7f65",
    "/rest/cp/works/v2/video/pc/upload/config": "34246353ba85100d11696a6b5b1bc5e0b155fd117575777778797a60",
    "/rest/cp/works/atlas/pc/upload/config": "32226555bc83160b1d6f6c6d5d1dc3e6b753fb17737371717e7f7c66",
    "/rest/cp/works/v2/collection/tab": "3a2a6d5db48b1e030d6764655515cbeebf5bf31f7b7b79797677746e",
    "/rest/cp/works/v2/common/pc/w/info": "d3c384b45d62f7eafa8e8d8c3f6254c356b21af6929290909f9e9d87",
}


def sig3_checksum(head27: bytes) -> int:
    """引擎 ``g()``：前 27 字节的无符号和；超过 255 时取其相反数的低字节。"""
    total = sum(head27)
    return (-total) & 0xFF if total > 255 else total & 0xFF


def encode_sig3(plain: bytes) -> str:
    """引擎 ``s()``：用末字节（校验和）作密钥，逐字节异或密钥与下标。

    :param plain: 28 字节明文，末字节须为 sig3_checksum(plain[:27])。
    :return: 56 位小写 hex 串。
    """
    if len(plain) != SIG3_PAYLOAD_LEN:
        raise ValueError(f"明文长度异常：{len(plain)} 字节（期望 {SIG3_PAYLOAD_LEN}）")
    key = plain[27]
    return bytes([(plain[i] ^ key ^ i) & 0xFF for i in range(27)] + [key]).hex()


def decode_sig3(sig: str) -> dict:
    """encode_sig3 的逆操作，并按 SIG3_LAYOUT 拆段（抓包核对用）。

    :param sig: 56 位 hex 串。
    :return: 含 ``plain`` 与各分段的 dict，另附解析好的整数字段。
    """
    raw = bytes.fromhex(sig)
    if len(raw) != SIG3_PAYLOAD_LEN:
        raise ValueError(f"__NS_sig3 长度异常：{len(raw)} 字节（期望 {SIG3_PAYLOAD_LEN}）")
    key = raw[27]
    plain = bytes([(raw[i] ^ key ^ i) & 0xFF for i in range(27)] + [key])
    result = {"plain": plain, "key": key}
    for name, (start, end) in SIG3_LAYOUT.items():
        result[name] = plain[start:end]
    result["startup_random_int"] = int.from_bytes(plain[4:8], "little")
    result["count_int"] = int.from_bytes(plain[8:12], "little")
    result["build_int"] = int.from_bytes(plain[16:20], "little")
    result["checksum_ok"] = sig3_checksum(plain[:27]) == key
    return result


class Sig3Signer:
    """``__NS_sig3`` 签名器（cp 发布侧）。

    对应浏览器里的一个引擎实例：``startupRandom`` 是引擎构造时刻的 unix 秒，
    ``count`` 从 100 起每次调用自增。两者都进签名明文，所以签名器要**长期持有**，
    每个爬虫会话一个实例，不要每次请求新建（那样 count 会永远是 100，
    和真实浏览器逐次递增的行为不一致）。
    """

    def __init__(self, startup_random: int = None, count: int = 100):
        """:param startup_random: 引擎初始化的 unix 秒，默认取当前时间。
        :param count: 调用计数器初值，浏览器侧固定为 100。
        """
        self.startup_random = int(time.time()) if startup_random is None else int(startup_random)
        self.count = int(count)

    def sign(self, sign_input: dict) -> str:
        """计算 ``__NS_sig3``。

        :param sign_input: ``{"query": dict, "body": dict, "type": "json"|"form-data"}``。
        :return: 56 位小写 hex 签名串。
        """
        digest_input = request2_md5(sign_input.get("query"),
                                    sign_input.get("body"),
                                    sign_input.get("type") or "json")
        return self._encode(digest_input)

    def _encode(self, digest_input: str) -> str:
        """还原引擎的 ``$encode``：32 位 md5 hex → 56 位签名串。"""
        head = (SIG3_MAGIC + SIG3_VERSION
                + self.startup_random.to_bytes(4, "little")
                + self.count.to_bytes(4, "little")
                + sig3_digest(digest_input)
                + SIG3_BUILD.to_bytes(4, "little")
                + SIG3_FLAGS)
        self.count += 1
        return encode_sig3(head + bytes([sig3_checksum(head)]))


if __name__ == '__main__':
    # 1) 真实抓包样本：容器 + 明文布局 + 校验字节逐项核对
    for api, sig in SIG3_SAMPLES.items():
        info = decode_sig3(sig)
        assert encode_sig3(info["plain"]) == sig, api
        assert info["magic"] == SIG3_MAGIC and info["version"] == SIG3_VERSION, api
        assert info["build_int"] == SIG3_BUILD and info["flags"] == SIG3_FLAGS, api
        assert info["checksum_ok"], api
        print(f"{api}\n  startupRandom={info['startup_random_int']} "
              f"count={info['count_int']} digest={info['digest'].hex()}")

    # 2) 用样本自身的会话参数重放，必须逐字节还原原签名
    print("\n重放校验：")
    for api, sig in SIG3_SAMPLES.items():
        info = decode_sig3(sig)
        signer = Sig3Signer(info["startup_random_int"], info["count_int"])
        head = (SIG3_MAGIC + SIG3_VERSION
                + signer.startup_random.to_bytes(4, "little")
                + signer.count.to_bytes(4, "little")
                + info["digest"]
                + SIG3_BUILD.to_bytes(4, "little") + SIG3_FLAGS)
        rebuilt = encode_sig3(head + bytes([sig3_checksum(head)]))
        print(f"  {'OK ' if rebuilt == sig else 'FAIL'} {api}")
        assert rebuilt == sig, api

    # 3) 摘要函数自查（对应 Node 预言机基准）
    print("\nsig3_digest(md5('')) =", sig3_digest(hashlib.md5(b"").hexdigest()).hex())
    print("端到端示例 =", Sig3Signer(1786175710, 116).sign({"query": {}, "body": {}}))
