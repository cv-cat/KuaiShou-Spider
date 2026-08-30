#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""``__NS_hxfalcon`` 纯算签名器（sig4，www 数据侧 + cp 少量接口）。

作用域：``www.kuaishou.com`` 部分 ``/rest/v/*``（见白名单）与 cp 侧 CP_SIG4_INTERFACES。
产物写入 query ``__NS_hxfalcon``，并附带 ``caver=2``（引擎版本号，``$getCatVersion`` 恒返回 "2"）。

签名输入（主包 formatParams + getSig4 反混淆，逐字段权威）：
    o = {
        url: pathname,                                   // 字段名是 url，值是 pathname
        query: { caver, ...params, ...urlSearchParams },
        form:  contentType==="application/x-www-form-urlencoded" && data ? data : {},
        requestBody: contentType==="application/json" && data ? data : {},
    }
    // signResult = engine.call("$encode", [o, {suc, err}])

引擎（app bundle 里的 `Jose`）已完整反编译。``reverse/vm/`` 默认不入库，本地需要的话自己从 bundle 解。
它是 vm.js 解释器 + 压缩 AST，配一批挂在 ``Object`` 上的明文原生函数（``jmpOnw_*``）。

产物形如 ``HUDR_<设备信息 blob>$HE_<45 字节容器>``：

1. ``HUDR_`` 段 = ``collectDeviceInfo()``：把 TLV 串逐字节异或 0x23，过一个自定义常量的
   ChaCha20，再 base64 并把 ``+/=`` 换成 ``-_.``。TLV 内容只有四项：
   ``document.scripts.length`` / ``KsGuard.count`` / ``SECS.s`` / ``SECS.c``。
   其中 ``SECS.s`` 是 ``Jose.call`` 抓的 ``Error.stack`` 尾部 100 字符，``SECS.c`` 等于当次 count。
2. ``$HE_`` 段 = 45 字节明文过校验字节 + 异或容器：
   ``4b54 | cca9 | ab | startupRandom(LE6) | 随机(LE6) | 0100000001 | count^常量(LE4)
     | 摘要(4) | now^常量(LE6) | 环境串(7) | 环境校验(1) | 整体校验(1)``
   摘要 = ``BLAKE2s 变体 -> 3-LFSR 流密码 -> 取前 4 字节 -> 异或常量``。
   环境串来自 ``jmpOnw_geh()``，它**硬编码返回 "e0000000000000"**，不是设备指纹。

校验（reverse/tools/）：
    ✅ 40 条 Node 预言机基准（真实 Jose 引擎）——完整签名逐字节一致
    ✅ 2 条真实抓包的 HUDR_ 段——解密回原始字段后重建，逐字符一致

对外统一门面在 ``utils.ks_util.generate_hxfalcon(path, method, query, body, content_type)``。
"""

from __future__ import annotations

import json
import random
import re
import time

from utils.sign.jsval import js_json_stringify, js_sorted, js_to_string

M32 = 0xFFFFFFFF

# caver：引擎版本号，query 里与 __NS_hxfalcon 一起提交。$getCatVersion 恒返回 "2"。
CAVER = "2"

# sig4 签名白名单（命中才需要签名；其余接口 cookie 直连即可）。
SIG4_WHITELIST = (
    "/rest/v/profile/get",
    "/rest/v/profile/user/v2",
    "/rest/v/search/user",
    "/rest/v/search/feed",
    "/rest/v/profile/feed",
    "/rest/v/feed/hot",
    "/rest/v/feed/liked",
    "/rest/v/collect/list",
    "/rest/v/profile/private/list",
)

# live.kuaishou.com 的 sig4 名单 = live-app.js 里那张 {url, realUrl} 映射表（28 条）。
#
# 拦截器原文（live-app.js @111543，axios request 拦截器 k）：
#
#     var r = v.find(e => e.url === t.url);          // 精确匹配，不是子串
#     if (r) { var n = await m(t.url, r.realUrl, t.params);
#              t.url = n.url; t.params = n.params; }
#
# 而 m(url, realUrl, params) 里签名输入是：
#
#     {url: realUrl, query: {caver, ...按键排序后的 params}, form: {}, requestBody: {}}
#
# 三个要点，缺一个签名内容就不对：
#   1. **签名算的是 realUrl（/rest/k/*），实际请求发的却是 /live_api/***——这张表就是为此存在的。
#   2. query 要先按键名排序，且排序后的结果会**替换**真实请求的 params（所以发出去也是排序的）。
#   3. form / requestBody 恒为空——即使 POST，body 也不参与直播站的签名。
#
# 2026-08-16 实抓校验：profile 页 + 房间页共 16 个 live_api 请求，
# 带签名的 7 个全部命中此表，不带签名的 9 个全部不在表内。
LIVE_URL_MAP = {
    "/live_api/baseuser/userinfo/sensitive": "/rest/k/user/info/sensitive",
    "/live_api/search/author": "/rest/k/live/search/user",
    "/live_api/comment/list": "/rest/k/photo/comment/list",
    "/live_api/search/overview": "/rest/k/live/search",
    "/live_api/search/category": "/rest/k/live/game/search/category",
    "/live_api/search/liveStream": "/rest/k/live/game/search/liveStream",
    "/live_api/profile/public": "/rest/k/feed/profile",
    "/live_api/profile/private": "/rest/k/feed/profile",
    "/live_api/profile/liked": "/rest/k/feed/liked",
    "/live_api/web/header/searchHotUserListQuery": "/rest/k/live/search/hot",
    "/live_api/web/header/searchSuggestQuery": "/rest/k/live/search/suggest",
    "/live_api/liveroom/websocketinfo": "/rest/k/live/websocket/info",
    "/live_api/profileInterestMask/list": "/rest/k/pc-live/author/category",
    "/live_api/profile/feedbyid": "/rest/k/photo",
    "/live_api/profile/likestatus": "/rest/k/photo",
    "/live_api/playback/list": "/rest/k/playback/product/list",
    "/live_api/baseuser/author/checkfollow": "/rest/k/user/info",
    "/live_api/baseuser/userinfo/byid": "/rest/k/user/info",
    "/live_api/baseuser/userLogin": "/rest/k/user/info",
    "/live_api/follow/all": "/rest/k/live/relation/follower",
    "/live_api/gameboard/list": "/rest/k/pc-live/live/getByGame",
    "/live_api/home/more": "/rest/k/pc-live/labels/switch",
    "/live_api/playback/detail": "/rest/k/playback/product/play",
    "/live_api/liveroom/like": "/rest/k/live/like",
    "/live_api/liveroom/status": "/rest/wd/live/liveStream/status",
    "/live_api/non-gameboard/list": "/rest/k/pc-live/live/synthesize",
    "/live_api/playback/download": "/rest/k/material/download",
    "/live_api/profile/interestlist": "/rest/k/pc-live/author/profile/reco",
}

LIVE_SIG4_INTERFACES = tuple(LIVE_URL_MAP)


def live_need_sign(url: str) -> bool:
    """直播站该 url 是否需要 ``__NS_hxfalcon``（精确匹配，与拦截器的 ``===`` 一致）。"""
    return (url or "").split("?")[0] in LIVE_URL_MAP


def live_sign_url(url: str) -> str:
    """取签名输入里该用的 url —— 是网关背后的 ``/rest/k/*``，不是 ``/live_api/*``。"""
    return LIVE_URL_MAP.get((url or "").split("?")[0], url)


# id.kuaishou.com（passport 扫码登录）的 sig4 名单，login-app.js @315175 明写的数组。
# 新旧两套 qr 路径并存，名单里都列了。
LOGIN_SIG4_INTERFACES = (
    "/rest/c/infra/ks/qr/start",
    "/rest/c/infra/ks/new/qr/start",
    "/rest/c/infra/ks/qr/scanResult",
    "/rest/c/infra/ks/new/qr/scanResult",
    "/rest/c/infra/ks/qr/acceptResult",
    "/rest/c/infra/ks/new/qr/acceptResult",
    "/pass/bid/web/sns/login/code",
    "/pass/bid/web/sns/quickLoginByKsAuth",
    # 手机号登录页的短信申请与验证码登录同样经过登录站 sig4 拦截器。
    # 2026-08-29 Chrome Network 实抓：两条请求均携带
    # ``__NS_hxfalcon`` + ``caver=2``，且 form body 参与签名。
    "/pass/kuaishou/sms/requestMobileCode",
    "/pass/kuaishou/login/mobileCode",
    # 下面这条**不在 bundle 那个数组里**，但 2026-08-16 真扫码实抓到它确实带签名。
    # 说明除了那个数组，还有别的调用点会显式签名 —— 只靠静态名单会漏。
    "/pass/kuaishou/login/qr/callback",
)


def login_need_sign(url: str) -> bool:
    """登录站该 url 是否需要 ``__NS_hxfalcon``（精确匹配）。

    实抓印证（完整扫码一次）：``qr/start`` / ``qr/scanResult`` / ``qr/acceptResult`` /
    ``login/qr/callback`` 四步**全部**带 ``__NS_hxfalcon`` + ``caver=2``；
    而 ``/pass/kuaishou/pc/pageInfo``、``/pass/kuaishou/login/passToken`` 不带。
    """
    return (url or "").split("?")[0] in LOGIN_SIG4_INTERFACES

# cp.kuaishou.com 侧改走 sig4 的接口（SIG4_INTERFACES / needsSig4，子串匹配）。
# 注意发布提交 /rest/cp/works/v2/video/pc/submit 在列——它走 sig4 而非 sig3。
CP_SIG4_INTERFACES = (
    "rest/cp/works/v2/common/pc/nearby",
    "rest/cp/works/v2/video/pc/edit/info",
    "rest/cp/works/v2/common/pc/ip2poi",
    "/rest/zt/location/wi/poi/search",
    "/rest/cp/works/v2/video/pc/submit",
)

# cp 侧 signInput 比 www 侧多一个 projectInfo 段（onvideo-index getUrlWithSig4 源码）。
CP_PROJECT_INFO = {"appKey": "mMovf2dVDF", "debug": False, "sampling": 1}

# --------------------------------------------------------------------------- #
# 引擎常量（全部取自 bundle 明文，勿改）                                        #
# --------------------------------------------------------------------------- #
_SIGMA = (
    (0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15),
    (14, 10, 4, 8, 9, 15, 13, 6, 1, 12, 0, 2, 11, 7, 5, 3),
    (11, 8, 12, 0, 5, 2, 15, 13, 10, 14, 3, 6, 7, 1, 9, 4),
    (7, 9, 3, 1, 13, 12, 11, 14, 2, 6, 5, 10, 4, 0, 15, 8),
    (9, 0, 5, 7, 2, 4, 10, 15, 14, 1, 11, 12, 6, 8, 3, 13),
    (2, 12, 6, 10, 0, 11, 8, 3, 4, 13, 7, 5, 15, 14, 1, 9),
    (12, 5, 1, 15, 14, 13, 4, 10, 0, 7, 6, 3, 9, 2, 8, 11),
    (13, 11, 7, 14, 12, 1, 3, 9, 5, 0, 15, 4, 8, 6, 2, 10),
    (6, 15, 14, 9, 11, 3, 0, 8, 12, 2, 13, 7, 1, 4, 10, 5),
    (10, 2, 8, 4, 7, 6, 1, 5, 15, 11, 9, 14, 3, 12, 13, 0),
)
_BLAKE_IV = (2837534710, 2845986804, 2436420605, 706843635,
             719254516, 2557931286, 2596197199, 2432949778)
_BLAKE_PARAM = 16842784          # $s[0] ^= 0x01010120

# jmpOnw_cts 流密码：48 字节常量块 + 密钥
_EO = bytes((98, 0, 0, 128, 49, 117, 185, 253, 224, 172, 104, 36, 223, 155, 87, 19,
             32, 0, 0, 64, 2, 0, 0, 16, 255, 255, 255, 127, 255, 255, 255, 63,
             0, 0, 0, 240, 0, 0, 0, 192, 0, 0, 0, 128, 255, 255, 255, 15))
_CTS_KEY = "Vuz4fCHxn1CO"

# collectDeviceInfo 的 ChaCha20（常量非标准）
_CHACHA_CONST = (394484062, 2378328696, 630790222, 1922531795)
_CHACHA_KEY = (4183807412, 394484062, 1106561997, 2378328696,
               630790222, 2546784104, 2891127470, 1922531795)
_CHACHA_NONCE = (2215853858, 1643070585, 1849059804)
_BLOB_XOR = 35
_B64 = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"

_GEH = "e0000000000000"          # jmpOnw_geh() 的硬编码返回值
_XOR_DIGEST = (45, 211, 69, 192)
_XOR_ENV = (123, 86, 62, 218)
_COUNT_MASK = 3131873467
_NOW_MASK = 3360347992
_RAND_SPAN = 281474976710655

# 明文第 2 段（小端 2 字节）是 SDK 内部版本号，**随 bundle 版本变，不是固定常量**：
#   cp/www 的 onvideo bundle 反编译出来是 43468 (0xa9cc)
#   live.kuaishou.com 实抓是    43469 (0xa9cd)
# 所以做成可配置；对不上时签名会被服务端拒。
SDK_VERSION_DEFAULT = 43468
SDK_VERSION_LIVE = 43469

# 真实浏览器会话实测值（reverse/tools/decrypt_prefix.py 从抓包解出），作为默认环境。
DEFAULT_SCRIPTS_LEN = 24
DEFAULT_SECS_STACK = ("spatchRequest (https://p23-plat.wskwai.com/kos/nlav111422/"
                      "ks-web/assets/index-bZyTA7JL.js:32:235479)")


def need_sign(path: str) -> bool:
    """路径是否命中 www 侧 sig4 白名单（需要 __NS_hxfalcon）。"""
    return path in SIG4_WHITELIST


def cp_need_sign(url: str) -> bool:
    """cp 侧该 url 是否走 sig4（优先级高于 sig3）。"""
    path = (url or "").split("?")[0]
    return any(marker in path for marker in CP_SIG4_INTERFACES)


def build_sign_input(path: str, method: str, query: dict = None,
                     body=None, content_type: str = "application/json",
                     project_info: dict = None, omit_empty_body: bool = False) -> dict:
    """构造送入引擎的 signInput（与主包 getSig4 内 o 对象逐字段对齐）。

    :param path: pathname，如 ``/rest/v/profile/get``。
    :param method: 请求方法（大写）；引擎只看 path/query/body，此参数保留以对齐调用方。
    :param query: 合并后的 query（不含 __NS_hxfalcon；caver 会被塞到最前）。
    :param body: 请求体（dict 或 json 字符串）。
    :param content_type: 决定 body 落到 form 还是 requestBody。
    :param project_info: cp 侧传 CP_PROJECT_INFO；www 侧不带该字段。
    :return: signInput dict。
    """
    query = dict(query or {})
    ct = (content_type or "").lower()
    is_form = "application/x-www-form-urlencoded" in ct
    is_json = "application/json" in ct

    if isinstance(body, str) and body:
        try:
            body_obj = json.loads(body)
        except Exception:
            body_obj = body
    else:
        body_obj = body

    sign_input = {
        "url": path,                       # 注意：字段名为 url，值为 pathname
        "query": {"caver": CAVER, **query},
    }
    # form / requestBody 带不带空对象，**各站不一样**，别一刀切：
    #
    # - www（omit_empty_body=True）：没 body 就不带这两个键。用
    #   ``/rest/v/profile/get`` 实测出来的——它是唯一一个真校验签名内容的只读接口，
    #   带 "{}" 一律 result=50，不带才 1。
    # - live / login（默认 False）：源码里恒写成 ``form: … : {}``，即键在、值为空。
    #   实测直播 ``websocketinfo`` 按 www 那套省略后会返回 result:2 拿不到 token。
    #
    # 引擎只要看见键就会拼上 JSON.stringify 的结果（哪怕是 "{}"），差分模糊测试确认过，
    # 所以差别只在「传不传这个键」。
    form_value = body_obj if (is_form and body_obj) else {}
    body_value = body_obj if (is_json and body_obj) else {}
    if not (omit_empty_body and not form_value):
        sign_input["form"] = form_value
    if not (omit_empty_body and not body_value):
        sign_input["requestBody"] = body_value
    if project_info:
        sign_input["projectInfo"] = dict(project_info)
    return sign_input


# --------------------------------------------------------------------------- #
# 原生函数移植                                                                  #
# --------------------------------------------------------------------------- #
def _rotr(x, n):
    x &= M32
    return ((x >> n) | (x << (32 - n))) & M32


def _rotl(x, n):
    x &= M32
    return ((x << n) | (x >> (32 - n))) & M32


def serialize_sign_input(data: dict) -> str:
    """``jmpOnw_ms``（原生 Ss）：路径 + 排序后的参数 + JSON body。

    cookie 白名单在 bundle 里恒为空数组，所以 cookie 不进签名输入。
    键名含 ``__NS`` 的参数会被跳过（避免把上一次的签名带进来）。
    """
    url = data.get("url") or ""
    path = url
    if re.match(r"http(s)?://([\w-]+\.)+[\w-]+", url):
        rest = url.split("//")[1]
        path = rest[rest.index("/"):] if "/" in rest else rest
    path = path.split("?")[0]

    merged = {str(k): v for k, v in (data.get("query") or {}).items()}
    merged.update({str(k): v for k, v in (data.get("form") or {}).items()})
    items = []
    for key, value in merged.items():
        if "__NS" in key:
            continue
        if value is None:
            items.append(f"{key}=")          # 源码里 null 走单独分支，不拼 "null"
        else:
            items.append(f"{key}={js_to_string(value)}")

    out = path + "".join(js_sorted(items))
    body = data.get("requestBody")
    # 只要键存在（哪怕是 {}），引擎就会拼上 JSON.stringify 的结果 —— 差分模糊测试
    # 400 组比对确认过。所以「该不该有 requestBody 这个键」由 build_sign_input 决定，
    # 这里忠实照抄引擎行为，不做额外判空。
    if body is not None:
        out += js_json_stringify(body)
    return out


def _blake_g(v, a, b, c, d, x, y):
    v[a] = (v[a] + v[b] + x) & M32
    v[d] = _rotr(v[d] ^ v[a], 16)
    v[c] = (v[c] + v[d]) & M32
    v[b] = _rotr(v[b] ^ v[c], 12)
    v[a] = (v[a] + v[b] + y) & M32
    v[d] = _rotr(v[d] ^ v[a], 8)
    v[c] = (v[c] + v[d]) & M32
    v[b] = _rotr(v[b] ^ v[c], 7)


def _blake_compress(h, words, off, counter, length, final):
    v = list(h) + list(_BLAKE_IV)
    v[12] ^= counter & M32
    if final:
        v[14] ^= M32
    m = [0] * 16
    for i in range(length):
        m[i % 16] ^= words[off + i] & M32
    for sg in _SIGMA:
        _blake_g(v, 0, 4, 8, 12, m[sg[0]], m[sg[1]])
        _blake_g(v, 1, 5, 9, 13, m[sg[2]], m[sg[3]])
        _blake_g(v, 2, 6, 10, 14, m[sg[4]], m[sg[5]])
        _blake_g(v, 3, 7, 11, 15, m[sg[6]], m[sg[7]])
        _blake_g(v, 0, 5, 10, 15, m[sg[8]], m[sg[9]])
        _blake_g(v, 1, 6, 11, 12, m[sg[10]], m[sg[11]])
        _blake_g(v, 2, 7, 8, 13, m[sg[12]], m[sg[13]])
        _blake_g(v, 3, 4, 9, 14, m[sg[14]], m[sg[15]])
    for i in range(8):
        h[i] = (h[i] ^ v[i] ^ v[i + 8]) & M32
    return h


def blake_hex(text: str) -> str:
    """``jmpOnw_b2has``：BLAKE2s 变体，输出 64 位 hex。

    与标准 BLAKE2s 的差异：自定义 IV；消息先补零到 4 字节对齐后按小端 int32 读成「字」，
    分块单位是 64 **字**（256 字节）且计数器按字累加；一个块内按 ``m[i%16] ^= word`` 折叠。
    """
    raw = text.encode("utf-8")
    raw += b"\x00" * ((-len(raw)) % 4)
    words = [int.from_bytes(raw[i:i + 4], "little") for i in range(0, len(raw), 4)]

    h = list(_BLAKE_IV)
    h[0] ^= _BLAKE_PARAM
    remain, off, counter = len(words), 0, 0
    while remain > 64:
        counter += 64
        remain -= 64
        _blake_compress(h, words, off, counter, 64, False)
        off += 64
    counter += remain
    _blake_compress(h, words, off, counter, remain, True)
    return "".join(f"{w:08x}" for w in h)


class _Cts:
    """``jmpOnw_cts``：三路 LFSR 组合生成器，逐字节 ``out = b ^ (keystream + 3)``。"""

    def __init__(self, key: str = _CTS_KEY):
        u32 = lambda lo, hi: int.from_bytes(_EO[lo:hi], "little")  # noqa: E731
        self.r0, self.r1, self.r2 = u32(12, 16), u32(8, 12), u32(4, 8)
        self.p0, self.f1, self.f2 = u32(0, 4), u32(16, 20), u32(20, 24)
        self.m0, self.m1, self.m2 = u32(24, 28), u32(28, 32), u32(44, 48)
        self.h0, self.h1, self.h2 = u32(40, 44), u32(36, 40), u32(32, 36)
        for i in range(4):
            byte = ord(key[i + 4]) & 0xFF
            self.r0 = ((self.r0 << 8) & M32) | byte
            self.r1 = ((self.r1 << 8) & M32) | byte
            self.r2 = ((self.r2 << 8) & M32) | byte
        self.r0 = self.r0 or 324508639
        self.r1 = self.r1 or 610839776
        self.r2 = self.r2 or 4256789809

    def _next(self) -> int:
        out = 0
        b0, b1 = self.r1 & 1, self.r2 & 1
        for _ in range(8):
            if self.r0 & 1:
                self.r0 = (self.r0 ^ ((self.p0 >> 1) & M32)) | self.h0
                self.r0 &= M32
                if self.r1 & 1:
                    self.r1 = ((self.r1 ^ ((self.f1 >> 1) & M32)) | self.h1) & M32
                    b0 = 1
                else:
                    self.r1 = (self.r1 >> 1) & self.m1 & M32
                    b0 = 0
            else:
                self.r0 = (self.r0 >> 1) & self.m0 & M32
                if self.r2 & 1:
                    self.r2 = ((self.r2 ^ ((self.f2 >> 1) & M32)) | self.h2) & M32
                    b1 = 1
                else:
                    self.r2 = (self.r2 >> 1) & self.m2 & M32
                    b1 = 0
            out = ((out << 1) & M32) | (b0 ^ b1)
            if out > 127:
                out -= 256
            elif out < -128:
                out += 256
        return out

    def apply(self, data: bytes) -> bytes:
        return bytes((b ^ (self._next() + 3)) & 0xFF for b in data)


def _chacha_block(state):
    w = list(state)
    for _ in range(10):
        for a, b, c, d in ((0, 4, 8, 12), (1, 5, 9, 13), (2, 6, 10, 14), (3, 7, 11, 15),
                           (0, 5, 10, 15), (1, 6, 11, 12), (2, 7, 8, 13), (3, 4, 9, 14)):
            w[a] = (w[a] + w[b]) & M32
            w[d] = _rotl(w[d] ^ w[a], 16)
            w[c] = (w[c] + w[d]) & M32
            w[b] = _rotl(w[b] ^ w[c], 12)
            w[a] = (w[a] + w[b]) & M32
            w[d] = _rotl(w[d] ^ w[a], 8)
            w[c] = (w[c] + w[d]) & M32
            w[b] = _rotl(w[b] ^ w[c], 7)
    return [(w[i] + state[i]) & M32 for i in range(16)]


def chacha(data) -> bytes:
    """collectDeviceInfo 用的 ChaCha20（常量/密钥/nonce 全定死，对称）。"""
    state = list(_CHACHA_CONST) + list(_CHACHA_KEY) + [1] + list(_CHACHA_NONCE)
    block = _chacha_block(state)
    out, k = bytearray(), 0
    for byte in data:
        if k == 64:
            state[12] = (state[12] + 1) & M32
            block = _chacha_block(state)
            k = 0
        out.append((byte ^ ((block[k >> 2] >> ((k & 3) << 3)) & 0xFF)) & 0xFF)
        k += 1
    return bytes(out)


def _le(value: int, nbytes: int) -> list:
    """``po()`` / ``_a()``：小端 n 字节；n>=4 且值 >= 2^32 时固定返回 4 个 0xFF。"""
    value = value or 0
    if nbytes >= 4 and value >= (1 << 32):
        return [255, 255, 255, 255]
    return [(value >> (8 * i)) & 0xFF for i in range(nbytes)]


def _le_hex(value: int, nbytes: int) -> str:
    """``jmpOnw_i2h(v, false, n)``：小端 n 字节的 hex（>32 位走二进制串分支，结果同小端）。"""
    return "".join(f"{(value >> (8 * i)) & 0xFF:02x}" for i in range(nbytes))


def _b64_url(data: bytes) -> str:
    chunks = []
    for i in range(0, len(data) - len(data) % 3, 3):
        n = (data[i] << 16) | (data[i + 1] << 8) | data[i + 2]
        chunks.append(_B64[(n >> 18) & 63] + _B64[(n >> 12) & 63]
                      + _B64[(n >> 6) & 63] + _B64[n & 63])
    rem = len(data) % 3
    if rem == 1:
        n = data[-1]
        chunks.append(_B64[n >> 2] + _B64[(n << 4) & 63] + "==")
    elif rem == 2:
        n = (data[-2] << 8) + data[-1]
        chunks.append(_B64[n >> 10] + _B64[(n >> 4) & 63] + _B64[(n << 2) & 63] + "=")
    return "".join(chunks).replace("+", "-").replace("/", "_").replace("=", ".")


def device_prefix(scripts_len: int, guard_count: int, secs_stack: str, secs_count: int) -> str:
    """``collectDeviceInfo()``：TLV -> 异或 0x23 -> ChaCha20 -> base64url，前缀 ``HUDR_``。"""
    blob = [45, 61, 0, 2]
    blob += [68, 0] + _le(scripts_len, 4)
    blob += [112, 0] + _le(guard_count, 4)
    blob += [114, 1] + _le(len(secs_stack), 2) + [ord(c) for c in secs_stack]
    blob += [115, 0] + _le(secs_count, 4)
    return "HUDR_" + _b64_url(chacha([(b ^ _BLOB_XOR) & 0xFF for b in blob]))


def _hex_checksum(hex_s: str) -> str:
    """``$()``：hex 串对应字节的无符号和；> 255 取相反数低字节。与 sig3 的 g() 同构。"""
    total = sum(bytes.fromhex(hex_s))
    return f"{((-total) & 0xFF) if total > 255 else (total & 0xFF):02x}"


def _container(hex_s: str, checksum: str) -> str:
    """``E()``：末字节（校验字节）作密钥整体异或。注意与 sig3 不同，**不异或下标**。"""
    raw = bytes.fromhex(hex_s + checksum)
    key = raw[-1]
    return bytes([(b ^ key) & 0xFF for b in raw[:-1]] + [key]).hex()


class HxFalconSigner:
    """``__NS_hxfalcon`` 签名器（sig4）。

    对应浏览器里的一个引擎实例：``startup_random`` 是引擎构造时刻的 unix 毫秒，
    ``count`` 与 ``KsGuard.count`` 都从 100 起逐次自增，三者都进签名。
    因此签名器要**长期持有**，每个爬虫会话一个实例，不要每次请求新建。

    ``secs_stack`` 是浏览器 ``Error.stack`` 尾部 100 字符，默认用真实会话实测值；
    ``scripts_len`` 是页面 ``document.scripts.length``，默认 24（同一实测会话）。
    """

    def __init__(self, startup_random: int = None, count: int = 100,
                 guard_count: int = 100, scripts_len: int = DEFAULT_SCRIPTS_LEN,
                 secs_stack: str = DEFAULT_SECS_STACK,
                 sdk_version: int = SDK_VERSION_DEFAULT):
        self.startup_random = int(time.time() * 1000) if startup_random is None else int(startup_random)
        self.count = int(count)
        self.guard_count = int(guard_count)
        self.scripts_len = int(scripts_len)
        self.secs_stack = secs_stack
        self.sdk_version = int(sdk_version)

    def sign(self, sign_input: dict) -> str:
        """计算 ``__NS_hxfalcon``。

        :param sign_input: build_sign_input() 的产物。
        :return: ``HUDR_...$HE_...`` 签名串。
        """
        return self._encode(sign_input, int(time.time() * 1000),
                            int(random.random() * _RAND_SPAN))

    def _encode(self, sign_input: dict, now_ms: int, rand48: int) -> str:
        """还原引擎的 ``$encode``。now/random 显式传入，便于对拍复现。"""
        # SECS.c 由 Jose.call 在进入 $encode 前置为当次 count，两者恒等
        prefix = device_prefix(self.scripts_len, self.guard_count, self.secs_stack, self.count)
        self.guard_count += 1

        serialized = serialize_sign_input(sign_input)
        stream = _Cts().apply(blake_hex(serialized + prefix).encode("utf-8"))
        digest = bytes((stream[i] ^ _XOR_DIGEST[i % 4]) & 0xFF for i in range(4)).hex()

        env_raw = bytes.fromhex(_GEH)
        env = bytes((env_raw[i] ^ _XOR_ENV[i % 4]) & 0xFF for i in range(len(env_raw))).hex()

        body = ("4b54" + _le_hex(self.sdk_version, 2) + "ab"
                + _le_hex(self.startup_random, 6)
                + _le_hex(rand48, 6)
                + "0100000001"
                + _le_hex(self.count ^ _COUNT_MASK, 4)
                + digest
                + _le_hex(now_ms ^ _NOW_MASK, 6)
                + env + _hex_checksum(env))
        self.count += 1
        return prefix + "$HE_" + _container(body, _hex_checksum(body))
