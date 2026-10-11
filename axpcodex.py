"""AXP 编解码层（25 路算法，decode / encode 成对）。

来源：Game.exe 里 prov->vtable[+16] 那个分发器（RVA 0x6EADD0）和它的 24 个 handler，
全部逐条转写；算法号来自 96 字节块头解密后的第 16 字节 dword（块头本身用 prov+8 表 XOR，
明文前 16 字节恒为 "SEPCIAL_FILE_HD"）。

handler 的四种字节形态（in = 包内字节/密文，out = 游戏拿到的明文）：
    X     out = in ^ k
    A     out = (in ^ k) - k          反：in = (out + k) ^ k
    B     out = k ^ (in - k)          反：in = (out ^ k) + k
    S     out = in - k                反：in = out + k
    ROLL  out = in ^ key; key += in
    W32   整 4 字节用 u32 表异或，尾字节原样
    ID    原样
密钥表都是运行时 prov 对象里的常量（不同客户端版本可用 动态挂钩/prov_probe2.py 重新取）。
pos 用"相对数据区起点"的偏移：body_pos(entry_off, data_off) = entry_off - data_off + 96（已实测）。

注意 13~18、21、22 只对"本次调用的前 1024/2048 字节"生效，之后原样；
     6 和 24 不用 pos，按调用内的序号走。游戏整文件一次读出来，所以这两种等价于块体内偏移。
"""
import os
import struct

MAGIC = b'SEPCIAL_FILE_HD'
HDR_LEN = 96
TAB_OFF = 8
TABSZ = 128

_kinds = {}
_offs = {}


def _reg(algo, kind, off=None, limit=None, extra=None):
    _kinds[algo] = kind
    _offs[algo] = (off, limit, extra)


# 算法号 → (形态, 表偏移)。表偏移按 handler 里 `+ a1 + N` 的实测值。
_reg(1, 'X', 8)
_reg(2, 'X', 136)
_reg(3, 'X', 264)
_reg(4, 'S', 392, None, 520)          # 索引再叠一个 prov+520 的常量
_reg(5, 'S', 524)
_reg(6, 'ROLL', None, None, 652)      # 初始 key 在 prov+652
_reg(7, 'B', 653)
_reg(8, 'A', 781)
_reg(9, 'S', 909)
_reg(10, 'A', 1037)
_reg(11, 'A', 1165)
_reg(12, 'A', 1293)
for _a, _o in ((13, 1421), (14, 1549), (15, 1677), (16, 1805), (17, 1933), (18, 2061)):
    _reg(_a, 'A', _o, 1024)
_reg(19, 'ID')
_reg(20, 'X', 2189)
_reg(21, 'A', 2317, 2048)
_reg(22, 'A', 2445, 1024)
_reg(23, 'A', 2573)
_reg(24, 'W32', 2697)
_reg(25, 'B15', 2829)

_blob = None
_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'axp_tables.bin')


def tables(blob=None):
    """prov 对象里的密钥表区块；blob 为 prov 起始读出的原始内存。"""
    global _blob
    if blob is not None:
        _blob = blob
    elif _blob is None:
        with open(_path, 'rb') as f:
            _blob = f.read()
    return _blob


def tab(off, n=TABSZ, blob=None):
    b = blob if blob is not None else tables()
    return b[off:off + n]


def body_pos(entry_off, data_off):
    return (entry_off - data_off + HDR_LEN) & 0xFFFFFFFF


# ---------- 块头 ----------
def decode_header(disk96):
    th = tab(TAB_OFF)
    plain = bytes(disk96[j] ^ th[j & 0x7F] for j in range(min(len(disk96), HDR_LEN)))
    return plain


def encode_header(plain96):
    return decode_header(plain96)            # 同一张表 XOR，自反


def header_algo(plain96):
    return struct.unpack_from('<I', plain96, 16)[0]


# ---------- 正文 ----------
def _step(algo, pos, j):
    off, _limit, extra = _offs[algo]
    b = tables()
    if extra is not None and algo == 4:
        i = (pos + j + struct.unpack_from('<I', b, extra)[0]) & 0x7F
    else:
        i = (pos + j) & 0x7F
    return b[off + i]


# ---- 快速路径：把逐字节 Python 循环换成 C 速度的切片 / translate / bigint ----
_GATE_STRIDED = 1024    # 整长条目 ≥ 此大小走步进切片
_GATE_SWAR = 4096       # B15 ≥ 此大小走 SWAR

_PAT_CACHE = {}
def _pattern(algo, pos):
    """密钥流周期模式 pattern[r] = 位置 pos+r 处的 k，周期 128 字节。"""
    off, _l, extra = _offs[algo]
    bb = tables()
    e = pos
    if extra is not None and algo == 4:
        e += struct.unpack_from('<I', bb, extra)[0]
    key = (algo, e & 0x7F)
    p = _PAT_CACHE.get(key)
    if p is None:
        p = bytes(bb[off + ((e + r) & 0x7F)] for r in range(128))
        if len(_PAT_CACHE) > 8192:
            _PAT_CACHE.clear()
        _PAT_CACHE[key] = p
    return p

_DTBL = {}
_ETBL = {}
def _byte_table(enc, kind, k):
    """固定 k 时单字节映射表：translate 用，全 C 速度。"""
    cache = _ETBL if enc else _DTBL
    key = (kind, k)
    t = cache.get(key)
    if t is None:
        if enc:
            if kind == 'A':
                t = bytes((((c + k) & 0xFF) ^ k) for c in range(256))
            elif kind == 'S':
                t = bytes((c + k) & 0xFF for c in range(256))
            else:                       # B / B15
                t = bytes((((c ^ k) + k) & 0xFF) for c in range(256))
        else:
            if kind == 'A':
                t = bytes((((c ^ k) - k) & 0xFF) for c in range(256))
            elif kind == 'S':
                t = bytes((c - k) & 0xFF for c in range(256))
            else:                       # B / B15
                t = bytes((k ^ ((c - k) & 0xFF)) for c in range(256))
        if len(cache) > 4096:
            cache.clear()
        cache[key] = t
    return t

def _xor_rep(data, pat):
    n = len(data)
    k = (pat * (n // 128 + 1))[:n]
    return (int.from_bytes(data, 'little') ^ int.from_bytes(k, 'little')).to_bytes(n, 'little')

def _strided(data, algo, pos, enc):
    """整长 X/A/B/S：按 j%128 分成 128 条步进切片逐条 translate，全 C 速度。"""
    kind = _kinds[algo]
    n = len(data)
    off, _l, extra = _offs[algo]
    bb = tables()
    e = pos
    if extra is not None and algo == 4:
        e += struct.unpack_from('<I', bb, extra)[0]
    if kind == 'X':
        return _xor_rep(data, _pattern(algo, pos))
    out = bytearray(data)
    for r in range(min(128, n)):
        k = bb[off + ((e + r) & 0x7F)]
        out[r::128] = data[r::128].translate(_byte_table(enc, kind, k))
    return bytes(out)

_HMASK = {}
def _hmask(m):
    h = _HMASK.get(m)
    if h is None:
        h = int.from_bytes(b'\x80' * m, 'little')
        if len(_HMASK) > 64:
            _HMASK.clear()
        _HMASK[m] = h
    return h

def _b15_swar(data, algo, pos, upto, enc):
    """B15 被变换位置（j%15==0）的批量运算：SWAR 逐字节减/加 + XOR，用 bigint 做。"""
    off, _l, extra = _offs[algo]
    bb = tables()
    e = pos
    if extra is not None and algo == 4:
        e += struct.unpack_from('<I', bb, extra)[0]
    m = (upto + 14) // 15
    A = bytes(data[:upto:15])
    K128 = bytes(bb[off + ((e + 15 * t) & 0x7F)] for t in range(128))
    K = (K128 * (m // 128 + 1))[:m]
    x = int.from_bytes(A, 'little')
    y = int.from_bytes(K, 'little')
    H = _hmask(m)
    if enc:
        q = x ^ y                                   # P ^ K
        r = ((q & ~H) + (y & ~H)) ^ ((q ^ y) & H)   # 逐字节 (q + K) mod 256
    else:
        c = ((x | H) - (y & ~H)) ^ ((x ^ ~y) & H)   # 逐字节 (A - K) mod 256
        r = c ^ y
    out = bytearray(data)
    out[:upto:15] = r.to_bytes(m, 'little')
    return bytes(out)

def _lim_loop(data, algo, pos, lim, enc):
    """限前 lim 字节的算法（13~18/21/22）：只变换前段，其余 memcpy。"""
    n = len(data)
    upto = min(n, lim)
    out = bytearray(data)
    off, _l, extra = _offs[algo]
    bb = tables()
    e = pos
    if extra is not None and algo == 4:
        e += struct.unpack_from('<I', bb, extra)[0]
    kind = _kinds[algo]
    for j in range(upto):
        k = bb[off + ((e + j) & 0x7F)]
        c = data[j]
        if enc:
            if kind == 'A':
                out[j] = ((c + k) & 0xFF) ^ k
            elif kind == 'S':
                out[j] = (c + k) & 0xFF
            elif kind == 'X':
                out[j] = c ^ k
            else:
                out[j] = ((c ^ k) + k) & 0xFF
        else:
            if kind == 'A':
                out[j] = ((c ^ k) - k) & 0xFF
            elif kind == 'S':
                out[j] = (c - k) & 0xFF
            elif kind == 'X':
                out[j] = c ^ k
            else:
                out[j] = k ^ ((c - k) & 0xFF)
    return bytes(out)

def _w32(data, algo):
    """整 4 字节字异或表（模式 32 个 u32 循环），尾字节原样；自反，编解码同路。"""
    off, _l, _e = _offs[algo]
    n = len(data)
    m4 = (n // 4) * 4
    if m4 == 0:
        return bytes(data)
    pat = tables()[off + 4:off + 132]
    K = (pat * (m4 // 128 + 1))[:m4]
    body = (int.from_bytes(data[:m4], 'little') ^ int.from_bytes(K, 'little')).to_bytes(m4, 'little')
    return body + bytes(data[m4:])


def decode_body(algo, pos, data):
    kind = _kinds.get(algo)
    if kind is None:
        raise ValueError('算法 %s 未转写' % algo)
    n = len(data)
    if n == 0:
        return b''
    if kind == 'ID':
        return bytes(data)
    if kind == 'W32':
        return _w32(data, algo)
    lim = _offs[algo][1]
    if kind == 'ROLL':
        b = tables()
        key = b[_offs[algo][2]]
        out = bytearray(n)
        for j in range(n):
            c = data[j]
            out[j] = c ^ key
            key = (key + c) & 0xFF
        return bytes(out)
    if kind == 'B15':
        upto = n if lim is None else min(n, lim)
        if upto >= _GATE_SWAR:
            return _b15_swar(data, algo, pos, upto, enc=False)
        b = tables()
        off = _offs[algo][0]
        out = bytearray(data)
        for j in range(0, upto, 15):
            k = b[off + ((pos + j) & 0x7F)]
            c = data[j]
            out[j] = k ^ ((c - k) & 0xFF)
        return bytes(out)
    if kind in ('X', 'A', 'B', 'S'):
        if lim is not None:
            return _lim_loop(data, algo, pos, lim, enc=False)
        if n >= _GATE_STRIDED:
            return _strided(data, algo, pos, enc=False)
    # 通用回退（小数据 / 未被快速路径覆盖的组合）
    b = tables()
    out = bytearray(n)
    for j in range(n):
        c = data[j]
        if lim is not None and j >= lim:
            out[j] = c
            continue
        k = _step(algo, pos, j)
        if kind == 'X':
            out[j] = c ^ k
        elif kind == 'A':
            out[j] = (c ^ k) - k & 0xFF
        elif kind == 'B':
            out[j] = k ^ ((c - k) & 0xFF)
        elif kind == 'S':
            out[j] = (c - k) & 0xFF
        elif kind == 'B15':
            out[j] = c if (j % 15) else (k ^ ((c - k) & 0xFF))
    return bytes(out)


def encode_body(algo, pos, data):
    """decode_body 的逆：把明文写成包内应该存的字节。"""
    kind = _kinds.get(algo)
    if kind is None:
        raise ValueError('算法 %s 未转写' % algo)
    n = len(data)
    if n == 0:
        return b''
    if kind == 'ID':
        return bytes(data)
    if kind == 'W32':
        return _w32(data, algo)
    lim = _offs[algo][1]
    if kind == 'ROLL':
        b = tables()
        key = b[_offs[algo][2]]
        out = bytearray(n)
        for j in range(n):
            p = data[j]
            c = p ^ key
            out[j] = c
            key = (key + c) & 0xFF
        return bytes(out)
    if kind == 'B15':
        upto = n if lim is None else min(n, lim)
        if upto >= _GATE_SWAR:
            return _b15_swar(data, algo, pos, upto, enc=True)
        b = tables()
        off = _offs[algo][0]
        out = bytearray(data)
        for j in range(0, upto, 15):
            k = b[off + ((pos + j) & 0x7F)]
            p = data[j]
            out[j] = ((p ^ k) + k) & 0xFF
        return bytes(out)
    if kind in ('X', 'A', 'B', 'S'):
        if lim is not None:
            return _lim_loop(data, algo, pos, lim, enc=True)
        if n >= _GATE_STRIDED:
            return _strided(data, algo, pos, enc=True)
    # 通用回退（小数据 / 未被快速路径覆盖的组合）
    b = tables()
    out = bytearray(n)
    for j in range(n):
        p = data[j]
        if lim is not None and j >= lim:
            out[j] = p
            continue
        k = _step(algo, pos, j)
        if kind == 'X':
            out[j] = p ^ k
        elif kind == 'A':
            out[j] = (((p + k) & 0xFF) ^ k) & 0xFF
        elif kind in ('B', 'B15'):
            if kind == 'B15' and (j % 15):
                out[j] = p
            else:
                out[j] = ((p ^ k) + k) & 0xFF
        elif kind == 'S':
            out[j] = (p + k) & 0xFF
    return bytes(out)


def algos_known():
    return sorted(_kinds)


def algo_kind(algo):
    return _kinds.get(algo)
