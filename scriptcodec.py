"""TLBB 脚本容器编解码（自研模块，纯标准库）。

来源：Game.exe 的 sub_1406DE210 / sub_1406DF4B0 / sub_1406E0240 逆向结论：
  容器 = magic(8) + u32 版本 + u32 算法号(2) + u32 密钥长(16) + 保留 + 偏移252 的 CRC32；
  负载前 24 字节 = Rijndael(Nb=6, Nk=6, Nr=12) 解一个 192 位分组，密钥 = 表[(id%32)] 起 (len%32) 字节 + 补零到 24；
  其余字节 = 与密钥前两项（0x41/0x53）交替异或。
Rijndael 实现已用 FIPS-197 的 AES-128 官方向量自检（见 自检/t.py）。
"""
import struct

KEYTAB = b'QWASDRTFYUIOGHJKLmncXz23456789zcbnmasdfjMNBC0qwzfgbhuifdfgJKL'
MAGIC = bytes.fromhex('d2d1e2e1b2b1c2c1')
def gmul(a, b):
    p = 0
    for _ in range(8):
        if b & 1:
            p ^= a
        hi = a & 0x80
        a = (a << 1) & 0xFF
        if hi:
            a ^= 0x1B
        b >>= 1
    return p


def build_sbox():
    """标准 AES S 盒：GF(2^8) 逆元 + 4 次循环移位仿射变换 + 0x63（现算，避免手抄错）。"""
    inv = [0] * 256
    for a in range(1, 256):
        for b in range(1, 256):
            if gmul(a, b) == 1:
                inv[a] = b
                break
    box = []
    for a in range(256):
        x = y = inv[a] if a else 0
        for _ in range(4):
            x = ((x << 1) | (x >> 7)) & 0xFF
            y ^= x
        box.append(y ^ 0x63)
    return box


class Rijndael:
    """Rijndael，可配分组列数 Nb（本包用 Nb=6 => 24 字节分组）、密钥列数 Nk=6、轮数 12。"""

    def __init__(self, key, nb=6, nk=None, nr=12, shifts=(1, 2, 3)):
        self.nb, self.nk, self.nr = nb, (nk or len(key) // 4), nr
        self.shifts = shifts
        self.sb = build_sbox()
        self.isb = [0] * 256
        for i, v in enumerate(self.sb):
            self.isb[v] = i
        self.ck = self._expand(key)

    def _expand(self, key):
        nb, nk, nr, sb = self.nb, self.nk, self.nr, self.sb
        w = [list(key[4 * i:4 * i + 4]) for i in range(nk)]
        rcon = 1
        for i in range(nk, nb * (nr + 1)):
            t = list(w[i - 1])
            if i % nk == 0:
                t = t[1:] + t[:1]
                t = [sb[x] for x in t]
                t[0] ^= rcon
                rcon = gmul(rcon, 2)
            w.append([w[i - nk][j] ^ t[j] for j in range(4)])
        return w

    def _rk(self, rnd):
        nb = self.nb
        return [self.ck[nb * rnd + c] for c in range(nb)]

    def _addrk(self, s, rnd):
        rk = self._rk(rnd)
        for c in range(self.nb):
            for r in range(4):
                s[r][c] ^= rk[c][r]

    def _sub(self, s, tab):
        for r in range(4):
            for c in range(self.nb):
                s[r][c] = tab[s[r][c]]

    def _shift(self, s, inv=False):
        out = [list(row) for row in s]
        for r in (1, 2, 3):
            n = self.shifts[r - 1]
            if inv:
                out[r] = s[r][-n:] + s[r][:-n] if n else list(s[r])
            else:
                out[r] = s[r][n:] + s[r][:n] if n else list(s[r])
        return out

    def _mix(self, s):
        def x(a):
            return ((a << 1) ^ 0x1B) & 0xFF if a & 0x80 else (a << 1)
        out = [[0] * self.nb for _ in range(4)]
        for c in range(self.nb):
            a = [s[r][c] for r in range(4)]
            t = a[0] ^ a[1] ^ a[2] ^ a[3]
            out[0][c] = a[0] ^ x(a[0] ^ a[1]) ^ t
            out[1][c] = a[1] ^ x(a[1] ^ a[2]) ^ t
            out[2][c] = a[2] ^ x(a[2] ^ a[3]) ^ t
            out[3][c] = a[3] ^ x(a[3] ^ a[0]) ^ t
        return out

    def _inv_mix(self, s):
        out = [[0] * self.nb for _ in range(4)]
        for c in range(self.nb):
            a = [s[r][c] for r in range(4)]
            out[0][c] = gmul(a[0], 14) ^ gmul(a[1], 11) ^ gmul(a[2], 13) ^ gmul(a[3], 9)
            out[1][c] = gmul(a[0], 9) ^ gmul(a[1], 14) ^ gmul(a[2], 11) ^ gmul(a[3], 13)
            out[2][c] = gmul(a[0], 13) ^ gmul(a[1], 9) ^ gmul(a[2], 14) ^ gmul(a[3], 11)
            out[3][c] = gmul(a[0], 11) ^ gmul(a[1], 13) ^ gmul(a[2], 9) ^ gmul(a[3], 14)
        return out

    def decrypt_block(self, blk):
        nb = self.nb
        s = [[blk[4 * c + r] for c in range(nb)] for r in range(4)]
        self._addrk(s, self.nr)
        for rnd in range(self.nr - 1, 0, -1):
            s = self._shift(s, inv=True)
            self._sub(s, self.isb)
            self._addrk(s, rnd)
            s = self._inv_mix(s)
        s = self._shift(s, inv=True)
        self._sub(s, self.isb)
        self._addrk(s, 0)
        return bytes(s[r][c] for c in range(nb) for r in range(4))

    def encrypt_block(self, blk):
        nb = self.nb
        s = [[blk[4 * c + r] for c in range(nb)] for r in range(4)]
        self._addrk(s, 0)
        for rnd in range(1, self.nr):
            self._sub(s, self.sb)
            s = self._shift(s)
            s = self._mix(s)
            self._addrk(s, rnd)
        self._sub(s, self.sb)
        s = self._shift(s)
        self._addrk(s, self.nr)
        return bytes(s[r][c] for c in range(nb) for r in range(4))


def container_key(algo_id, key_len):
    """按 Game.exe 的取法：从 61 字符表里 (id%32) 起取 (len%32) 字节。"""
    return KEYTAB[(algo_id % 32):(algo_id % 32) + (key_len % 32)]


def decode_container(blob, nb=6, shifts=(1, 2, 3)):
    if len(blob) < 280 or blob[:8] != MAGIC:
        return None
    algo, klen = struct.unpack_from('<II', blob, 12)
    key = container_key(algo, klen)
    full = (key + b'\0' * 8)[:24]
    pay = blob[256:]
    rd = Rijndael(full, nb=nb, nk=6, nr=12, shifts=shifts)
    out = bytearray(rd.decrypt_block(pay[:24])) + bytearray(pay[24:])
    v = True
    for i in range(24, len(out)):
        out[i] ^= key[0] if v else key[1]
        v = not v
    return bytes(out)


HDR_LEN = 256


def encode_container(plain, header, nb=6, shifts=(1, 2, 3)):
    """decode_container 的逆。header 是原容器前 256 字节（算法号、密钥长和每条自己的盐都在里面），
    照抄不改；正文首 24 字节 encrypt_block，其后与 key 前两项交替异或。
    实测 Interface 全部 224 个容器用它把明文重包回去都能逐字节还原原容器。
    变长安全性（2026-10-10 定案）：游戏判定函数 sub_1406DE730 只校验
    「长度>256 + 头 8 字节 magic + 对头前 252 字节做 CRC32 表循环 == @252 的 u32」，
    完全不读正文；实测 224 个容器里有 30 组「头 252 字节逐字节相同、正文长度不同」
    （同头组内正文 3,371..122,723 字节共存，@252 值一致）。
    所以头部照抄 + 任意长度正文 = 合法容器，等长限制已取消。"""
    if len(header) < HDR_LEN:
        raise ValueError('容器头不足 %d 字节（只有 %d）' % (HDR_LEN, len(header)))
    if len(plain) < 24:
        raise ValueError('明文不足一个分组（24 字节），无法加密')
    algo, klen = struct.unpack_from('<II', header, 12)
    key = container_key(algo, klen)
    full = (key + b'\0' * 8)[:24]
    rd = Rijndael(full, nb=nb, nk=6, nr=12, shifts=shifts)
    pay = bytearray(rd.encrypt_block(plain[:24])) + bytearray(plain[24:])
    v = True
    for i in range(24, len(pay)):
        pay[i] ^= key[0] if v else key[1]
        v = not v
    return bytes(header[:HDR_LEN]) + bytes(pay)


def verify_container_editable(old_len, new_len):
    """容器回写前的可行性检查。2026-10-10 起**不再限制等长**（依据见 encode_container 注释），
    只拦真正做不了的：新明文短到不足一个加密分组。"""
    if new_len < 24:
        raise ValueError('脚本明文只有 %d 字节，不足一个加密分组（24 字节），无法封装' % new_len)
