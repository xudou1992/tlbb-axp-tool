r"""模式 B（全量重建）：从「条目集合」重新生成一个完整的 .axp，不搬原文件的字节。

每个字段的实测依据都写在同目录 `模式B_表结构.md`（哪个包、哪个偏移、读出什么、跨几个包一致）。
本模块只按那些实测结论读写；没吃透的一律硬闸（NotImplementedError），不猜值。

    import axpcore, axp_build
    pkg = axpcore.Package(r'D:\XTLBB\Data\Model4.axp')
    st  = axp_build.build(pkg, r'out\Model4_new.axp')               # 全量重建
    rep = axp_build.rebuild_verify(pkg, r'out\Model4_new.axp')      # 从新文件按名字哈希逐条核对

实测基线：Model4.axp 用本模块从条目集合重建，产出 15624232 字节，与原包**逐字节完全相同**。

与模式 A（packcore.axp_repack）的分工：模式 A 保留原包的名字表/哈希表/布局，只换被编辑的块；
模式 B 只接「名字 + 明文」，名字表、哈希表、96 字节块头、数据区布局全部重新生成。

内存口径：build() 会把整包明文收在内存里（15MB 的 Model4 没问题，1.4GB 的 Interface
要先改成流式）；rebuild_verify 是逐条懒读懒解，不吃内存。
"""
import os, struct

import axpcore
import axpcodex

# ===================== 包级布局（实测 23/23 个 .axp 完全一致）=====================
MAGIC = b'AXPK'
HDR_VERSION = 0x00010001        # 0x04 23/23 恒为此值（两个 u16：1 / 1）
HDR_RESERVED08 = 0              # 0x08 23/23 恒 0
HDR_HEAD_LEN = 0x28             # 0x0C 头部长度，23/23 恒 0x28
HASH_SLOTS = 0x8000             # 哈希表桶数（Render.dll 校验循环 `while (v9 < 0x8000)`）
HASH_REC = 12                   # 每桶 12 字节 {h1, h2, 目录序号|0x80000000}
HASH_BYTES = HASH_SLOTS * HASH_REC          # 393216
DIR_AREA = 0x100000             # 0x18 目录区预留 1MiB（23/23 恒此值）
DIR_OFF = HDR_HEAD_LEN + HASH_BYTES         # 0x60028 = 0x28 + 32768*12，23/23 实测
DATA_OFF = DIR_OFF + DIR_AREA               # 0x160028 23/23 实测
MAX_ENTRIES = DIR_AREA // HASH_REC          # 87381
ALIGN = 256                     # 条目起始偏移相对数据区 256 对齐；区间 = ceil(size/256)*256
FLAG_USED = 0x80000000          # 目录第三字：全库 23 包只有 0x80000000(108987 条) 与 0(190 条)
LIST_NAME = b'(list)'           # 名字表条目自己在哈希表里的名字
HDR_PLAIN = 96                  # 块头长度

# ===================== AXP 名字哈希 =====================
# axpcore.gen_hashtable() 第 4 组下标写成 T[p+511]，真代码是 v3[511]（v3 已 ++，等价 T[768+i]）。
# which=1/2 用的 128..639 段不受影响（所以 h1/h2 一直对），但 which=3 的桶号全错 ——
# 这就是「名字表↔条目错位」和「按哈希找不到桶」的根因：修正后 Model4 53/53 条命中桶号。
_HASHM = 0x2AAAAB


def gen_hashtable():
    """照 Render.dll sub_180272D00（RVA 0x272D00）逐句转写，第 4 组落在 T[768+i]。"""
    T = [0] * 1024
    v2 = 1048577
    for i in range(256):
        v5 = (125 * v2 + 3) % _HASHM
        v7 = (125 * v5 + 3) % _HASHM
        T[i] = ((v5 << 16) & 0xFFFFFFFF) | (v7 & 0xFFFF)
        v8 = (125 * v7 + 3) % _HASHM
        v10 = (125 * v8 + 3) % _HASHM
        T[256 + i] = ((v8 << 16) & 0xFFFFFFFF) | (v10 & 0xFFFF)
        v11 = (125 * v10 + 3) % _HASHM
        v13 = (125 * v11 + 3) % _HASHM
        T[512 + i] = ((v11 << 16) & 0xFFFFFFFF) | (v13 & 0xFFFF)
        v14 = (125 * v13 + 3) % _HASHM
        v2 = (125 * v14 + 3) % _HASHM
        T[768 + i] = ((v14 << 16) & 0xFFFFFFFF) | (v2 & 0xFFFF)
    return T


HASHTAB = gen_hashtable()
HASHTAB_CORE_OK = list(axpcore.HASHTAB) == HASHTAB      # 核心库修好后自动跟随它


def name_hash(name, which, tab=None):
    if isinstance(name, str):
        name = name.encode('gbk', 'replace')
    T = tab or (axpcore.HASHTAB if HASHTAB_CORE_OK else HASHTAB)
    A = 0x7FED7FED
    B = 0xEEEEEEEE
    for b in name:
        c = b - 256 if b >= 128 else b                  # _BYTE 是有符号 char
        A = ((B + A) ^ T[((which << 8) + c) & 0x3FF]) & 0xFFFFFFFF
        B = (A + c + 33 * B + 3) & 0xFFFFFFFF
    return A


def lower(name):
    """游戏建表用的键就是小写名字（实测 col2/哈希 pair 全部按小写名字对得上）。"""
    return bytes(name).lower()


def name_pair(name):
    lo = lower(name)
    return (name_hash(lo, 1), name_hash(lo, 2))


def bucket_of(name):
    """桶位 = hash(lower(name), 3) & 0x7FFF（冲突线性探测，撞空桶即判不存在）。"""
    return name_hash(lower(name), 3) & 0x7FFF


# ===================== AXP CRC =====================
# 表取自 Render.dll RVA 0x3B4800（sub_1802730C0 里 `lea r11,[rip+0x141717]` 指的 256 个 dword）。
# 初值 0xFFFFFFFF（不做前置取反），循环后整体取反：crc(b'')=00000000、crc(b'a')=73d37cf3。
# 它与常见 CRC32(zlib) 的表在 64..127 / 192..255 两段不同，所以 zlib.crc32 实测一条都对不上。
_CRC_HEX = (
    '00000000963007772c610eeeba51099919c46d078ff46a7035a563e9a395649e3288db0ea4b8dc791ee9d5e088d9'
    'd2972b4cb609bd7cb17e072db8e7911dbf906410b71df220b06a4871b9f3de41be847dd4da1aebe4dd6d51b5d4f4'
    'c785d38356986c13c0a86b647af962fdecc9658a4f5c0114d96c0663633d0ffaf50d088dc8206e3b5e10694ce441'
    '60d5727167a2d1e4033c47d4044bfd850dd26bb50aa5faa8b5356c98b242d6c9bbdb40f9bcace36cd832755cdf45'
    'cf0dd6dc593dd1abac30d9263a00de518051d7c81661d0bfb5f4b42123c4b3569995bacf0fa5bdb89eb802280888'
    '055fb2d90cc624e90bb1877c6f2f114c6858ab1d61c13d2d66b62083b8edb6b3bf9a0ce2b6039ad2b1743947d5ea'
    'af77d29d1526db048316dc73120b63e3843b64943e6a6d0da85a6a7a0bcf0ee49dff099327ae000ab19e077d4493'
    '0ff0d2a3088768f2011efec206695d5762f7cb67658071366c19e7066b6e761bd4fee02bd3895a7ada10cc4add67'
    '6fdfb9f9f9efbe8e43beb717d58eb060e8a3d6d67e93d1a1c4c2d83852f2df4ff167bbd16757bca6dd06b53f4b36'
    'b248da2b0dd84c1b0aaff64a0336607a0441c3ef60df55df67a8ef8e6e3179be69468cb361cb1a8366bca0d26f25'
    '36e2685295770ccc03470bbbb91602222f260555be3bbac5280bbdb2925ab42b046ab35ca7ffd7c231cfd0b58b9e'
    'd92c1daede5b9041dc760671db01bc20d2982a10d5ef8985b1711fb5b606a5e4bf9f33d4b8e8a2c9077834f9000f'
    '8ea8099618980ee1bb0d6a7f2d3d6d08976c6491015c63e6f4516b6b62616c1cd83065854e0062f2ed95066c7ba5'
    '011bc1f4088257c40ff5c6d9b06550e9b712eab8be8b7c88b9fcdf1ddd62492dda15f37cd38c654cd4fb5861b24d'
    'ce51b53a7400bca3e230bbd441a5df4ad795d83d6dc4d1a4fbf4d6d36ae96943fcd96e34468867add0b860da732d'
    '0444e51d03335f4c0aaac97c0ddd3c710550aa41022710100bbe86200cc925b56857b3856f2009d466b99fe461ce'
    '0ef9de5e98c9d9292298d0b0b4a8d7c7173db359810db42e3b5cbdb7ad6cbac0b0c2649b26f263ec9ca36a750a93'
    '6d02a906099c3f360eeb8567077213570005824abf95147ab8e2ae2bb17b381bb60c9b8ed2920dbed5e5b7efdc7c'
    '21dfdb0bd4d2d38642e2d4f1f8b3dd686e83da1fcd16be815b26b9f6e177b06f7747b718e65a0888706a0fffca3b'
    '06665c0b0111ff9e658f69ae62f8d3ff6b6145cf6c1678e20aa0eed20dd75483044ec2b30339612667a7f71660d0'
    '4d476949db776e3e4a6ad1aedc5ad6d9660bdf40f03bd83753aebca9c59ebbde7fcfb247e9ffb5301cf2bdbd8ac2'
    'baca3093b353a6a3b4240536d0ba9306d7cd2957de54bf67d9232e7a66b3b84a61c4021b685d942b6f2a37be0bb4'
    'a18e0cc31bdf055a8def022d')
CRC_TAB = list(struct.unpack('<256I', bytes.fromhex(_CRC_HEX)))
assert len(CRC_TAB) == 256
_CRC_T = [CRC_TAB]
for _k in range(1, 8):                                   # slicing-by-8，结果与逐字节实现逐位相同
    _p = _CRC_T[_k - 1]
    _CRC_T.append([((_p[i] >> 8) ^ CRC_TAB[_p[i] & 0xFF]) & 0xFFFFFFFF for i in range(256)])


def crc_axp(data):
    c = 0xFFFFFFFF
    n = len(data)
    i = 0
    T = _CRC_T
    while i + 8 <= n:
        v = int.from_bytes(data[i:i + 8], 'little') ^ c
        c = (T[7][v & 0xFF] ^ T[6][(v >> 8) & 0xFF] ^ T[5][(v >> 16) & 0xFF] ^ T[4][(v >> 24) & 0xFF]
             ^ T[3][(v >> 32) & 0xFF] ^ T[2][(v >> 40) & 0xFF] ^ T[1][(v >> 48) & 0xFF] ^ T[0][(v >> 56) & 0xFF])
        i += 8
    t0 = CRC_TAB
    while i < n:
        c = (c >> 8) ^ t0[(c ^ data[i]) & 0xFF]
        i += 1
    return (~c) & 0xFFFFFFFF


def crc_axp_slow(data):
    """逐字节参考实现（自检对照用）。"""
    c = 0xFFFFFFFF
    t0 = CRC_TAB
    for b in data:
        c = (c >> 8) ^ t0[(c ^ b) & 0xFF]
    return (~c) & 0xFFFFFFFF


# ===================== 96 字节块头 =====================
def make_plain_header(algo, body_len, body_crc):
    """明文块头 = 'SEPCIAL_FILE_HD' + 0x00 + u32 算法号@16 + u32 正文长度@20 + u32 正文CRC@24 + 补零到 96。

    实测：Model4 全部 53 条 + Material8/Config/Model3/Interface 各 120 条，按这个式子造出来
    再 axpcodex.encode_header() 一遍，与原包磁盘块头逐字节 100% 相同；28..96 全是 0。
    """
    h = bytearray(HDR_PLAIN)
    h[0:15] = axpcodex.MAGIC
    struct.pack_into('<III', h, 16, algo & 0xFFFFFFFF, body_len & 0xFFFFFFFF, body_crc & 0xFFFFFFFF)
    return bytes(h)


def parse_plain_header(plain96):
    """解出块头三个字段；28..96 有非零就硬闸（那是没吃透的字段，不猜）。"""
    if len(plain96) != HDR_PLAIN or plain96[:15] != axpcodex.MAGIC:
        return None
    if any(plain96[28:]):
        raise NotImplementedError('块头 28..96 出现未定字段（%s），模式 B 不猜' % plain96[28:40].hex())
    algo, blen, bcrc = struct.unpack_from('<3I', plain96, 16)
    return algo, blen, bcrc


# ===================== 哈希表定位 =====================
def lookup(buckets, name):
    """按游戏的查找算法定位：起点 hash(lower(name),3)&0x7FFF，线性探测，撞空桶即止。

    返回 (目录序号 or None, 命中桶号, 探测步数)。空桶判据是第三字 == 0。
    """
    lo = lower(name)
    ideal = name_hash(lo, 3) & 0x7FFF
    p1 = name_hash(lo, 1)
    p2 = name_hash(lo, 2)
    i = ideal
    steps = 0
    while True:
        h1, h2, z = buckets[i]
        if z == 0:
            return None, i, steps
        if z & FLAG_USED and h1 == p1 and h2 == p2:
            return z & 0x3FFFFFFF, i, steps
        i = (i + 1) & 0x7FFF
        steps += 1
        if i == ideal:
            return None, i, steps


def read_buckets(path):
    with open(path, 'rb') as f:
        f.seek(0x28)
        blob = f.read(HASH_BYTES)
    return [struct.unpack_from('<3I', blob, i * HASH_REC) for i in range(HASH_SLOTS)]


def read_dir(path):
    with open(path, 'rb') as f:
        h = f.read(HDR_HEAD_LEN)
        if h[:4] != MAGIC:
            raise ValueError('不是 AXPK 包：%s' % path)
        ver, r08, hlen, dir_off, count, dir_area, data_off, data_len, free = struct.unpack_from('<9I', h, 4)
        f.seek(dir_off)
        drew = f.read(count * HASH_REC)
    return dict(ver=ver, r08=r08, hlen=hlen, dir_off=dir_off, count=count, dir_area=dir_area,
                data_off=data_off, data_len=data_len, free=free,
                ents=[struct.unpack_from('<3I', drew, i * HASH_REC) for i in range(count)],
                size=os.path.getsize(path))


# ===================== 条目集合 =====================
class Entry(object):
    """模式 B 的最小输入单元：名字 + 明文（+ 要不要块头、块头算法号）。"""
    __slots__ = ('name', 'plain', 'algo', 'ciphered', 'src_index', 'src_size', 'col1', 'col2')

    def __init__(self, name, plain, algo=None, ciphered=False, src_index=None, src_size=0,
                 col1=0, col2=0):
        self.name = name              # 原始大小写的名字字节（GBK）；None = 源包没给它名字
        self.plain = plain            # 无块头：整条原文；有块头：正文明文
        self.algo = algo              # 块头算法号；None = 这条不写块头
        self.ciphered = ciphered      # 正文走不走算法（决定重排时要不要重编）
        self.src_index = src_index
        self.src_size = src_size
        self.col1 = col1              # 源包名字表第一列（对照）
        self.col2 = col2              # 源包名字表第二列（对照）

    @property
    def stored_len(self):
        return (HDR_PLAIN if self.algo is not None else 0) + len(self.plain)

    @property
    def region(self):
        return -(-self.stored_len // ALIGN) * ALIGN


def read_package_entries(pkg, keep_free=False):
    """把源包拆成条目集合。名字用哈希表探针定位，不信名字表行序（行序是按小写名字排的）。

    每条都先自证「能逐字节还原」：块头 @24 的 CRC 要么等于 crc(存储正文)（正文没加密），
    要么等于 crc(按该算法+该相位解出的正文)（正文加密）。两者都不成立 → 硬闸，不写。
    """
    buckets = read_buckets(pkg.path)
    dirinfo = read_dir(pkg.path)
    main = max(pkg.lists, key=lambda l: len(l['rows'])) if pkg.lists else None
    rep = dict(entries=pkg.count, named=0, unnamed_used=0, free=0, list_rows=0, stale_rows=0,
               ciphered=0, plain_body=0, raw=0, extra_lists=len(pkg.lists) - (1 if main else 0),
               list_index=main['index'] if main else None, dir_free=dirinfo['free'])
    row_by_index = {}
    if main:
        rep['list_rows'] = len(main['rows'])
        for nm, c1, c2 in main['rows']:
            z, b, st_ = lookup(buckets, nm)
            if z is None:
                rep['stale_rows'] += 1            # 名字表有这行，但哈希表里查不到（陈旧行）
                continue
            row_by_index[z] = (nm, c1, c2)

    entries = []
    with open(pkg.path, 'rb') as f:
        for idx, (o, s, fl) in enumerate(pkg.entries):
            if not s:
                continue
            if not (fl & FLAG_USED):
                rep['free'] += 1
                if keep_free:
                    raise NotImplementedError('条目 %d 是 flag=0 的空洞条目（偏移 %d 长度 %d），'
                                              '模式 B 还不知道该给它什么名字，先别硬搬' % (idx, o, s))
                continue
            if main and idx == main['index']:
                continue                          # 名字表条目自己在写的时候再生成
            nm, c1, c2 = row_by_index.get(idx, (None, 0, 0))
            if nm is None:
                rep['unnamed_used'] += 1
            else:
                rep['named'] += 1
            f.seek(o)
            raw = f.read(s)
            if s > HDR_PLAIN and raw[:6] == axpcore.HDR_PREFIX:
                ph = axpcodex.decode_header(raw[:HDR_PLAIN])
                got = parse_plain_header(ph) if ph[:15] == axpcodex.MAGIC else None
                if not got:
                    raise NotImplementedError('条目 %d 有 AX 块头前缀但明文头魔数不对，先没吃透' % idx)
                a, blen, bcrc = got
                if blen != s - HDR_PLAIN:
                    raise NotImplementedError('条目 %d 块头正文长度 %d 与目录长度 %d 不符'
                                              % (idx, blen, s - HDR_PLAIN))
                body = raw[HDR_PLAIN:]
                if bcrc == crc_axp(body):
                    plain, algo, ciphered = body, a, False     # 正文原样存储，位置无关
                    rep['plain_body'] += 1
                elif a in axpcodex._kinds:
                    pb = axpcodex.decode_body(a, axpcodex.body_pos(o, pkg.data_off), body)
                    if bcrc != crc_axp(pb):
                        raise NotImplementedError(
                            '条目 %d（%s）算法 %d：解出来的正文 CRC(%08X) != 块头 @24(%08X)，'
                            '这条的加密方式还没吃透，模式 B 不许猜'
                            % (idx, (nm or b'').decode('gbk', 'replace'), a, crc_axp(pb), bcrc))
                    plain, algo, ciphered = pb, a, True
                    rep['ciphered'] += 1
                else:
                    raise NotImplementedError('条目 %d 算法 %d 未在 axpcodex 里转写，无法重编' % (idx, a))
            else:
                plain, algo, ciphered = raw, None, False    # 无块头：整条就是原文
                rep['raw'] += 1
            entries.append(Entry(nm, plain, algo=algo, ciphered=ciphered, src_index=idx,
                                 src_size=s, col1=c1, col2=c2))
    entries.sort(key=lambda e: (lower(e.name) if e.name is not None else b'\xff' * 64, e.src_index))
    return entries, rep


# ===================== 生成各张表 =====================
def plan_layout(entries):
    """布局：目录序号 = 按小写名字升序，名字表条目放最后（实测干净包的 (list) 都是末条）。"""
    if len(entries) + 1 > MAX_ENTRIES:
        raise NotImplementedError('条目数 %d 超过目录区容量 %d' % (len(entries) + 1, MAX_ENTRIES))
    seen = {}
    out = []
    cur = DATA_OFF
    for i, e in enumerate(entries):
        if e.name is not None:
            lo = lower(e.name)
            if lo in seen:
                raise NotImplementedError('名字重复（忽略大小写）：%s —— 游戏按 std::map 存名字，'
                                          '模式 B 不知道同名两条该怎么放' % e.name.decode('gbk', 'replace'))
            seen[lo] = i
        out.append((e, i, cur))
        cur += e.region
    return out, (len(entries), cur)


def build_list_text(triples):
    """名字表正文：`%08X\\n%d\\n` + 每行 `名字|%08X|%08X\\n`，按小写名字升序。

    第一行 key = 0xFFFFFFFF ^ XOR(每行第二列)（Render.dll sub_18026F6C0：`v2 = -1; v2 ^= node[17]`）。
    实测 9 个包 11 张表按此式子重建，与原包名字表条目逐字节完全相同（含两张历史残留表）。
    """
    key = 0xFFFFFFFF
    for nm, c1, c2 in triples:
        key ^= c2
    out = bytearray(b'%08X\n%d\n' % (key & 0xFFFFFFFF, len(triples)))
    for nm, c1, c2 in sorted(triples, key=lambda r: lower(r[0])):
        out += b'%s|%08X|%08X\n' % (nm, c1, c2)
    return bytes(out)


def build_hash_table(records):
    """records = [(name, 目录序号)]，按给定顺序线性探测插入。

    实测：按「小写名字升序 + (list) 最后」插入，Model4/Material8/Model3/Config/Effect/Sound 的
    32768×12 哈希表与原包逐字节相同（见 test_rebuild.py 的 hash_table_same）。
    """
    tab = bytearray(HASH_BYTES)
    for nm, z in records:
        lo = lower(nm)
        i = name_hash(lo, 3) & 0x7FFF
        for _ in range(HASH_SLOTS):
            off = i * HASH_REC
            if struct.unpack_from('<I', tab, off + 8)[0] == 0:
                struct.pack_into('<3I', tab, off, name_hash(lo, 1), name_hash(lo, 2), z | FLAG_USED)
                break
            i = (i + 1) & 0x7FFF
        else:
            raise IOError('哈希表塞不下 %d 条' % len(records))
    return bytes(tab)


def encode_entry_blob(e, offset):
    """按新位置生成条目的磁盘字节：块头重新造，正文按新相位重编（无块头的原样）。"""
    if e.algo is None:
        return e.plain
    body = (axpcodex.encode_body(e.algo, axpcodex.body_pos(offset, DATA_OFF), e.plain)
            if e.ciphered else e.plain)
    head = axpcodex.encode_header(make_plain_header(e.algo, len(e.plain), crc_axp(e.plain)))
    return head + body


def build(pkg, out_path, progress=None, cancel=None, keep_free=False, unnamed='raise'):
    """全量重建主流程。返回统计 dict（所有数字都是实测口径）。

    keep_free=False：flag=0 的空洞条目不重建（它没有名字，模式 B 的输入只有「名字+明文」）；
    unnamed='raise'：有 flag=0x80000000 却在名字表/哈希表里都查不到名字的条目就硬闸；
                     'drop'：把这些够不到的条目丢掉，只在报告里给数量。
    """
    st = dict(out=out_path, entries=0, count=0, named=0, ciphered=0, plain_body=0, raw=0,
              free_skipped=0, unnamed_used=0, dropped_unnamed=0, stale_rows=0, extra_lists=0,
              size=0, bytes=0, data_len=0, list_bytes=0, list_same_src=0, hash_table_same=0,
              col2_differs_src=0, col1_differs_src=0, errors=[], cancelled=False)
    entries, rep = read_package_entries(pkg, keep_free=keep_free)
    if rep['unnamed_used'] and unnamed != 'drop':
        raise NotImplementedError('有 %d 条 flag=0x80000000 的条目在名字表/哈希表里都查不到名字，'
                                  '模式 B 不能凭空给它名字（要丢掉它们就传 unnamed="drop"）'
                                  % rep['unnamed_used'])
    if rep['unnamed_used']:
        dropped = [e for e in entries if e.name is None]
        st['dropped_unnamed'] = len(dropped)
        st['dropped_src_index'] = [e.src_index for e in dropped][:20]
        entries = [e for e in entries if e.name is not None]
    st.update(named=rep['named'], ciphered=rep['ciphered'], plain_body=rep['plain_body'],
              raw=rep['raw'], free_skipped=rep['free'], unnamed_used=rep['unnamed_used'],
              stale_rows=rep['stale_rows'], extra_lists=rep['extra_lists'])
    layout, (list_index, list_off) = plan_layout(entries)

    blobs = []
    for k, (e, di, off) in enumerate(layout):
        if cancel is not None and cancel.is_set():
            st['cancelled'] = True
            return st
        blobs.append(encode_entry_blob(e, off))
        if progress and k % 100 == 0:
            progress(k + 1, len(layout), (e.name or b'').decode('gbk', 'replace'))

    triples = []
    for (e, di, off), b in zip(layout, blobs):
        c2 = crc_axp(b)
        if e.col2 and e.col2 != c2:
            st['col2_differs_src'] += 1
        if e.col1 and e.col1 != len(b):
            st['col1_differs_src'] += 1
        triples.append((e.name, len(b), c2))
    list_text = build_list_text(triples)
    st['list_bytes'] = len(list_text)
    st['list_same_src'] = int(list_text == _read_src_list(pkg))

    records = [(e.name, di) for (e, di, off) in layout]
    records.append((LIST_NAME, list_index))
    hashtab = build_hash_table(records)
    with open(pkg.path, 'rb') as f:
        f.seek(0x28)
        st['hash_table_same'] = int(f.read(HASH_BYTES) == hashtab)

    dirblob = bytearray((list_index + 1) * HASH_REC)
    for (e, di, off), b in zip(layout, blobs):
        struct.pack_into('<3I', dirblob, di * HASH_REC, off, len(b), FLAG_USED)
    struct.pack_into('<3I', dirblob, list_index * HASH_REC, list_off, len(list_text), FLAG_USED)
    data_len = list_off + -(-len(list_text) // ALIGN) * ALIGN - DATA_OFF
    header = struct.pack('<4s9I', MAGIC, HDR_VERSION, HDR_RESERVED08, HDR_HEAD_LEN,
                         DIR_OFF, list_index + 1, DIR_AREA, DATA_OFF, data_len, 0)
    if len(header) != HDR_HEAD_LEN:
        raise IOError('包头长度算错：%d' % len(header))
    total = list_off + -(-len(list_text) // ALIGN) * ALIGN

    tmp = out_path + '.part'
    done = False
    try:
        d = os.path.dirname(out_path)
        if d:
            os.makedirs(d, exist_ok=True)
        with open(tmp, 'wb') as g:
            g.write(header)
            g.write(hashtab)
            g.write(bytes(dirblob))
            g.write(b'\0' * (DATA_OFF - HDR_HEAD_LEN - HASH_BYTES - len(dirblob)))
            if g.tell() != DATA_OFF:
                raise IOError('数据区起点没落到 %08x：实际 %d' % (DATA_OFF, g.tell()))
            pos = DATA_OFF
            for (e, di, off), b in zip(layout, blobs):
                if off != pos:
                    raise IOError('布局不连续：%d != %d' % (off, pos))
                g.write(b)
                pad = e.region - len(b)
                if pad:
                    g.write(b'\0' * pad)
                pos = off + e.region
                st['bytes'] += len(b)
            if pos != list_off:
                raise IOError('名字表位置不对：%d != %d' % (pos, list_off))
            g.write(list_text)
            pad = -(-len(list_text) // ALIGN) * ALIGN - len(list_text)
            if pad:
                g.write(b'\0' * pad)
            if g.tell() != total:
                raise IOError('落盘长度 %d != 计划 %d' % (g.tell(), total))
            g.flush()
        os.replace(tmp, out_path)
        done = True
        st['size'] = total
        st['count'] = list_index + 1
        st['entries'] = list_index + 1
        st['data_len'] = data_len
    finally:
        if not done and os.path.exists(tmp):
            try:
                os.remove(tmp)
            except OSError:
                pass
    return st


def _read_src_list(pkg):
    if not pkg.lists:
        return b''
    main = max(pkg.lists, key=lambda l: len(l['rows']))
    o, s, fl = pkg.entries[main['index']]
    with open(pkg.path, 'rb') as f:
        f.seek(o)
        return f.read(s)


# ===================== 校验 =====================
def rebuild_verify(pkg, out_path, progress=None, limit=None):
    """硬校验：从**新写的文件**按名字哈希把每条解出明文，逐字节等于源包解码明文才算过。

    顺带核对新文件自己各张表是否自洽：包级偏移/长度/空闲计数、哈希表桶位、块头三字段、
    名字表 key/两列值/排序、256 对齐、文件总长。返回的每个数字都是实测出来的。
    """
    src = read_dir(pkg.path)
    new = read_dir(out_path)
    sb = read_buckets(pkg.path)
    nb = read_buckets(out_path)
    res = dict(checked=0, passed=0, failed=0, missing=0, hdr_bad=0, align_bad=0,
               list_rows=0, list_key_bad=0, list_col1_bad=0, list_col2_bad=0, list_order_bad=0,
               probe_steps_max=0, collision=0, size_src=pkg.size, size_new=new['size'],
               entries_src=src['count'], entries_new=new['count'], errors=[],
               bucket_ok=0, bucket_bad=0, data_len_ok=0, head_ok=0)
    if (new['dir_off'], new['data_off'], new['dir_area'], new['hlen'], new['ver'], new['r08']) != \
       (src['dir_off'], src['data_off'], src['dir_area'], src['hlen'], src['ver'], src['r08']):
        res['errors'].append('包级常量字段与源包不一致（dir_off/data_off/dir_area/hlen/ver/08）')
    else:
        res['head_ok'] = 1
    if new['size'] != new['data_off'] + new['data_len']:
        res['errors'].append('文件长度 %d != 数据区末尾 %d' % (new['size'], new['data_off'] + new['data_len']))
    else:
        res['data_len_ok'] = 1
    if new['free'] != sum(-(-s // ALIGN) * ALIGN for o, s, fl in new['ents'] if s and not (fl & FLAG_USED)):
        res['errors'].append('偏移24 空闲计数字段 %d 与实际空洞和不符' % new['free'])

    # 逐条：源包明文 vs 新包明文（都按各自位置解）
    src_rows = {}
    main = max(pkg.lists, key=lambda l: len(l['rows'])) if pkg.lists else None
    if main:
        for nm, c1, c2 in main['rows']:
            z, b, st_ = lookup(sb, nm)
            if z is not None:
                src_rows[z] = nm
    with open(pkg.path, 'rb') as fs, open(out_path, 'rb') as fg:
        names = sorted(set(src_rows.values()))
        for k, nm in enumerate(names):
            if limit and k >= limit:
                break
            if progress and k % 200 == 0:
                progress(k + 1, len(names), nm.decode('gbk', 'replace'))
            sz_, _, _ = lookup(sb, nm)
            nz, nb_bucket, steps = lookup(nb, nm)
            res['probe_steps_max'] = max(res['probe_steps_max'], steps)
            if nb_bucket != bucket_of(nm):
                res['collision'] += 1
            if nz is None:
                res['missing'] += 1
                res['errors'].append('新包按名字找不到：%s' % nm.decode('gbk', 'replace'))
                continue
            res['bucket_ok'] += 1
            a = _entry_plain(fs, src['ents'][sz_], pkg.data_off) if sz_ is not None else None
            b = _entry_plain(fg, new['ents'][nz], new['data_off'])
            if a is None:
                res['missing'] += 1
                res['errors'].append('源包按名字找不到：%s' % nm.decode('gbk', 'replace'))
                continue
            res['checked'] += 1
            if a[0] == b[0] and a[1] == b[1]:
                res['passed'] += 1
            else:
                res['failed'] += 1
                res['errors'].append('明文不一致：%s 源 %s/%s(%d) 新 %s/%s(%d)' % (
                    nm.decode('gbk', 'replace'), a[1], a[2], len(a[0]), b[1], b[2], len(b[0])))
            if (new['ents'][nz][0] - new['data_off']) % ALIGN:
                res['align_bad'] += 1

    # 名字表自洽
    di, bkt, steps = lookup(nb, LIST_NAME)
    if di is None:
        res['errors'].append('新包哈希表里没有 (list) 记录')
        return res
    o, s, fl = new['ents'][di]
    with open(out_path, 'rb') as g:
        g.seek(o)
        txt = g.read(s)
    lines = txt.split(b'\n')
    key = int(lines[0], 16)
    n = int(lines[1])
    rows = []
    for ln in lines[2:]:
        if not ln:
            continue
        pt = ln.split(b'|')
        rows.append((pt[0], int(pt[1], 16), int(pt[2], 16)))
    res['list_rows'] = len(rows)
    if n != len(rows):
        res['errors'].append('名字表行数不符：%d != %d' % (n, len(rows)))
    if [lower(r[0]) for r in rows] != sorted(lower(r[0]) for r in rows):
        res['list_order_bad'] += 1
        res['errors'].append('名字表不是按小写名字升序')
    x = 0xFFFFFFFF
    for nm, c1, c2 in rows:
        x ^= c2
    if (x & 0xFFFFFFFF) != key:
        res['list_key_bad'] += 1
        res['errors'].append('名字表第一行 key 不等于 0xFFFFFFFF^XOR(第二列)')
    with open(out_path, 'rb') as g:
        for nm, c1, c2 in rows:
            j, bb, st_ = lookup(nb, nm)
            if j is None:
                res['list_col2_bad'] += 1
                continue
            oo, ss, ff = new['ents'][j]
            g.seek(oo)
            raw = g.read(ss)
            if c1 != ss:
                res['list_col1_bad'] += 1
            if crc_axp(raw) != c2:
                res['list_col2_bad'] += 1
    if res['list_col1_bad']:
        res['errors'].append('名字表第一列有 %d 行不等于目录存储长度' % res['list_col1_bad'])
    if res['list_col2_bad']:
        res['errors'].append('名字表第二列有 %d 行不等于 crc_axp(整条原始字节)' % res['list_col2_bad'])
    return res


def _entry_plain(fh, ent, data_off):
    """把一条目录项还原成 (明文, 算法号或 None, 是否加密)。"""
    o, s, fl = ent
    if not s:
        return None
    fh.seek(o)
    raw = fh.read(s)
    if s > HDR_PLAIN and raw[:6] == axpcore.HDR_PREFIX:
        ph = axpcodex.decode_header(raw[:HDR_PLAIN])
        if ph[:15] != axpcodex.MAGIC:
            return raw, None, False
        a, blen, bcrc = parse_plain_header(ph)
        body = raw[HDR_PLAIN:]
        if bcrc == crc_axp(body):
            return body, a, False
        if a in axpcodex._kinds:
            return axpcodex.decode_body(a, axpcodex.body_pos(o, data_off), body), a, True
        return body, a, False
    return raw, None, False


def selftest():
    """模块自检：CRC 表/哈希表实现与实测基准值一致（不需要真包，全靠固化下来的实测数字）。

    基准值出处：
      crc_axp(b'')=0x00000000、crc_axp(b'a')=0x73D37CF3 —— Render.dll sub_1802730C0 的初值/收尾口径；
      bucket('(list)')=29955、pair('(list)')=8EE2C597/1EC97D8E —— 9 个包的哈希表实测；
      Model4 名字表首行 0灌木/Model4_分包用不能删.mesh → 桶 26134、目录序号 0、
      pair 6C57E670/98C2D707（与包内记录逐字相同）。
    """
    out = []
    for s in (b'', b'a', b'ab', b'12345678', b'123456789', bytes(range(256))):
        if crc_axp(s) != crc_axp_slow(s):
            out.append('CRC 快实现与逐字节实现不符：%r' % s)
    if crc_axp(b'') != 0x00000000 or crc_axp(b'a') != 0x73D37CF3:
        out.append('CRC 基准值不对：%08X %08X' % (crc_axp(b''), crc_axp(b'a')))
    if bucket_of(b'(list)') != 29955:
        out.append('(list) 桶号不对：%d（应为 29955）' % bucket_of(b'(list)'))
    if name_pair(b'(list)') != (0x8EE2C597, 0x1EC97D8E):
        out.append('(list) 校验字不对：%s' % (name_pair(b'(list)'),))
    nm = bytes.fromhex('30b9e0c4be2f4d6f64656c345fb7d6b0fcd3c3b2bbc4dcc9be2e6d657368')
    if name_pair(nm) != (0x6C57E670, 0x98C2D707) or bucket_of(nm) != 26134:
        out.append('Model4 首行名字的哈希三元组不对：%s %d' % (name_pair(nm), bucket_of(nm)))
    return out
