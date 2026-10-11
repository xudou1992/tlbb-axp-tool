"""AXPK (.axp) 引擎：解析、名字表对齐、形态识别、导出、审计。

  import axpcore
  pkg = axpcore.Package('Data/Config.axp')
  pkg.rows()                    # 每条：名字/形态/状态/长度
  axpcore.audit(pkg)            # 只读体检，不写文件
  axpcore.extract(pkg, 'out')   # 导出
"""
import bisect, hashlib, json, os, re, struct, zlib
from difflib import SequenceMatcher
import scriptcodec
try:
    import axpcodex                       # 25 路 AXP 编解码（需要 axp_tables.bin）
except Exception:                         # 表缺失时仍可解包，但不解码
    axpcodex = None

MAGIC = b'AXPK'
HDR_PREFIX = bytes.fromhex('84ccfa759a9d')
HDR_LEN = 96
REC = 12
NLIST_RE = re.compile(rb'^[0-9A-Fa-f]{6,10}\n\d{1,7}\n')
BAD_CHARS = re.compile(r'[\x00-\x1f<>:"|?*]')

RAW, PLAIN, OPAQUE = 'raw', 'plain', 'opaque'
FORM_CN = {RAW: '原文', PLAIN: '带头明文', OPAQUE: '密文(可解码)'}
OK, REWRITTEN, UNKNOWN = 'ok', 'rewritten', 'unknown'

TABLE_MAGIC = bytes.fromhex('00ccbbdd')            # TLBB 表头 00 cc bb dd
SCRIPT_MAGIC = bytes.fromhex('d2d1e2e1b2b1c2c1')   # 已编译脚本容器
TABLE_MAGICS = (TABLE_MAGIC, b'MGR_TXT', bytes.fromhex('00105b4d'),
                bytes.fromhex('00105b53'), SCRIPT_MAGIC)
OTHER_MAGICS = (b'DDS ', b'<?xml', b'PK\x03\x04', b'RIFF', b'OggS', b'GIF8', b'\x89PNG',
                b'\xff\xd8\xff', b'[Mesh', b'[Submesh', b'[Serializer', b'[Material',
                b'\x00\x10', b'BM')


def decode_name(raw):
    return decode_name_ex(raw)[0]


def decode_name_ex(raw):
    """返回 (文本, 编码)。编码要一起记住，落盘时才能用同一种编码还原真名。"""
    for enc in ('gbk', 'utf-8'):
        try:
            return raw.decode(enc), enc
        except (UnicodeDecodeError, ValueError):
            pass
    return raw.decode('gbk', 'replace'), 'gbk'


def _is_textish(data):
    """ASCII、GBK 双字节、TAB/CRLF 混排都算可读；用于识别文本型负载。"""
    n = 0
    while n < len(data):
        c = data[n]
        if 32 <= c < 127 or c in (9, 10, 13):
            n += 1
            continue
        if c >= 0x81 and n + 1 < len(data) and (0x40 <= data[n + 1] <= 0xfe) and data[n + 1] != 0x7f:
            n += 2                       # GBK 汉字
            continue
        return False
    return True


STRONG_MAGICS = (b'DDS ', b'<?xml', b'PK\x03\x04', b'RIFF', b'OggS', b'GIF8', b'\x89PNG',
                 b'\xff\xd8\xff', b'[Mesh', b'[Submesh', b'[Serializer', b'[Material',
                 b'\x00\x10[', b'BM', b'\x00\x10\x00', TABLE_MAGIC, b'MGR_TXT', SCRIPT_MAGIC)


def _text_ratio(data):
    """可读字节占比（ASCII + GBK 双字节 + UTF-8 多字节 + UTF-16 + TAB/CRLF），返回 0~1。"""
    if not data:
        return 0.0
    n = hits = 0
    L = len(data)
    while n < L:
        c = data[n]
        if 32 <= c < 127 or c in (9, 10, 13):
            if n + 1 < L and data[n + 1] == 0 and c != 0 and data[n:n + 8].count(0) >= 3:
                return 1.0                      # UTF-16 LE 文本，整段判可读
            hits += 1
            n += 1
        elif c >= 0x81 and n + 1 < L and 0x40 <= data[n + 1] <= 0xfe and data[n + 1] != 0x7f:
            hits += 2
            n += 2
        elif 0xC2 <= c <= 0xDF and n + 1 < L and 0x80 <= data[n + 1] <= 0xBF:
            hits += 2
            n += 2
        elif 0xE0 <= c <= 0xEF and n + 2 < L and all(0x80 <= data[n + k] <= 0xBF for k in (1, 2)):
            hits += 3
            n += 3
        elif 0xF0 <= c <= 0xF4 and n + 3 < L and all(0x80 <= data[n + k] <= 0xBF for k in (1, 2, 3)):
            hits += 4
            n += 4
        else:
            n += 1
    return hits / float(L)


CONTAINER_MAGICS = (b'AXFT', b'\x1aE\xdf\xa3', b'\x00\x01\x00\x00', b'OTTO',
                    bytes.fromhex('00000200'), bytes.fromhex('00000a00'))


def _is_container(data):
    """打包器自己的容器/已知二进制格式：内容没问题，只是与后缀对不上。"""
    if len(data) < 8:
        return False
    if data[:4] in CONTAINER_MAGICS:
        return True
    if data[4:8] == b'ftyp':
        return True
    if data[:2] == b'\x00\x00' and data[3] == 0 and data[4:12] == b'\x00' * 8:
        return True                             # 00 00 <n> 00 + 8 个零的贴图容器族
    return False


def _blank(data):
    return len(data) > 0 and set(data[:128]) <= {0}


# 实测反推的「每 15 字节改写」密钥：块体位置 p 若 p%15==0，则存储值 = 原文 ⊕ KEY15[(p//15)%128]，
# 其余位置密钥为 0。来源：常量填充段反推 1000 个连续位置（自洽、周期严格 128）+ DDS/mesh 已知明文核对。
# 只在部分块类型（h16=0x5e/0x54/0x50）验证有效，不是全库通解；判定按块逐个做（复原后魔数要成立）。
KEY15 = bytes.fromhex(
    'da3c12320e7c5a66b012a890aa404202'
    '34d868e8bc7e6a3e186af4ec5ce2786c'
    '8056783458586efaa45e9642ea3274f0'
    'fc2ce8ce96c01e94401e306e9eee6a2e'
    'c42614720eea72eaace286d43ace1ce0'
    'b0c0d848bcd6865c5e4a587a2e2ae8b8'
    '4290905278e4aed870b8406cb832223c'
    '4000d8b6da7ec80872c09e10bede5ccc')


def descramble15(buf, at=0):
    """按 KEY15 复原块体的每 15 字节改写；at = buf 首字节在块体内的偏移（便于分块）。"""
    out = bytearray(buf)
    n = len(out)
    i = (-at) % 15
    k = (at + i) // 15
    while i < n:
        out[i] ^= KEY15[k % 128]
        i += 15
        k += 1
    return bytes(out)


# ---- AXP 名字哈希（照 Render.dll 的 sub_180272D00 + sub_180272EA0 复刻）----
# 表：1024 个 dword，由 LCG x=(125*x+3)%0x2AAAAB（种子 1048577）生成；
# 哈希：A=0x7FED7FED, B=0xEEEEEEEE，逐字节（**有符号 char**，中文名会踩符号扩展）：
#   A = (B + A) ^ TAB[(which << 8) + c] ；B = A + c + 33*B + 3
# 哈希表项 = {hash(name.lower(),1), hash(name.lower(),2), 目录序号|0x80000000}，
# 桶位 = hash(...,3) & 0x7FFF 起线性探测（实测 Model4 53/54 对上；老包可能用别的名字写法）。
_HASHM = 0x2AAAAB


def gen_hashtable():
    T = [0] * 1024
    v2 = 1048577
    for i in range(256):
        p = 256 + i
        v5 = (125 * v2 + 3) % _HASHM
        v6 = (v5 << 16) & 0xFFFFFFFF
        v7 = (125 * v5 + 3) % _HASHM
        T[p - 256] = v6 | (v7 & 0xFFFF)
        v8 = (125 * v7 + 3) % _HASHM
        v9 = (v8 << 16) & 0xFFFFFFFF
        v10 = (125 * v8 + 3) % _HASHM
        T[p] = v9 | (v10 & 0xFFFF)
        v11 = (125 * v10 + 3) % _HASHM
        v12 = (v11 << 16) & 0xFFFFFFFF
        v13 = (125 * v11 + 3) % _HASHM
        T[p + 256] = v12 | (v13 & 0xFFFF)
        v14 = (125 * v13 + 3) % _HASHM
        v15 = (v14 << 16) & 0xFFFFFFFF
        v2 = (125 * v14 + 3) % _HASHM
        T[p + 511] = v15 | (v2 & 0xFFFF)
    return T


HASHTAB = gen_hashtable()


def axp_hash(name, which, tab=None):
    if isinstance(name, str):
        name = name.encode('gbk', 'replace')
    T = tab or HASHTAB
    A = 0x7FED7FED
    B = 0xEEEEEEEE
    for b in name:
        c = b - 256 if b >= 128 else b          # _BYTE 是有符号 char
        A = ((B + A) ^ T[((which << 8) + c) & 0x3FF]) & 0xFFFFFFFF
        B = (A + c + 33 * B + 3) & 0xFFFFFFFF
    return A


def axp_pair(name):
    """哈希表里该名字应占的两个校验字。"""
    low = name.lower() if isinstance(name, str) else bytes(name).lower()
    return (axp_hash(low, 1), axp_hash(low, 2))


def name_from_hash(pool, a1, a2):
    """在候选名字池里找哈希对得上的名字；pool 是 {名字(小写 str/bytes): ...} 或可迭代。"""
    for nm in pool:
        if axp_pair(nm) == (a1, a2):
            return nm
    return None


def classify(head):
    if len(head) < 6 or head[:6] != HDR_PREFIX:
        return RAW
    body = head[HDR_LEN:]
    if len(body) < 16:
        return OPAQUE
    probe = body[:64]
    if any(m in probe[:16] for m in STRONG_MAGICS):
        return PLAIN
    n = sum(1 for c in probe if (32 <= c < 127 or c in (9, 10, 13)))
    if n / len(probe) < 0.7:
        return OPAQUE
    pair = sum(1 for i in range(len(probe) - 1)
               if probe[i] >= 0x81 and 0x40 <= probe[i + 1] <= 0xfe)
    return PLAIN if (n + pair * 2) / len(probe) > 0.9 else OPAQUE


def periodic_rewrites(data, mod=15, limit=2048):
    """带头明文里，有些条目每 mod 字节就有一个字节被改写。返回可疑位置列表。
    只在"整体以文本为主（≥85% 可读）"的内容上判定——二进制资源（mesh/scene 序列化等）
    会产出大量假阳性；而真被改写的样本只有零星坏字节，所以这里用比例门而不是全有全无。"""
    seg = data[:limit]
    if len(seg) < mod * 3:
        return []
    if not _is_textish(seg[:mod * 2]):
        return []
    ok = sum(1 for c in seg if 32 <= c < 127 or c in (9, 10, 13) or c >= 0x81)
    if ok / len(seg) < 0.85:
        return []
    bad = []
    for i in range(0, len(seg) - mod, mod):
        a, b, c = seg[i:i + 3]
        # 该位置异常：本身不可读，但同块后续可读
        if not (32 <= a < 127 or a in (9, 10, 13) or a >= 0x81):
            if all(32 <= x < 127 or x in (9, 10, 13) or x >= 0x81 for x in (b, c)):
                bad.append(i)
    return bad


def magic_offset(data):
    """内容里的已知魔数不在 0 位（首字节被改写）时返回那个偏移，否则 None。"""
    if data[:3] == b'\xef\xbb\xbf' or data[:2] in (b'\xff\xfe', b'\xfe\xff'):
        return None                              # BOM 开头：不是"首字节被改写"
    if data[:2] == b'\x00\x10':
        return None                              # OGRE 序列化的正规两字节长度前缀，魔数就在偏移 2
    if data[:4] in (b'DDS ', b'<?xm', b'RIFF', b'OggS', b'GIF8', b'\x89PNG', b'PK\x03\x04', b'[Mes'):
        return None
    for off in (1, 2, 3):
        win = data[off:off + 8]
        if any(m in win for m in (b'DDS ', b'<?xml', b'RIFF', b'OggS', b'GIF8', b'\x89PNG',
                                  b'[Mesh', b'[Serializer', b'Serialized')):
            return off
        if off == 1 and data[1:4] == b'DS ':        # DDS 首字节被改写
            return 1
        if off == 1 and data[1:4] == b'?xml':       # xml 首字节被改写
            return 1
    return None


def magic_match(name, data):
    """按后缀校验内容。True 对 / False 真不符 / None 判不了 / 'other' 内容有效但类型与后缀不同。"""
    if not name or not data:
        return None
    low = name.lower()
    ext = low.rsplit('.', 1)[-1] if '.' in low else ''
    head = data[:24]
    if any(data[:len(m)] == m for m in TABLE_MAGICS) or head[:2] == b'\x00\x10':
        return True
    if _blank(data):
        return None            # 全零占位文件，无从判断
    if _is_container(data):
        return True            # 打包器自己的贴图/视频容器，格式是认得的
    if ext == 'dds':
        return True if (data[:4] == b'DDS ' or data[1:4] == b'DS ') else _other(data)
    if ext in ('mesh', 'skeleton'):
        return True if (head[:2] == b'\x00\x10' or b'[Mesh' in head or b'[Serializer' in head
                        or b'Serialized' in data[:64]) else _other(data)
    if ext in ('xml',):
        bom8 = bytes.fromhex('efbbbf')
        if data[:3] == bom8 or data[:2] in (bytes.fromhex('fffe'), bytes.fromhex('feff')):
            return True
        body = data.lstrip(bom8)
        if body[:1] == b'<' or head.lstrip()[:5] == b'<?xml' or b'xml' in data[:40]:
            return True
        return _other(data)
    if ext == 'png':
        return True if data[:4] == b'\x89PNG' else _other(data)
    if ext in ('jpg', 'jpeg'):
        return True if data[:3] == b'\xff\xd8\xff' else _other(data)
    if ext == 'gif':
        return True if head[:3] == b'GIF' else _other(data)
    if ext == 'ogg':
        return True if head[:4] == b'OggS' else _other(data)
    if ext in ('mp3', 'mp2'):
        if data[:3] == b'ID3':                       # 带 ID3v2 标签的 mp3（Sound.axp 实测 118 条）
            return True
        if data[0] == 0xFF and (data[1] & 0xE0) == 0xE0:
            return True
        return _other(data)
    if ext == 'wav':
        return True if head[:4] == b'RIFF' else _other(data)
    if ext in ('lua', 'txt', 'tab', 'dat', 'ini', 'cfg', 'conf', 'script', 'desc', 'gis',
               'skl', 'act', 'list', 'inc', 'def'):
        return True if _text_ratio(data[:256]) > 0.95 else _other(data)
    return None


def _other(data):
    """内容本身是另一种有效格式（源文件后缀就不对），不算我们的错。"""
    if any(m in data[:16] for m in OTHER_MAGICS):
        return 'other'
    if _text_ratio(data[:256]) > 0.98:
        return 'other'
    return False


class Row(object):
    __slots__ = ('index', 'offset', 'stored', 'flag', 'region', 'form', 'content_len',
                 'spill', 'name', 'name_raw', 'name_enc', 'named_by', 'name_verified',
                 'status', 'magic_ok', 'rewrite_at', 'ftype', 'light15', 'script', 'algo')

    def __init__(self, index, offset, stored, flag, region, form, content_len, spill):
        self.index = index
        self.offset = offset
        self.stored = stored
        self.flag = flag
        self.region = region
        self.form = form
        self.content_len = content_len
        self.spill = spill
        self.name = None
        self.name_raw = b''
        self.name_enc = 'gbk'
        self.named_by = None
        self.name_verified = None
        self.status = UNKNOWN
        self.magic_ok = None
        self.rewrite_at = []
        self.ftype = None
        self.light15 = False
        self.script = False
        self.algo = None

    @property
    def display(self):
        return self.name if self.name else '(未命名)#%d' % self.index

    @property
    def encodable(self):
        """有块头算法号，且该算法已在 codec 层实现。"""
        return (axpcodex is not None and self.algo is not None
                and axpcodex.algo_kind(self.algo) is not None)

    @property
    def status_cn(self):
        if self.script:
            return '脚本容器'
        if self.encodable and self.algo != 19:
            return '正常' if self.magic_ok is True else '可解码(算法%d)' % self.algo
        if self.form == OPAQUE and not self.encodable:
            return '未解出'
        if self.light15:
            return '每15字节有改写'
        if self.spill:
            return '长度异常'
        if self.magic_ok is False:
            return '内容异常'
        if self.magic_ok == 'other':
            return '后缀与内容不一致'
        if not self.name:
            return '无名字'
        return '正常'


class Package(object):
    def __init__(self, path):
        self.path = path
        self.name = os.path.basename(path)
        self.size = os.path.getsize(path)
        with open(path, 'rb') as f:
            head = f.read(0x28)
            if head[:4] != MAGIC:
                raise ValueError('不是 AXPK 包：%s' % path)
            self.dir_off = struct.unpack_from('<I', head, 0x10)[0]
            self.count = struct.unpack_from('<I', head, 0x14)[0]
            self.data_off = struct.unpack_from('<I', head, 0x1C)[0]
            self.data_len = struct.unpack_from('<I', head, 0x20)[0]
            f.seek(self.dir_off)
            raw = f.read(self.count * REC)
            if len(raw) < self.count * REC:
                raise ValueError('目录不完整：%s' % path)
            self.entries = [struct.unpack_from('<3I', raw, i * REC) for i in range(self.count)]
            self.lists = self._read_name_lists(f)
            offs = sorted(e[0] for e in self.entries)
            self.rows_list = self._build(f, offs)

    def _read_name_lists(self, f):
        lists = []
        for i, (o, s, _fl) in enumerate(self.entries):
            if s < 40:
                continue
            f.seek(o)
            if not NLIST_RE.match(f.read(32)):
                continue
            f.seek(o)
            body = f.read(s)
            lines = body.split(b'\n')
            rows = []
            for line in lines[2:]:
                parts = line.split(b'|')
                if len(parts) >= 3:
                    try:
                        rows.append((parts[0], int(parts[1], 16), int(parts[2], 16)))
                    except ValueError:
                        continue
            if rows:
                lists.append({'index': i, 'key': lines[0].decode('ascii', 'replace'), 'rows': rows})
        return lists

    def _region(self, offset, offs):
        j = bisect.bisect_right(offs, offset)
        return offs[j] - offset if j < len(offs) else self.size - offset

    def _build(self, f, offs):
        rows = []
        hdrs = []
        for i, (o, s, fl) in enumerate(self.entries):
            if s <= 0:
                continue
            region = self._region(o, offs)
            f.seek(o)
            head = f.read(min(max(s, HDR_LEN + 64), 256))
            form = classify(head)
            base = HDR_LEN if form != RAW else 0
            content = s - base
            if content <= 0:
                continue
            rows.append(Row(i, o, s, fl, region, form, content, max(0, base + content - region)))
            hdrs.append(head[:HDR_LEN] if form != RAW else b'')
            if head[(HDR_LEN if form != RAW else 0):][:8] == scriptcodec.MAGIC:
                rows[-1].script = True
        self._assign_names(rows)
        for k, r in enumerate(rows):
            r.ftype = hdrs[k][16] if len(hdrs[k]) == HDR_LEN else None
            r.algo = self._algo(hdrs[k])
            data = self.read(r, limit=4096, fh=f)
            if r.encodable and not r.script:
                data = self.decode(r, data)
            r.magic_ok = magic_match(r.display, data)
            spots = periodic_rewrites(data)
            off = magic_offset(data)
            r.rewrite_at = spots if spots else ([off] if off else [])
            if (spots or off) and not r.encodable:
                r.light15 = True
                r.status = REWRITTEN
            elif r.magic_ok is True:
                r.status = OK
            else:
                r.status = UNKNOWN
        return rows

    def _algo(self, hdr96):
        if axpcodex is None or len(hdr96) != HDR_LEN or hdr96[:6] != HDR_PREFIX:
            return None
        try:
            ph = axpcodex.decode_header(hdr96)
        except Exception:
            return None
        if ph[:15] != axpcodex.MAGIC:
            return None
        return axpcodex.header_algo(ph)

    def body_pos(self, offset):
        """正文密钥流的起点：相对数据区起点（已用游戏输出实测确认）。"""
        if axpcodex is None:
            return 0
        return axpcodex.body_pos(offset, self.data_off)

    def decode(self, row, data=None):
        """把包内字节解成游戏实际拿到的明文；没算法可解时原样返回。"""
        if data is None:
            data = self.read(row)
        if not row.encodable or row.script:
            return data
        return axpcodex.decode_body(row.algo, self.body_pos(row.offset), data)

    def encode(self, row, plain):
        """把明文编回包内字节（回包用）。pos 用的是这条目当前的相对位置。"""
        if not row.encodable or row.script:
            return plain
        return axpcodex.encode_body(row.algo, self.body_pos(row.offset), plain)

    def _ftype(self, f, r):
        f.seek(r.offset + 16)
        b = f.read(1)
        return b[0] if b else None

    def _assign_names(self, rows):
        """名字表逐行 = 目录里 flag≠0（进哈希表）的条目，按目录顺序，一一对应。
        23 个包里 21 个行数完全相等；不等时（Material8/Brushes）再按长度序列对齐。"""
        best = None
        for lst in self.lists:
            slots = [r for r in rows if r.flag and r.index != lst['index']]
            if len(slots) == len(lst['rows']):
                pairs = {slot: (i, 'order') for i, slot in enumerate(slots)}
                best = (1.0, lst, slots, pairs)
                break
            pairs = self._align(lst, slots)
            score = len(pairs) / max(1, len(slots))
            if best is None or score > best[0]:
                best = (score, lst, slots, pairs)
        lst = best[1] if best else None
        self.name_list = lst
        self.align_exact = bool(best and best[0] >= 1.0)
        self.list_pairs = {}
        if best:
            for row, (k, how) in best[3].items():
                raw_name = lst['rows'][k][0]
                row.name_raw, row.named_by = raw_name, how
                row.name, row.name_enc = decode_name_ex(raw_name)
                self.list_pairs[row.index] = k
        by_index = {r.index: r for r in rows}
        for l in self.lists:
            row = by_index.get(l['index'])
            if row is None or row.name:
                continue
            label = '名字表_%s.txt' % l['key'] if l is lst else '名字表_副本%d.txt' % l['index']
            row.name_raw, row.name, row.named_by = label.encode('gbk', 'replace'), label, 'self'
            row.name_enc = 'gbk'
        self._fix_names_by_hash(rows)
        self.verify_names(rows)

    def _fix_names_by_hash(self, rows):
        """名字表按位置发名字是错的（实测 Config 只有 103/1878、Interface 1165/8023 对得上，
        Model4 恰好对齐所以骗过了早期自检）。游戏只按哈希定位，所以拿名字池算哈希反查每条的真名。
        返回改名的条目数；哈希查不到唯一名字的条目保留位置法结果，由 name_verified=False 标出。"""
        hp = self.hash_pairs()
        pool = {}
        for l in self.lists:
            for rec in l['rows']:
                raw = bytes(rec[0])
                pool.setdefault(axp_pair(raw.lower()), {})[raw] = None
        by_index = {r.index: r for r in rows}
        fixed = 0
        for i, pr in hp.items():
            r = by_index.get(i)
            if r is None or r.named_by == 'self':
                continue
            hits = pool.get(pr)
            if not hits or len(hits) != 1:
                continue
            raw = next(iter(hits))
            if bytes(r.name_raw or b'').lower() == raw.lower():
                continue
            r.name_raw, r.named_by = raw, 'hash'
            r.name, r.name_enc = decode_name_ex(raw)
            fixed += 1
        if fixed:
            self.names_fixed_by_hash = fixed
        return fixed

    def verify_names(self, rows=None):
        """逐行把「名字 ↔ 包内哈希表」核对结果写进 row.name_verified：
        True/False = 有哈希对且比过了；None = 这行没名字或目录序号不在哈希表里。"""
        hp = self.hash_pairs()
        for r in (self.rows_list if rows is None else rows):
            pr = hp.get(r.index) if r.name_raw else None
            r.name_verified = None if pr is None else (
                axp_pair(bytes(r.name_raw).lower()) == pr)

    def _align(self, lst, slots):
        """名字表与目录按“存储长度序列”保序对齐；序号硬对在 Config 只有 70%、Model8 只有 1.7%。"""
        a = [r[1] for r in lst['rows']]
        b = [r.stored for r in slots]
        pairs = {}
        sm = SequenceMatcher(None, a, b, autojunk=False)
        for blk in sm.get_matching_blocks():
            for d in range(blk.size):
                pairs[slots[blk.b + d]] = (blk.a + d, 'seq')
        used_rows = set(v[0] for v in pairs.values())
        for tag, i1, i2, j1, j2 in sm.get_opcodes():
            if tag != 'replace':
                continue
            gap_rows = [i for i in range(i1, i2) if i not in used_rows]
            gap_slots = [slots[j] for j in range(j1, j2)]
            if len(gap_rows) == len(gap_slots) and gap_rows:
                for ri, slot in zip(gap_rows, gap_slots):
                    pairs[slot] = (ri, 'gap')
                    used_rows.add(ri)
        return pairs

    def rows(self):
        return self.rows_list

    def hash_pairs(self):
        """目录序号 -> 哈希表里的两个校验字（同一序号被多个桶命中时取先见到的）。"""
        if not hasattr(self, '_hp'):
            out = {}
            n = min((self.dir_off - 0x28) // REC, 32768)
            with open(self.path, 'rb') as f:
                f.seek(0x28)
                blob = f.read(n * REC)
            for b in range(n):
                a1, a2, z = struct.unpack_from('<3I', blob, b * REC)
                if z & 0x80000000:
                    out.setdefault(z & 0x3FFFFFFF, (a1, a2))
            self._hp = out
        return self._hp

    def check_names(self):
        """用哈希校验「名字 ↔ 条目」的对应是否成立。返回 (成立数, 有哈希的有名条目数)。"""
        hp = self.hash_pairs()
        ok = tot = 0
        for r in self.rows_list:
            if not r.name_raw:
                continue
            pr = hp.get(r.index)
            if pr is None:
                continue
            tot += 1
            if axp_pair(bytes(r.name_raw).lower()) == pr:
                ok += 1
        return ok, tot

    def fill_names(self, pool):
        """名字缺失的条目，拿候选名字池（如 versionlist 的全量路径）按哈希反查补齐。
        返回补上的条数。pool 里用不到的名字会被跳过。"""
        hp = self.hash_pairs()
        by_index = {r.index: r for r in self.rows_list}
        want = {i: pr for i, pr in hp.items()
                if i in by_index and not by_index[i].name_raw}
        if not want:
            return 0
        target = {(a1, a2): [] for a1, a2 in want.values()}
        for nm in pool:
            key = axp_pair(bytes(nm).lower() if not isinstance(nm, str) else nm)
            if key in target:
                target[key].append(nm)
        got = 0
        for i, (a1, a2) in want.items():
            hits = target.get((a1, a2)) or []
            if len(hits) != 1:
                continue
            r = by_index[i]
            raw = hits[0] if isinstance(hits[0], bytes) else hits[0].encode('gbk', 'replace')
            r.name_raw, r.named_by = raw, 'hash'
            r.name, r.name_enc = decode_name_ex(raw)
            got += 1
        if got:
            self.verify_names()
        return got

    def read(self, row, limit=None, fh=None):
        base = row.offset + (0 if row.form == RAW else HDR_LEN)
        want = row.content_len if limit is None else min(limit, row.content_len)
        own = fh is None
        if own:
            fh = open(self.path, 'rb')
        try:
            fh.seek(base)
            data = fh.read(want)
        finally:
            if own:
                fh.close()
        if len(data) != want:
            raise IOError('读取不足：条目 %d 期望 %d 实得 %d' % (row.index, want, len(data)))
        return data

    def stats(self):
        c = {RAW: 0, PLAIN: 0, OPAQUE: 0}
        named = rewritten = magic_bad = magic_other = spill = gap_named = light15 = scripts = 0
        name_ok = name_checked = 0
        decodable = undecoded = 0
        bytes_total = 0
        for r in self.rows_list:
            c[r.form] += 1
            if r.encodable:
                decodable += 1
            elif r.form == OPAQUE and not r.script:
                undecoded += 1          # 真"未解出"：带块头且算法未转写、当前解不了
            if r.script:
                scripts += 1
            if r.light15:
                light15 += 1
            if r.name:
                named += 1
            if r.named_by == 'gap':
                gap_named += 1
            if r.name_verified is True:
                name_ok += 1
            if r.name_verified is not None:
                name_checked += 1
            if r.status == REWRITTEN:
                rewritten += 1
            if r.magic_ok is False:
                magic_bad += 1
            elif r.magic_ok == 'other':
                magic_other += 1
            if r.spill:
                spill += 1
            if r.form != OPAQUE:
                bytes_total += r.content_len
        return dict(entries=self.count, items=len(self.rows_list), raw=c[RAW], plain=c[PLAIN],
                    opaque=c[OPAQUE], decodable=decodable, undecoded=undecoded,
                    named=named, unnamed=len(self.rows_list) - named,
                    name_ok=name_ok, name_checked=name_checked,
                    light15=light15, scripts=scripts,
                    gap_named=gap_named, rewritten=rewritten, magic_bad=magic_bad,
                    magic_other=magic_other, spill=spill, extract_bytes=bytes_total,
                    lists=[(l['index'], len(l['rows'])) for l in self.lists],
                    list_key=self.name_list['key'] if self.name_list else '-')


def safe_relpath(name_raw, index, enc='gbk'):
    rel = name_raw.decode(enc, 'replace') if isinstance(name_raw, bytes) else (name_raw or '')
    rel = rel.replace('\\', '/')
    parts = []
    for seg in rel.split('/'):
        seg = BAD_CHARS.sub('_', seg).strip().strip('.')
        if seg in ('', '.', '..'):
            continue
        parts.append(seg)
    if not parts:
        parts = ['未命名_%d' % index]
    return os.path.join(*parts)


def _fit(outdir, rel, budget):
    """Windows 260 字符路径上限的挤压：先削最长的中间目录名，再削文件名主干。"""
    full = os.path.normpath(os.path.join(outdir, rel))
    if len(full) <= budget:
        return full
    segs = rel.split(os.sep)
    guard = 0
    while len(full) > budget and guard < 400:
        guard += 1
        if len(segs) > 1:
            i = max(range(len(segs) - 1), key=lambda j: len(segs[j]))
            if len(segs[i]) > 6:
                segs[i] = segs[i][:6]
            else:
                segs.pop(i)
        else:
            stem, ext = os.path.splitext(segs[0])
            segs[0] = stem[:max(6, len(stem) - 8)] + ext
        full = os.path.normpath(os.path.join(outdir, os.sep.join(segs)))
    return full


def target_path(outdir, row, used, budget=240):
    rel = safe_relpath(row.name_raw, row.index, row.name_enc)
    if row.form == OPAQUE and not row.encodable and not row.script:
        # 只有"真落原样密文"（解不了）才加 .enc；能解码的条目导出的是解密后的真实文件，用原名
        rel += '.enc'
    base, ext = os.path.splitext(rel)
    key = rel.lower()
    n = used.get(key, 0) + 1
    used[key] = n
    if n > 1:
        while True:
            cand = '%s (重名%d)%s' % (base, n, ext)
            if cand.lower() not in used:
                used[cand.lower()] = 1
                rel = cand
                break
            n += 1
    return _fit(outdir, rel, budget)


CHUNK = 1 << 22


def extract(pkg, outdir, include_enc=False, progress=None, cancel=None, verify=True,
            used=None, budget=240, decode=True, override=None, manifest=False):
    """导出。默认对「脚本容器」条目就地解密后落盘（decode=False 可拿到原始字节）。
    used 可跨包共用，避免两个同名包写进同一个文件；
    override = {条目下标: 字节}：这些条目直接落 override 给的字节（有效资源/补丁覆盖用，
    不再从包里读也不按包内算法解）；统计里 override_used 单独计数。
    每条先写 .part 再改名，中断/异常不会留下半成品。
    manifest=True 时在 outdir 写 .axp_export_manifest.json（文件→size+sha1+条目号），
    文件夹打包回 AXP 时靠它免解密核对，大包提速的关键。"""
    os.makedirs(outdir, exist_ok=True)
    if used is None:
        used = {}
    st = dict(written=0, skipped=0, bytes=0, verify_bad=0, errors=[], cancelled=False,
              decoded=0, decode_fail=0, codec_by_algo={}, override_used=0)
    man = {} if manifest else None
    def _man_add(dest, size, digest, row):
        if man is not None and getattr(row, 'named_by', None) != 'self':
            man[os.path.relpath(dest, outdir).replace('\\', '/').lower()] = \
                [size, digest, row.index]
    rows = pkg.rows()
    with open(pkg.path, 'rb') as src:
        for k, row in enumerate(rows):
            if cancel is not None and cancel.is_set():
                st['cancelled'] = True
                break
            if progress and (k % 25 == 0 or k == len(rows) - 1):
                progress(k + 1, len(rows), row.display)
            if override and row.index in override:
                buf = override[row.index]
                dest = target_path(outdir, row, used, budget)
                tmp = dest + '.part'
                try:
                    d = os.path.dirname(dest)
                    if d:
                        os.makedirs(d, exist_ok=True)
                    with open(tmp, 'wb') as g:
                        g.write(buf)
                    os.replace(tmp, dest)
                    st['written'] += 1
                    st['bytes'] += len(buf)
                    st['override_used'] += 1
                    if man is not None:
                        _man_add(dest, len(buf), hashlib.sha1(buf).hexdigest(), row)
                except Exception as exc:
                    st['errors'].append('%s：%s' % (row.display, exc))
                continue
            if row.form == OPAQUE and not include_enc and not row.encodable:
                st['skipped'] += 1
                continue
            dest = target_path(outdir, row, used, budget)
            tmp = dest + '.part'
            try:
                d = os.path.dirname(dest)
                if d:
                    os.makedirs(d, exist_ok=True)
                base = row.offset + (0 if row.form == RAW else HDR_LEN)
                left = row.content_len
                got = 0
                blob = None
                if decode and row.script:
                    src.seek(base)
                    blob = scriptcodec.decode_container(src.read(left))
                    if blob is None:
                        st['decode_fail'] += 1
                        left = row.content_len
                elif decode and row.encodable:
                    src.seek(base)
                    raw = src.read(left)
                    try:
                        blob = pkg.decode(row, raw)
                        st['codec_by_algo'][row.algo] = \
                            st['codec_by_algo'].get(row.algo, 0) + 1
                    except Exception:
                        blob = raw
                        st['decode_fail'] += 1
                        left = row.content_len
                hh = hashlib.sha1() if man is not None else None
                with open(tmp, 'wb') as g:
                    if blob is not None:
                        g.write(blob)
                        got = len(blob)
                        if hh is not None:
                            hh.update(blob)
                    else:
                        src.seek(base)
                        while left > 0:
                            chunk = src.read(min(left, CHUNK))
                            if not chunk:
                                raise IOError('读取不足：期望 %d 实得 %d' % (row.content_len, got))
                            g.write(chunk)
                            left -= len(chunk)
                            got += len(chunk)
                            if hh is not None:
                                hh.update(chunk)
                if verify:
                    real = os.path.getsize(tmp)
                    if real != got:
                        st['verify_bad'] += 1
                        st['errors'].append('回读长度不符 %s：%d!=%d' % (
                            row.display, real, got))
                        os.remove(tmp)
                        continue
                os.replace(tmp, dest)
                st['written'] += 1
                st['bytes'] += got
                if blob is not None:
                    st['decoded'] += 1
                if hh is not None:
                    _man_add(dest, got, hh.hexdigest(), row)
            except Exception as exc:
                st['errors'].append('%s：%s' % (row.display, exc))
                if os.path.exists(tmp):
                    try:
                        os.remove(tmp)
                    except OSError:
                        pass
    if man is not None:
        try:
            with open(os.path.join(outdir, '.axp_export_manifest.json'), 'w',
                      encoding='utf-8') as f:
                json.dump({'pkg': os.path.basename(pkg.path), 'entries': man}, f,
                          ensure_ascii=False)
            st['manifest'] = len(man)
        except Exception as exc:
            st['errors'].append('导出清单写入失败：%s' % exc)
    return st


def audit(pkg, deep=0):
    """只读体检。deep>0 时额外抽样比对包内字节与导出逻辑（不写文件）。"""
    issues = []
    s = pkg.stats()
    kinds = {}
    ftypes = {}
    for r in pkg.rows_list:
        kinds[r.status_cn] = kinds.get(r.status_cn, 0) + 1
        if r.ftype is not None:
            k = '%02x' % r.ftype
            ftypes[k] = ftypes.get(k, 0) + 1
    for r in pkg.rows_list:
        if r.spill:
            issues.append('条目%d(%s) 内容超出区段 %d 字节' % (r.index, r.display, r.spill))
        if r.magic_ok is False:
            issues.append('条目%d(%s) 内容读不出已知格式' % (r.index, r.display))
    bad_names = [r for r in pkg.rows_list
                 if r.name_verified is False and r.named_by != 'self']
    for r in bad_names[:5]:
        issues.append('条目%d(%s) 名字与包内哈希表对不上（名字表可能错位）' % (r.index, r.display))
    if len(bad_names) > 5:
        issues.append('……名字与包内哈希表对不上的共 %d 条，其余从略' % len(bad_names))
    checked = 0
    if deep:
        step = max(1, len(pkg.rows_list) // max(1, deep))
        for r in pkg.rows_list[::step]:
            if r.form == OPAQUE:
                continue
            data = pkg.read(r)
            if len(data) != r.content_len:
                issues.append('条目%d 长度自校验失败' % r.index)
            raw = None
            with open(pkg.path, 'rb') as f:
                f.seek(r.offset + (0 if r.form == RAW else HDR_LEN))
                raw = f.read(len(data))
            if raw != data:
                issues.append('条目%d 内容与包内字节不一致' % r.index)
            checked += 1
    algo = {}
    decodable = 0
    for r in pkg.rows_list:
        if r.algo is not None:
            algo[r.algo] = algo.get(r.algo, 0) + 1
        if r.encodable:
            decodable += 1
    return dict(stats=s, issues=issues[:120], issue_total=len(issues), deep_checked=checked,
                kinds=kinds, ftypes=ftypes, algo=algo, decodable=decodable)
