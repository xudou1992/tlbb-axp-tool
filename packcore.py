"""写侧引擎：.xzip 补丁包解包/打包、.axp 回包、文件夹改动 -> 官方格式 .xzip 补丁。全程只在用户选定的目录里读写。

  import packcore
  packcore.xzip_unpack('a.xzip', 'out')       # 补丁包 -> 目录树
  packcore.xzip_pack('tree', 'new.xzip')      # 目录树 -> 补丁包
  packcore.axp_repack(pkg, {条目下标: 内容}, '新包.axp')
  packcore.axp_add(pkg, {名字: 内容}, '新包.axp')         # 往包里新增条目（哈希/目录/名字表全维护）
  packcore.make_xzip_patch(pkg, 'folder', 'patch.xzip')   # 改过/新增文件 -> 官方格式补丁
"""
import hashlib, json, lzma, math, os, shutil, struct, tempfile, time, zlib
import axpcore
import scriptcodec
try:
    import axpcodex                       # 25 路 AXP 编解码（需要 axp_tables.bin）
except Exception:                         # 表缺失时退化为纯搬运（row.encodable 也都是 False）
    axpcodex = None
try:
    import axp_build                      # 名字表/哈希表/CRC 的权威实现（crc_axp、桶定位、表规则）
except Exception:                         # 缺依赖时名字表自动维护退化为"原样搬运"（并如实计数）
    axp_build = None

_CRC32TAB = []
for _i in range(256):
    _c = _i
    for _ in range(8):
        _c = (0xEDB88320 ^ (_c >> 1)) if (_c & 1) else (_c >> 1)
    _CRC32TAB.append(_c)


def xkey(pos):
    j = ((pos & 0xFF) * 13 + 47) & 0xFF
    return ((_CRC32TAB[j >> 2] >> (8 * (j & 3))) & 0xFF) ^ 0xCE


XKEY = bytes(xkey(p) for p in range(256))
BLOCK = 1 << 20


def xstream(buf, at=0):
    """密钥流异或，对称（解和包用同一个函数）。at = buf 首字节在文件里的绝对偏移。"""
    if not buf:
        return buf
    off = at & 0xFF
    key = (XKEY[off:] + XKEY[:off]) * (-(-len(buf) // 256))
    a = int.from_bytes(buf, 'little') ^ int.from_bytes(key[:len(buf)], 'little')
    return a.to_bytes(len(buf), 'little')


def xzip_entries(path):
    out = []
    size = os.path.getsize(path)
    with open(path, 'rb') as f:
        pos = 0
        while pos + 30 <= size:
            f.seek(pos)
            head = xstream(f.read(30), pos)
            if head[:4] != b'PK\x03\x04':
                break
            _v, _fl, method, _t, _d, crc, csize, usize, nl, el = struct.unpack_from(
                '<HHHHHIIIHH', head, 4)
            f.seek(pos + 30)
            nraw = xstream(f.read(nl), pos + 30)
            extra = b''
            if el:
                f.seek(pos + 30 + nl)
                extra = xstream(f.read(el), pos + 30 + nl)
            out.append(dict(name=nraw.decode('gbk', 'replace'), method=method, crc=crc,
                            csize=csize, usize=usize, offset=pos + 30 + nl + el,
                            nraw=nraw, dost=_t, dosd=_d, ver=_v, flags=_fl, extra=extra))
            pos += 30 + nl + el + csize
    return out


def xzip_read(path, ent, raw=False):
    """读条目内容。

    method=0（存储）：返回 xstream 解码后的字节（= 原文件内容）；
    method=8（deflate，官方补丁实测在用）：按 raw deflate 解压后返回原文件内容
    （zip 规范的 CRC 是对解压后的内容算的）；
    raw=True 时只做 xstream、不做解压（原样重打/搬运用）。
    其他 method 不猜，抛 IOError。"""
    with open(path, 'rb') as f:
        f.seek(ent['offset'])
        n = ent['csize']
        at = ent['offset']
        chunks = []
        while n > 0:
            raw_chunk = f.read(min(n, BLOCK))
            if not raw_chunk:
                raise IOError('补丁包读取不足')
            chunks.append(xstream(raw_chunk, at))
            at += len(raw_chunk)
            n -= len(raw_chunk)
    data = b''.join(chunks)
    m = ent.get('method', 0)
    if m == 0 or raw:
        return data
    if m == 8:
        try:
            return zlib.decompressobj(-15).decompress(data)
        except zlib.error as exc:
            raise IOError('条目 %r deflate 解压失败：%s' % (ent.get('name'), exc))
    raise IOError('条目 %r 的存储方法 %d 未支持（不猜）' % (ent.get('name'), m))


def lzma_unwrap(data):
    """官方补丁条目负载的 LZMA 包裹拆开（lzma_wrap 的逆）。
    实测布局（两个官方样本 0.07.6665 与 0.08.2639 一致，9/9 与 88/88 条都是这个写法）：
      'LZMA' + 28×00 + u32@32(恒 0) + u32@36(声明长度) + 属性字节@40 + u32@41(字典) + raw 流@45。
    官方打包器的老毛病：部分条目实际解开比 @36 声明多 1 字节，多的那个字节恒为 0x00
    （把 C 字符串结尾一起压进去了；0.07 样本 1/9 条、0.08 样本 12/88 条，全部如此）。
    这里不判失败：按实际解开的长度交付，只在告警里写明，免得把能用的内容退回成包裹字节。
    返回 (字节, 是否解开, 告警)。"""
    if len(data) < 45 or data[:4] != LZMA_WRAP_MAGIC:
        return data, False, None
    u36 = struct.unpack_from('<I', data, 36)[0]
    u32 = struct.unpack_from('<I', data, 32)[0]
    expect = u36 or u32
    props = data[40]                       # LZMA1 属性字节：d = (pb*5 + lp)*9 + lc
    lc = props % 9
    t = props // 9
    lp = t % 5
    pb = t // 5
    filt = {'id': lzma.FILTER_LZMA1, 'dict_size': struct.unpack_from('<I', data, 41)[0],
            'lc': lc, 'lp': lp, 'pb': pb}
    dec = lzma.LZMADecompressor(format=lzma.FORMAT_RAW, filters=[filt])
    out = dec.decompress(data[45:])
    note = None
    if expect and len(out) != expect:
        note = 'LZMA 解开 %d 字节，包头声明 %d 字节（按实际长度交付）' % (len(out), expect)
    return out, True, note


def block_to_plain(block):
    """AXP 存储块（96 字节块头 + 正文）解到游戏实际拿到的明文；不是块就原样返回。
    返回 (字节, 形态) —— 形态 ∈ container / block / raw。"""
    if len(block) < axpcodex.HDR_LEN:
        return block, 'raw'
    try:
        ph = axpcodex.decode_header(block[:axpcodex.HDR_LEN])
    except Exception:
        return block, 'raw'
    if ph[:len(axpcodex.MAGIC)] != axpcodex.MAGIC:
        return block, 'raw'
    algo = struct.unpack_from('<I', ph, 16)[0]
    plain = axpcodex.decode_body(algo, 0, block[axpcodex.HDR_LEN:])
    if plain[:8] == scriptcodec.MAGIC:
        cont = scriptcodec.decode_container(plain)
        if cont is not None:
            return cont, 'container'
    return plain, 'block'


def patch_entry_to_file_bytes(data):
    """补丁条目负载（deflate 解出来那点字节）→ 落盘该写的字节。
    返回 (字节, 形态, 告警)：形态 ∈ container / block / lzma / raw。"""
    if data[:4] == LZMA_WRAP_MAGIC and len(data) >= 45:
        block, ok, note = lzma_unwrap(data)
        if ok:
            plain, kind = block_to_plain(block)
            return plain, kind, note
        return block, 'lzma', note
    return block_to_plain(data) + (None,)


def xzip_unpack(path, outdir, progress=None, cancel=None, decode=True):
    """补丁包 → 目录。decode=True（默认）时把每条负载解到底：
    LZMA 包裹 → AXP 存储块 → 算法正文 →（若是脚本容器）Lua 明文，
    解不动/不是块格式的原样落盘并在统计里分类；decode=False 保留旧行为（原样负载字节）。"""
    st = dict(written=0, bytes=0, crc_bad=0, errors=[], cancelled=False, entries=0,
              container=0, block=0, lzma=0, raw=0, notes=[])
    ents = xzip_entries(path)
    st['entries'] = len(ents)
    for i, ent in enumerate(ents):
        if cancel is not None and cancel.is_set():
            st['cancelled'] = True
            break
        if progress:
            progress(i + 1, len(ents), ent['name'])
        rel = axpcore.safe_relpath(ent['name'], i)
        dest = os.path.join(outdir, rel)
        try:
            data = xzip_read(path, ent)
            if ent['crc'] and (zlib.crc32(data) & 0xFFFFFFFF) != ent['crc']:
                st['crc_bad'] += 1
                st['errors'].append('CRC 不符：%s' % ent['name'])
            kind = 'raw'
            if decode:
                try:
                    data, kind, note = patch_entry_to_file_bytes(data)
                    if note:
                        st['notes'].append('%s：%s' % (ent['name'], note))
                except Exception as exc:
                    st['errors'].append('%s：解包内层失败，按原样落盘（%s）' % (ent['name'], exc))
                    kind = 'raw'
            st[kind if kind in st else 'raw'] += 1
            d = os.path.dirname(dest)
            if d:
                os.makedirs(d, exist_ok=True)
            with open(dest, 'wb') as g:
                g.write(data)
            st['written'] += 1
            st['bytes'] += len(data)
        except Exception as exc:
            st['errors'].append('%s：%s' % (ent['name'], exc))
    return st


def _dos_time(tm=None):
    tm = tm or time.localtime()
    return ((tm.tm_hour << 11) | (tm.tm_min << 5) | (tm.tm_sec // 2),
            ((tm.tm_year - 1980) << 9) | (tm.tm_mon << 5) | tm.tm_mday)


def xzip_pack(srcdir, out_path, progress=None, cancel=None, times=None,
              meta=None, order=None, tail=b'', method=8):
    """目录树 -> .xzip。

    method = 新打包条目默认用的存储方法：8=deflate（官方补丁口径）、0=原样存。
      默认 8；压不小就自动退回 0（图片/视频这类已压缩内容不白涨）。
      meta 里给了 method 的条目按 meta 走（原样重打用，不受本参数影响）。
    times = {相对路径('/')：(dos_time, dos_date)}：按原值写这两个字段（原样重打用）。
    meta  = {相对路径('/')：{dost,dosd,method,lver,lmade,lextra}}：逐条原样重打字段 ——
            method=8 时按 raw deflate(zlib level 9，实测与官方补丁逐字节相同)压写、crc/长度按原文件内容算；
            lextra 原样带本地额外字段；lver/lmade 默认 20（官方样本 local=45 / central-made=0）。
            meta 里再给 payload/crc/usize 三项时，正文**原样搬运不再重压缩**（跨版本逐字节还原：
            官方不同批次用的 deflate 参数不完全一致，重压会有几字节出入）。
            meta 里给 ename（条目原名 str）时，包内名字按 ename 写 —— 解包到磁盘上的名字会被
            安全化（斜杠、非法字符），绕文件系统一圈回来名字就变了；要逐字节还原官方包必须显式带原名。
    order = [相对路径('/')...]：按这个顺序写（缺省=目录遍历序；官方补丁顺序 = 保留原包顺序）。
    tail  = EOCD 之后原样追加的字节（官方样本尾部 4 字节 f5fba238；原样重打透传）。
    落盘：逐条流式写 .part（不再把整包堆内存），单条正文仍一次性读入 —— 内存峰值 = 最大单文件。
    """
    files = []
    for root, dirs, fs in os.walk(srcdir):
        dirs.sort()
        for fn in sorted(fs):
            files.append(os.path.join(root, fn))
    eff_meta = {}
    for rel, m in (meta or {}).items():
        eff_meta[rel] = dict(m)
    for rel, (t_, d_) in (times or {}).items():
        eff_meta.setdefault(rel, {}).update(dost=t_, dosd=d_)
    if order:
        by_rel = {os.path.relpath(f, srcdir).replace(os.sep, '/'): f for f in files}
        seq = [by_rel[r] for r in order if r in by_rel]
        seq += [f for f in files if f not in set(seq)]
        files = seq
    total = len(files)
    st = dict(written=0, bytes=0, errors=[], cancelled=False, deflated=0, stored=0, out_bytes=0)
    central = bytearray()
    dost, dosd = _dos_time()

    tmp = out_path + '.part'
    done = False
    try:
        with open(tmp, 'wb') as g:
            state = {'pos': 0}

            def wr(blob):
                at, n = 0, len(blob)
                while at < n:
                    k = min(BLOCK, n - at)
                    g.write(xstream(blob[at:at + k], state['pos'] + at))
                    at += k
                state['pos'] += n

            for i, full in enumerate(files):
                if cancel is not None and cancel.is_set():
                    st['cancelled'] = True
                    break
                if progress:
                    progress(i + 1, total, os.path.relpath(full, srcdir))
                rel = os.path.relpath(full, srcdir).replace(os.sep, '/')
                mm = eff_meta.get(rel) or {}
                dt_ = mm.get('dost', dost)
                dd_ = mm.get('dosd', dosd)
                meth = mm.get('method', method)
                lver = mm.get('lver', 20)
                lmade = mm.get('lmade', 20)
                lextra = mm.get('lextra') or b''
                try:
                    nraw = (mm.get('ename') or rel).encode('gbk')
                except UnicodeEncodeError:
                    nraw = (mm.get('ename') or rel).encode('gbk', 'replace')
                with open(full, 'rb') as f:
                    data = f.read()
                crc = zlib.crc32(data) & 0xFFFFFFFF
                if 'payload' in mm:
                    payload = mm['payload']          # 原样搬运正文（不重压缩，跨版本逐字节还原）
                elif meth == 8:
                    co = zlib.compressobj(9, zlib.DEFLATED, -15)
                    payload = co.compress(data) + co.flush()
                    if len(payload) >= len(data) and 'method' not in mm:
                        meth, payload = 0, data      # 压不小就退回原样存
                elif meth == 0:
                    payload = data
                else:
                    raise IOError('条目 %r 的存储方法 %d 不支持写入（不猜）' % (rel, meth))
                head = struct.pack('<IHHHHHIIIHH', 0x04034b50, lver, 0, meth, dt_, dd_, crc,
                                   len(payload), len(data), len(nraw), len(lextra))
                wr(head)
                wr(nraw)
                if lextra:
                    wr(lextra)
                wr(payload)
                craw = mm.get('cname') or nraw      # 中央目录名（官方新版本这里可能写短名）
                ent_start = state['pos'] - len(head) - len(nraw) - len(lextra) - len(payload)
                central += struct.pack('<IHHHHHHIIIHHHHHII', 0x02014b50, lmade, 20, 0, meth,
                                       dt_, dd_, crc, len(payload), len(data), len(craw),
                                       0, 0, 0, 0, 0, ent_start)
                central += craw
                st['written'] += 1
                st['bytes'] += len(data)
                st['out_bytes'] += len(head) + len(nraw) + len(lextra) + len(payload)
                st['deflated' if meth == 8 else 'stored'] += 1
            if st['cancelled']:
                st['errors'].append('已取消：不产出半成品补丁包')
                return st
            cd_at = state['pos']
            wr(bytes(central))
            wr(struct.pack('<IHHHHIIH', 0x06054b50, 0, 0, st['written'], st['written'],
                           len(central), cd_at, 0))
            if tail:
                wr(tail)
        os.replace(tmp, out_path)
        done = True
    finally:
        if not done and os.path.exists(tmp):
            try:
                os.remove(tmp)
            except OSError:
                pass
    return st


# ---------- .axp 回包 ----------


def entry_index_of(pkg, name):
    want = name.replace('\\', '/').lower()
    for r in pkg.rows():
        if r.display.replace('\\', '/').lower() == want:
            return r.index
    return None


def detect_align(pkg):
    """从原包各块相对数据区起点的偏移推出对齐（真包常见 8），推不出来退回 4。"""
    g = 0
    for o, s, _fl in pkg.entries:
        if s:
            d = o - pkg.data_off
            if d > 0:
                g = math.gcd(g, d)
    for a in (16, 8, 4, 2, 1):
        if g and g % a == 0:
            return a
    return 4


def _regions(pkg):
    """每个条目在原包占用的字节区间长度（含填充）；按原数据区顺序划分。"""
    order = sorted((i for i, (o, s, _f) in enumerate(pkg.entries) if s),
                   key=lambda i: pkg.entries[i][0])
    end = pkg.data_off + (pkg.data_len or 0)
    reg = {}
    for k, i in enumerate(order):
        nxt = pkg.entries[order[k + 1]][0] if k + 1 < len(order) else end
        reg[i] = nxt - pkg.entries[i][0]
    return reg, order


def _codec_row(row):
    """要走编解码器的条目：有块头算法号、算法已转写、且不是脚本容器。
    脚本容器的存储体就是容器原文（不叠算法加密，pkg.decode/encode 对它都是原样），
    与位置无关，所以照旧原样搬运。"""
    return (axpcodex is not None and row is not None and row.encodable
            and not getattr(row, 'script', False))


def _script_row(row):
    """脚本容器条目（Lua 加密包）：edits 给的同样是 Lua 明文，回写要重新封装容器。
    封装 = 照抄原 256 字节容器头 + 正文重新加密，与位置无关，所以只在被编辑时才处理。"""
    return row is not None and getattr(row, 'script', False)


def _edit_blob(src, o, i, row, blob, new_off, data_off):
    """生成一条被编辑条目最终的存储字节，返回 (wbuf, hdr_len)：
    容器条目 = 原 256 字节容器头 + 正文重封装；带块头条目 = 原 96 字节块头 +
    正文按「该块新位置」重编；无块头条目 = 原样。src 停在包文件句柄上。"""
    if _script_row(row):
        src.seek(o)
        head = src.read(scriptcodec.HDR_LEN)
        if len(head) != scriptcodec.HDR_LEN:
            raise IOError('条目 %d 容器头读取不足' % i)
        return scriptcodec.encode_container(blob, head), scriptcodec.HDR_LEN
    if _codec_row(row):
        src.seek(o)
        hdr96 = src.read(axpcodex.HDR_LEN)
        if len(hdr96) != axpcodex.HDR_LEN:
            raise IOError('条目 %d 块头读取不足' % i)
        return (hdr96 + axpcodex.encode_body(
            row.algo, axpcodex.body_pos(new_off, data_off), blob), axpcodex.HDR_LEN)
    return blob, 0


def axp_repack(pkg, edits, out_path, progress=None, cancel=None, grow='append'):
    """流式回包：不把整包读进内存。
    - 头部区（0..data_off）整段照抄，只就地改写目录项与 0x20 的数据区长度；哈希表原样保留。
    - 数据区顺序与原包一致；没改过的块连同原来的填充逐字节搬运。
    - 被编辑的块：新内容（含块头）装得下原来的区间就沿用原区间（后面一块都不挪）。
      装不下时按 grow 选择：
        grow='append'（默认；2026-10-10 实机画面验证通过）：原区间一个字节不动（旧内容成为
          无人引用的死区），新内容整体追加到数据区末尾，只更新它自己的目录项与名字表行；
          其余条目全部原位、连快路径都不破。日志里的 st['appended'] = 走了这条路的条目序号列表。
        grow='shift'（历史行为，仅存档/对照用）：从那块起所有后续块位置平移、密钥相位全变、
          带块头的条目一律重编 —— 实机实测崩客户端（2026-10-10），别再对真机用。
    - 带块头的条目（row.encodable）：正文密钥流下标 = (条目新offset - data_off + 96) & 0x7F，
      条目位置一变、密钥相位全变，密文必须重编。所以除了快路径
      「未编辑 且 新相对pos == 旧相对pos 且 存储长度不变」允许逐字节搬运外，
      一律：先原样拷贝该块自己的 96 字节块头（块头与位置无关，已验证），
      再用 axpcodex.encode_body(算法号, 新相对pos, 明文) 重编正文。
      编辑表 edits 给的是「明文」；没编辑的条目明文 = pkg.decode(row)（原密文先读进内存，
      逐条处理，不全库一次读；正文必须整块一次编 —— 13~18/21/22 号算法只对每次调用的
      前 1024/2048 字节生效，分块会错）。新条目存储长度 = 96 + len(明文)。
    - 无块头的条目（algo is None，含名字表）不依赖位置，照旧原样搬运/整块替换。
    - 名字表：规则已实测（第二列=目录存储长度、第三列=crc_axp(整条磁盘字节)、
      第一行 key=0xFFFFFFFF^XOR(第三列)）。凡是被写侧改过字节或长度的条目，
      收尾时按规则原地更新它那两列并重算 key（%08X 定宽，行长不变）；
      没改过的行一个字节不动。对不到条目的陈旧行只计数，不猜。
    """
    if grow not in ('shift', 'append'):
        raise ValueError("grow 只支持 'shift' 或 'append'：%r" % (grow,))
    st = dict(copied=0, replaced=0, recoded=0, bytes=0, errors=[], cancelled=False,
              list_rewritten=False, list_updated=0, list_unresolved=0,
              list_self_edited=False, size=0, appended=[])
    n = len(pkg.entries)
    align = detect_align(pkg)
    reg, order = _regions(pkg)
    if pkg.data_len and sum(reg.values()) != pkg.data_len:
        st['errors'].append('数据区区间合计 %d 与包头长度 %d 不符' % (sum(reg.values()), pkg.data_len))
    lst = pkg.name_list
    list_index = lst['index'] if lst else -1
    all_edits = dict(edits)
    st['list_untouched'] = True
    rows_by_index = {r.index: r for r in pkg.rows()}

    # 名字表跟踪：把每一行解析出来，行内条目用哈希定位（与游戏同一口径）。
    tab = None
    if lst and axp_build is not None:
        if list_index in all_edits:
            st['list_self_edited'] = True     # 该条目自身被编辑：不自动维护，交给 verify 报
        else:
            lo_, lsz_, _ = pkg.entries[list_index]
            with open(pkg.path, 'rb') as f:
                f.seek(lo_)
                ltxt = f.read(lsz_)
            trows = []
            pos = 0
            for j, ln in enumerate(ltxt.split(b'\n')):
                if j >= 2 and ln:
                    p1 = ln.find(b'|')
                    p2 = ln.find(b'|', p1 + 1)
                    if p1 > 0 and p2 == p1 + 9 and len(ln) == p2 + 9:
                        trows.append(dict(name=ln[:p1], col2_at=pos + p1 + 1,
                                          col3_at=pos + p2 + 1,
                                          c2=ln[p1 + 1:p2], c3=ln[p2 + 1:]))
                pos += len(ln) + 1
            row_by_entry = {}
            try:
                buckets = axp_build.read_buckets(pkg.path)
                for k, rw in enumerate(trows):
                    z, _b, _sp = axp_build.lookup(buckets, rw['name'])
                    if z is not None and z not in row_by_entry:
                        row_by_entry[z] = k
            except Exception:
                row_by_entry = {}
            tab = dict(text=ltxt, rows=trows, row_by_entry=row_by_entry, lsz=lsz_)
    upd_c2 = {}
    upd_c3 = {}

    lens = {}
    space = {}
    appended = []                      # grow='append'：装不下原区间、改到数据区末尾的条目
    for i in range(n):
        o, s, _fl = pkg.entries[i]
        row = rows_by_index.get(i)
        if i in all_edits:
            if _script_row(row):
                # 容器条目：edits 给 Lua 明文，重新封装容器（头部照抄，正文任意长度）——
                # 容器头 @252 的校验值只覆盖头前 252 字节，与正文长度无关（实测同头不同长共用同值），
                # 所以变长合法；新存储长度 = 256 容器头 + 新正文。
                scriptcodec.verify_container_editable(
                    row.content_len - scriptcodec.HDR_LEN, len(all_edits[i]))
                lens[i] = scriptcodec.HDR_LEN + len(all_edits[i])
            else:
                hdr = axpcodex.HDR_LEN if _codec_row(row) else 0
                lens[i] = hdr + len(all_edits[i])
            old_reg = reg.get(i)
            if old_reg is not None and lens[i] <= old_reg:
                # 新内容（含块头）装得下原来的区间（含原来的填充）就沿用原区间：
                # 后面的块一个都不挪，快路径全部保留，回包对原包的扰动最小。
                space[i] = old_reg
            elif grow == 'append':
                # 搬家模式：原区间字节原样留存（无人引用的死区），新内容整体追加到
                # 数据区末尾，只更新它自己的目录项与名字表行 —— 其他条目零扰动。
                space[i] = old_reg or 0
                appended.append(i)
            else:
                space[i] = (lens[i] + align - 1) & ~(align - 1)
        elif s:
            lens[i] = s
            space[i] = reg.get(i, s)
        else:
            lens[i] = s
            space[i] = 0
    newoff = {}
    cur = pkg.data_off
    for i in order:
        newoff[i] = cur
        cur += space[i]
    for i in appended:
        newoff[i] = cur
        cur += (lens[i] + align - 1) & ~(align - 1)
    appended_set = set(appended)
    for i in range(n):
        if i not in newoff:
            newoff[i] = cur
    if lst:
        # 名字表条目自己也要占位（它可能因为长度数字变长而变大）
        if (list_index in all_edits and list_index not in reg
                and list_index not in appended_set):
            newoff[list_index] = cur

    with open(pkg.path, 'rb') as f:
        f.seek(0)
        tmpl = bytearray(f.read(pkg.data_off))
    if len(tmpl) != pkg.data_off:
        raise IOError('头部区读取不足：%d/%d' % (len(tmpl), pkg.data_off))
    for i in range(n):
        struct.pack_into('<3I', tmpl, pkg.dir_off + i * 12, newoff[i], lens[i], pkg.entries[i][2])
    struct.pack_into('<IIII', tmpl, 0x10, pkg.dir_off, n,
                     struct.unpack_from('<I', tmpl, 0x18)[0], pkg.data_off)
    struct.pack_into('<I', tmpl, 0x20, cur - pkg.data_off)

    tmp = out_path + '.part'
    done = False
    try:
        with open(tmp, 'w+b') as g, open(pkg.path, 'rb') as src:
            g.write(bytes(tmpl))
            if g.tell() != pkg.data_off:
                raise IOError('头部区域长度对不上：%d != %d' % (g.tell(), pkg.data_off))
            for i in order:
                if cancel is not None and cancel.is_set():
                    st['cancelled'] = True
                    return st
                o, s, _fl = pkg.entries[i]
                row = rows_by_index.get(i)
                if i in all_edits:
                    if i in appended_set:
                        # 搬家模式：该条目的新内容稍后在数据区末尾统一追加；
                        # 原区间字节照旧搬运，成为无人引用的死区（保持数据区连续推进）。
                        left = space[i]
                        src.seek(o)
                        while left > 0:
                            chunk = src.read(min(left, BLOCK))
                            if not chunk:
                                raise IOError('条目 %d 死区搬运读取不足：还差 %d 字节' % (i, left))
                            g.write(chunk)
                            left -= len(chunk)
                        st['copied'] += 1
                    else:
                        wbuf, hdr_len = _edit_blob(src, o, i, row, all_edits[i],
                                                   newoff[i], pkg.data_off)
                        g.write(wbuf)
                        if tab is not None:
                            upd_c2[i] = len(wbuf)
                            upd_c3[i] = axp_build.crc_axp(wbuf)
                        st['recoded' if hdr_len else 'replaced'] += 1
                        pad = space[i] - hdr_len - len(all_edits[i])
                        if pad:
                            g.write(b'\0' * pad)
                else:
                    # 快路径三条件：带块头可解码 + 没编辑 + 新相对pos == 旧相对pos + 存储长度不变。
                    # 三者都成立密文才与原包逐字节相同，才允许原样搬运；
                    # 无块头条目（_codec_row 为假）不依赖位置，永远原样搬运。
                    fast = not _codec_row(row)
                    if not fast:
                        fast = (axpcodex.body_pos(o, pkg.data_off)
                                == axpcodex.body_pos(newoff[i], pkg.data_off)) and lens[i] == s
                    if fast:
                        left = space[i]
                        src.seek(o)
                        while left > 0:
                            chunk = src.read(min(left, BLOCK))
                            if not chunk:
                                raise IOError('条目 %d 搬运读取不足：还差 %d 字节' % (i, left))
                            g.write(chunk)
                            left -= len(chunk)
                        st['copied'] += 1
                    else:
                        # 位置变了：明文不变、密文必变 —— 解出明文再按新位置重编
                        # （encode_body 只出正文，块头与位置无关，原样抄 96 字节 —— 与上面的编辑分支一致）
                        src.seek(o + axpcodex.HDR_LEN)
                        raw = src.read(row.content_len)
                        plain = pkg.decode(row, raw)
                        del raw
                        src.seek(o)
                        hdr96 = src.read(axpcodex.HDR_LEN)
                        if len(hdr96) != axpcodex.HDR_LEN:
                            raise IOError('条目 %d 块头读取不足' % i)
                        wbuf = hdr96 + axpcodex.encode_body(
                            row.algo, axpcodex.body_pos(newoff[i], pkg.data_off), plain)
                        del plain
                        g.write(wbuf)
                        if tab is not None:
                            upd_c2[i] = len(wbuf)
                            upd_c3[i] = axp_build.crc_axp(wbuf)
                        pad = space[i] - s
                        if pad:
                            g.write(b'\0' * pad)
                        st['recoded'] += 1
                st['bytes'] += lens[i]
                if progress and i % 32 == 0:
                    progress(st['copied'] + st['replaced'] + st['recoded'], len(order), '条目 %d' % i)
            data_end_expect = (pkg.data_off + (pkg.data_len or 0)) if appended else cur
            if g.tell() != data_end_expect:
                raise IOError('落盘位置与目录不符：%d != %d' % (g.tell(), data_end_expect))
            for i in appended:
                if cancel is not None and cancel.is_set():
                    st['cancelled'] = True
                    return st
                if progress:
                    progress(st['copied'] + st['replaced'] + st['recoded'], len(order),
                             '追加条目 %d' % i)
                row = rows_by_index.get(i)
                wbuf, hdr_len = _edit_blob(src, pkg.entries[i][0], i, row,
                                           all_edits[i], newoff[i], pkg.data_off)
                g.write(wbuf)
                if tab is not None:
                    upd_c2[i] = len(wbuf)
                    upd_c3[i] = axp_build.crc_axp(wbuf)
                st['recoded' if hdr_len else 'replaced'] += 1
                pad = ((lens[i] + align - 1) & ~(align - 1)) - len(wbuf)
                if pad:
                    g.write(b'\0' * pad)
            tail = pkg.size - (pkg.data_off + (pkg.data_len or 0))
            if tail > 0:
                src.seek(pkg.data_off + pkg.data_len)
                left = tail
                while left > 0:
                    chunk = src.read(min(left, BLOCK))
                    if not chunk:
                        break
                    g.write(chunk)
                    left -= len(chunk)
            if tab is not None and upd_c3:
                text2, n_upd, n_unres = _merge_table(tab, upd_c2, upd_c3)
                st['list_updated'] = n_upd
                st['list_unresolved'] = n_unres
                if text2 != tab['text']:
                    if len(text2) != tab['lsz']:
                        raise IOError('名字表自动更新改变行长（%d != %d），模式 A 不支持'
                                      % (len(text2), tab['lsz']))
                    g.seek(newoff.get(list_index, cur))
                    g.write(text2)
                    st['list_rewritten'] = True
                    st['list_untouched'] = False
            g.flush()
        os.replace(tmp, out_path)
        done = True
        st['size'] = cur
        st['appended'] = list(appended)
    finally:
        if not done and os.path.exists(tmp):
            try:
                os.remove(tmp)
            except OSError:
                pass
    return st


def _merge_table(tab, upd_c2, upd_c3):
    """按实测规则更新名字表文本：行 = `名字|%08X(存储长度)|%08X(crc_axp(整条磁盘字节))`，
    第一行 key = 0xFFFFFFFF ^ XOR(全部第三列)。只改能被哈希定位到条目的行；
    定宽八位十六进制 ⇒ 行长不变。对不到条目的行原样保留（只计数）。
    返回 (新文本, 实际改动字段数, 对不到条目的条目数)。"""
    text = bytearray(tab['text'])
    c3_final = {}
    n_upd = 0
    unresolved = 0
    for i, crc in upd_c3.items():
        k = tab['row_by_entry'].get(i)
        if k is None:
            unresolved += 1
            continue
        rw = tab['rows'][k]
        nb2 = b'%08X' % (upd_c2[i] & 0xFFFFFFFF)
        nb3 = b'%08X' % (crc & 0xFFFFFFFF)
        if len(nb2) != 8 or len(nb3) != 8:
            raise IOError('名字表字段放不进 8 位十六进制：len=%d crc=%08X'
                          % (upd_c2[i], crc))
        if bytes(text[rw['col2_at']:rw['col2_at'] + 8]) != nb2:
            text[rw['col2_at']:rw['col2_at'] + 8] = nb2
            n_upd += 1
        if bytes(text[rw['col3_at']:rw['col3_at'] + 8]) != nb3:
            text[rw['col3_at']:rw['col3_at'] + 8] = nb3
            n_upd += 1
        c3_final[k] = crc
    key = 0xFFFFFFFF
    for k, rw in enumerate(tab['rows']):
        c3 = c3_final.get(k)
        if c3 is None:
            try:
                c3 = int(rw['c3'], 16)
            except ValueError:
                raise IOError('名字表第 %d 行第三列不是十六进制：%r' % (k + 3, rw['c3']))
        key ^= c3
    nb = b'%08X' % (key & 0xFFFFFFFF)
    if bytes(text[:8]) != nb:
        text[:8] = nb
        n_upd += 1
    return bytes(text), n_upd, unresolved


def axp_verify_repack(pkg, out_path, edits, list_index=None, deep=True, appended=None):
    """回包后自检：头部区除目录项外要逐字节一致；条目数/标志不变；改过的块解出的明文 == 编辑内容；
    其余块与原包一致 —— 无块头的逐字节比对；带块头的块走硬校验：
    块头必须原样拷贝，正文用 axpcodex.decode_body(算法, 该块新相对pos, 输出正文) 解出的明文
    必须等于期望明文（编辑过的 = 编辑内容；没编辑的 = 原包 decode 结果）——
    位置变过的块密文必然不同，逐字节比对会误报，所以按「各自位置的明文」比。
    数据区长度字段与实际落盘一致；对齐保持。
    appended 传 grow='append' 回包的 st['appended'] 时按搬家模式校验：
    未编辑条目必须原地（offset 不变），追加块必须越过旧数据区末尾。
    deep=False 时大块只抽样（无块头的比首尾各 4KB；带块头的解前 4KB，前缀解码与整块解码一致）。"""
    import axpcore
    bad = []
    appended_set = set(appended) if appended else None
    new = axpcore.Package(out_path)
    if len(new.entries) != len(pkg.entries):
        return ['条目数变了：%d -> %d' % (len(pkg.entries), len(new.entries))]
    rows_by_index = {r.index: r for r in pkg.rows()}
    lst_idx = list_index if list_index is not None else (
        pkg.name_list['index'] if pkg.name_list else -1)
    if lst_idx is None:
        lst_idx = -1
    with open(pkg.path, 'rb') as fa, open(out_path, 'rb') as fb:
        ha, hb = _head(fa), _head(fb)
        for off in (0x10, 0x14, 0x18, 0x1C):
            va, vb = struct.unpack_from('<I', ha, off)[0], struct.unpack_from('<I', hb, off)[0]
            if va != vb:
                bad.append('头字段 %02X 变了：%08x -> %08x' % (off, va, vb))
        if ha[:4] != hb[:4]:
            bad.append('包魔数变了：%s -> %s' % (ha[:4], hb[:4]))
        hla, hlb = _slice(fa, 0x28, pkg.dir_off), _slice(fb, 0x28, new.dir_off)
        if hla != hlb or len(hla) != pkg.dir_off - 0x28:
            bad.append('哈希表区（0x28..%08x）字节变了' % pkg.dir_off)
        for i in range(len(pkg.entries)):
            if _ent(fa, pkg.dir_off, i)[2] != _ent(fb, new.dir_off, i)[2]:
                bad.append('条目%d 标志变了 %08x->%08x' % (
                    i, _ent(fa, pkg.dir_off, i)[2], _ent(fb, new.dir_off, i)[2]))
        skip = set(edits)
        reg, order = _regions(pkg)
        nreg, norder = _regions(new)
        al = detect_align(new)
        H = axpcodex.HDR_LEN if axpcodex is not None else 96
        for i in order:
            o, s, fl = pkg.entries[i]
            no, ns, nfl = new.entries[i]
            row = rows_by_index.get(i)
            if i in skip:
                if appended_set and i in appended_set and no < pkg.data_off + (pkg.data_len or 0):
                    bad.append('条目%d 追加块位置 %d 没越过旧数据区末尾' % (i, no))
                if i in edits:
                    if _script_row(row):
                        # 编辑的容器块：容器头应原样，解出的 Lua 明文必须等于编辑内容
                        fa.seek(o)
                        head_old = fa.read(scriptcodec.HDR_LEN)
                        fb.seek(no)
                        stored = fb.read(ns)
                        if stored[:scriptcodec.HDR_LEN] != head_old:
                            bad.append('条目%d 容器头没原样拷贝' % i)
                        got = scriptcodec.decode_container(stored)
                        if got != edits[i]:
                            bad.append('条目%d 容器解出的明文与编辑内容对不上' % i)
                    elif _codec_row(row):
                        # 编辑表给的是明文：块头应原样，正文按「新包里该块自己的位置」解出必须等于编辑内容
                        fa.seek(o)
                        hdr_old = fa.read(H)
                        fb.seek(no)
                        stored = fb.read(ns)
                        if stored[:H] != hdr_old:
                            bad.append('条目%d 块头没原样拷贝' % i)
                        try:
                            got = axpcodex.decode_body(
                                row.algo, axpcodex.body_pos(no, new.data_off), stored[H:])
                        except Exception as exc:
                            bad.append('条目%d 新内容解码失败：%s' % (i, str(exc)[:60]))
                            got = None
                        if got != edits[i]:
                            bad.append('条目%d 新内容（按新位置解码）对不上' % i)
                    else:
                        fb.seek(no)
                        if fb.read(ns) != edits[i]:
                            bad.append('条目%d 新内容对不上' % i)
                continue
            if i == lst_idx:
                # 名字表条目：写侧按规则自动维护它的内容（允许变），逐字节比对不适用；
                # 它的长度必须不变（模式 A 不允许增删行），一致性在文件尾统一硬核。
                if s != ns:
                    bad.append('名字表条目长度变了 %d -> %d' % (s, ns))
                continue
            if s != ns:
                bad.append('条目%d 长度变了 %d -> %d' % (i, s, ns))
                continue
            if s and (no - new.data_off) % al:
                bad.append('条目%d 偏移 %d 不再 %d 对齐' % (i, no, al))
            if appended_set is not None:
                if no != o:
                    bad.append('条目%d 位置被挪 %d -> %d（append 模式下未编辑条目应原地）' % (i, o, no))
            elif reg.get(i) != nreg.get(i):
                bad.append('条目%d 占用区间变了 %d -> %d' % (i, reg.get(i), nreg.get(i)))
            if not s:
                continue
            if _codec_row(row):
                # 硬校验：输出正文按块自己的（新）相对位置解出的明文，必须等于原包 decode 结果。
                # 块头与位置无关，仍须逐字节一致。位置没变且正文逐字节一致的快路径块，
                # 字节相等已蕴含解码相等，不必再解一遍。
                fa.seek(o)
                old_stored = fa.read(s)
                fb.seek(no)
                new_stored = fb.read(ns)
                if old_stored[:H] != new_stored[:H]:
                    bad.append('条目%d 块头没原样拷贝' % i)
                old_pos = axpcodex.body_pos(o, pkg.data_off)
                new_pos = axpcodex.body_pos(no, new.data_off)
                if new_pos == old_pos and old_stored[H:] == new_stored[H:]:
                    continue
                cap = None if deep else 4096
                ob = old_stored[H:]
                nb = new_stored[H:]
                if cap is not None:
                    ob, nb = ob[:cap], nb[:cap]
                try:
                    expect = axpcodex.decode_body(row.algo, old_pos, ob)
                    got = axpcodex.decode_body(row.algo, new_pos, nb)
                except Exception as exc:
                    bad.append('条目%d 解码失败：%s' % (i, str(exc)[:60]))
                    continue
                if got != expect:
                    bad.append('条目%d 重编码后按新位置解码 != 原包明文（pos %d->%d）'
                               % (i, old_pos, new_pos))
                continue
            if deep:
                fa.seek(o)
                fb.seek(no)
                if fa.read(s) != fb.read(ns):
                    bad.append('条目%d 原块搬运不符' % i)
            else:
                fa.seek(o)
                fb.seek(no)
                head = fa.read(min(s, 4096)), fb.read(min(s, 4096))
                fa.seek(o + s - min(s, 4096))
                fb.seek(no + s - min(s, 4096))
                tail = fa.read(min(s, 4096)), fb.read(min(s, 4096))
                if head[0] != head[1] or tail[0] != tail[1]:
                    bad.append('条目%d 原块搬运不符（抽样首尾）' % i)
        tail_orig = max(0, pkg.size - (pkg.data_off + (getattr(pkg, 'data_len', 0) or 0)))
        real = os.path.getsize(out_path) - new.data_off - tail_orig
        dl = struct.unpack_from('<I', _head(fb), 0x20)[0]
        if dl != real:
            bad.append('数据区长度字段 %d 与实际 %d 不符' % (dl, real))
        # 名字表一致性硬核（只对真实游戏布局的包）：第二列 == 目录存储长度（全行）；
        # 第一行 key == 0xFFFFFFFF^XOR(第三列)；deep 时逐行重算第三列 == crc_axp(整条磁盘字节)。
        # 对不到条目的陈旧行只计数不判错。合成小夹具（紧凑布局/占位表值）不在本契约内，跳过。
        std_layout = (new.dir_off == axp_build.DIR_OFF and new.data_off == axp_build.DATA_OFF)
        if lst_idx >= 0 and axp_build is not None and std_layout:
            try:
                lb = axp_build.read_buckets(out_path)
                o_l, s_l, _fl = new.entries[lst_idx]
                fb.seek(o_l)
                lt = fb.read(s_l)
                lt_lines = lt.split(b'\n')
                nrows = int(lt_lines[1])
                trows = []
                for j, ln in enumerate(lt_lines):
                    if j >= 2 and ln:
                        p1 = ln.find(b'|')
                        p2 = ln.find(b'|', p1 + 1)
                        if p1 > 0 and p2 == p1 + 9 and len(ln) == p2 + 9:
                            trows.append((ln[:p1], ln[p1 + 1:p2], ln[p2 + 1:]))
                if nrows != len(trows):
                    bad.append('名字表行数不符：声明 %d 实际 %d' % (nrows, len(trows)))
                key = int(lt_lines[0], 16)
                x = 0xFFFFFFFF
                c2_bad = c3_bad = 0
                for nm, c2f, c3f in trows:
                    z, _b, _sp = axp_build.lookup(lb, nm)
                    if z is None:
                        x ^= int(c3f, 16)
                        continue          # 陈旧行（源包本就可能有），只参与 key
                    oo, ss, _ff = new.entries[z]
                    if int(c2f, 16) != ss:
                        c2_bad += 1
                    if deep:
                        fb.seek(oo)
                        if axp_build.crc_axp(fb.read(ss)) != int(c3f, 16):
                            c3_bad += 1
                    x ^= int(c3f, 16)
                if (x & 0xFFFFFFFF) != key:
                    bad.append('名字表第一行 key 与各第三列不符')
                if c2_bad:
                    bad.append('名字表第二列有 %d 行 != 目录存储长度' % c2_bad)
                if c3_bad:
                    bad.append('名字表第三列有 %d 行 != crc_axp(整条磁盘字节)' % c3_bad)
            except Exception as exc:
                bad.append('名字表自检异常：%s' % str(exc)[:80])
    return bad


def _head(f):
    f.seek(0)
    return f.read(0x28)


def _slice(f, a, b):
    if b <= a:
        return b''
    f.seek(a)
    return f.read(b - a)


def _ent(f, dir_off, i):
    f.seek(dir_off + i * 12)
    return struct.unpack('<3I', f.read(12))


# ---------- .axp 新增条目（axp_add） ----------
# 规则全部来自 23 个真包实测，证据汇总在 _tmp_add/加条目_实现报告.md：
#   * 哈希表槽位：home = hash(lower(name), 3) & 0x7FFF，线性探测 (i+1)&0x7FFF；
#     空槽判据 = 整个 12 字节全零（全库 644,653 个空槽 100% 如此）；
#     删除留下的 tombstone = z 非零但 0x80000000 顶位被清掉（全库 24 个），插新记录时按"已占"跳过。
#   * 新记录第三字 = 目录序号 | 0x80000000（全库 108,987 条在用记录 100% 这个形态）。
#   * 目录 flag = 0x80000000（在用）或 0（空洞/残留，计入 0x24 free）。
#   * 新条目写 RAW 形态（无 96 字节块头）——全库 58,000+ 条被哈希引用的 RAW 条目（.dds/.s3d/.lua 等真实资源）同型。
#   * 名字表行 = `名字|%08X(存储长度)|%08X(crc_axp(整条磁盘字节))`，首行 key = 0xFFFFFFFF ^ XOR(全部第三列)。


def axp_add(pkg, additions, out_path, progress=None, cancel=None):
    """往 .axp 包里新增条目（包里原本没有的文件名），游戏按哈希表定位即可找到。

    additions = {名字(str，GBK 可编码，可含 '/' 与中文)：bytes/bytearray（文件内容，非空）}
    做法（最小扰动，已存在条目的字节一个都不动）：
      * 目录末尾追加 k 行（新 z = n_old..n_old+k-1，按小写名字升序；flag=0x80000000）；
        0x14 = n+k，0x20 = 新数据区长度；0x10/0x18/0x1C/0x24 不变。
      * 数据区：新块从旧数据区末尾起按 256 对齐追加（全库 23 包条目偏移全是 256 的倍数、
        free 也按 256 计）；不动别人的字节 ⇒ 位置相关的密文块无需重编。
      * 名字表：新行按小写名字升序插入，第二列 = 实写长度、第三列 = crc_axp(实写字节)，
        首行 key 重算；原行字节原样（对应条目没变）。新文本装得下原区间原位写，
        装不下整条挪到数据区末尾并更新它自己的目录项（旧区间成未被引用的空洞，free 不动）。
      * 哈希表：home 起线性探测到第一个全零槽写入 (h1, h2, z|0x80000000)；已占槽（含 tombstone）不改。
    产物先写 out_path+'.part' 再改名；取消/异常不留半成品。返回统计 dict。
    """
    if axp_build is None:
        raise IOError('新增条目需要 axp_build（哈希表/名字表/CRC 权威实现），当前环境缺依赖')
    st = dict(out=out_path, added=0, names=[], count_before=0, count_after=0,
              data_len_before=0, data_len_after=0, bytes_added=0,
              list_index=-1, list_rows_before=0, list_rows_after=0,
              list_off_before=0, list_off_after=0, list_fits=True, list_moved=False,
              list_rewritten=False, new_offsets={}, hash_slots={}, hash_steps_max=0,
              size=0, cancelled=False, errors=[])
    if cancel is not None and cancel.is_set():
        st['cancelled'] = True
        return st
    # ---- 1. 校验 additions ----
    if not additions:
        raise ValueError('additions 为空：没有要新增的文件')
    items = []
    seen = set()
    for name, data in additions.items():
        if isinstance(name, bytes):
            raw = name
        else:
            try:
                raw = str(name).encode('gbk')
            except UnicodeEncodeError as exc:
                raise ValueError('名字无法 GBK 编码：%r（%s）' % (name, exc))
        if not raw:
            raise ValueError('空名字')
        for bad in (b'|', b'\n', b'\r', b'\x00'):
            if bad in raw:
                raise ValueError('名字含非法字符 %r：%r' % (bad, name))
        if not isinstance(data, (bytes, bytearray, memoryview)):
            raise ValueError('内容必须是 bytes：%r' % (name,))
        blob = bytes(data)
        if not blob:
            raise ValueError('条目内容为空：%r —— 全库 23 包目录里没有 s==0 的条目，空文件不写' % (name,))
        if len(blob) > 0xFFFFFFFF:
            raise ValueError('内容超过 u32：%r' % (name,))
        lo = raw.lower()
        if lo in seen:
            raise ValueError('新增列表里名字重复（忽略大小写）：%r' % (name,))
        seen.add(lo)
        items.append([raw, lo, blob, 0, 0, None])          # name, lower, blob, z, off, slot
    # 排序规则与官方一致（Material8 修补后的 117 条新条目、以及全库重建口径都是小写名字升序）
    items.sort(key=lambda it: it[1])
    # ---- 2. 读现包结构 ----
    n_old = len(pkg.entries)
    if n_old + len(items) > axp_build.MAX_ENTRIES:
        raise ValueError('条目数 %d 超过目录区容量 %d' % (n_old + len(items), axp_build.MAX_ENTRIES))
    d = axp_build.read_dir(pkg.path)
    buckets = axp_build.read_buckets(pkg.path)
    if d['count'] != n_old or d['dir_off'] != pkg.dir_off or d['data_off'] != pkg.data_off:
        raise IOError('包头与 Package 解析对不上（n %d/%d，dir_off %08X/%08X，data_off %08X/%08X）'
                      % (d['count'], n_old, d['dir_off'], pkg.dir_off, d['data_off'], pkg.data_off))
    tail = pkg.size - (pkg.data_off + d['data_len'])
    if tail < 0:
        raise IOError('文件长度 %d < 数据区末尾 %d' % (pkg.size, pkg.data_off + d['data_len']))
    lst = pkg.name_list
    if lst is None:
        raise NotImplementedError('包里没有可解析的名字表，axp_add 不知道往哪追加行（不猜）')
    list_index = lst['index']
    o_l, s_l, fl_l = pkg.entries[list_index]
    with open(pkg.path, 'rb') as f:
        f.seek(o_l)
        ltxt = f.read(s_l)
    # 名字表重建前置校验：解析出的行原样拼回去必须逐字节等于原文（否则格式没吃透，不猜）
    lines = ltxt.split(b'\n')
    if len(lines) < 3 or not lines[1].isdigit():
        raise NotImplementedError('名字表头两行不是 %08X/%%d 形态，先别插行')
    ex_rows = []                                          # (name_raw, c2_bytes, c3_bytes)
    for ln in lines[2:]:
        if not ln:
            continue
        p1 = ln.find(b'|')
        p2 = ln.find(b'|', p1 + 1)
        if p1 <= 0 or p2 != p1 + 9 or len(ln) != p2 + 9:
            raise NotImplementedError('名字表行不是 名字|8HEX|8HEX：%r' % ln[:80])
        try:
            int(ln[p1 + 1:p2], 16)
            int(ln[p2 + 1:], 16)
        except ValueError:
            raise NotImplementedError('名字表行含非十六进制列：%r' % ln[:80])
        ex_rows.append((ln[:p1], ln[p1 + 1:p2], ln[p2 + 1:]))
    rebuilt = lines[0] + b'\n' + lines[1] + b'\n' + b''.join(ln + b'\n' for ln in lines[2:] if ln)
    if rebuilt != ltxt or int(lines[1]) != len(ex_rows):
        raise NotImplementedError('名字表重建 != 原文（%d != %d 或字节不符），先别插行'
                                  % (int(lines[1]), len(ex_rows)))
    # 新名字查重：哈希表 + 全部名字表的行（含陈旧行）
    ex_lowers = set()
    for l2 in pkg.lists:
        for r2 in l2['rows']:
            ex_lowers.add(bytes(r2[0]).lower())
    # 原 key 必须符合实测规则（0xFFFFFFFF ^ XOR(第三列)），不符合就不动这个包
    xor_old = 0xFFFFFFFF
    for nmx, c2b, c3b in ex_rows:
        xor_old ^= int(c3b, 16)
    if int(lines[0], 16) != (xor_old & 0xFFFFFFFF):
        raise NotImplementedError('名字表首行 key 与各行第三列不符（key=%s），先别插行'
                                  % lines[0].decode('ascii', 'replace'))
    for it in items:
        if axp_build.lookup(buckets, it[0])[0] is not None:
            raise ValueError('名字已存在（哈希表命中）：%r' % it[0].decode('gbk', 'replace'))
        if it[1] in ex_lowers:
            raise ValueError('名字已存在（名字表行命中）：%r' % it[0].decode('gbk', 'replace'))
    # ---- 3. 新名字表文本 ----
    keyv = xor_old
    newrows = []
    for k, it in enumerate(items):
        it[3] = n_old + k                                  # 新目录序号
        c2 = len(it[2])
        c3 = axp_build.crc_axp(it[2])
        keyv ^= c3
        newrows.append((it[1], len(ex_rows) + 999999 + k,
                        b'%s|%08X|%08X' % (it[0], c2, c3)))
    merged = [(nm.lower(), i, nm + b'|' + c2 + b'|' + c3)
              for i, (nm, c2, c3) in enumerate(ex_rows)]
    merged += newrows
    merged.sort(key=lambda r: (r[0], r[1]))
    ltext2 = b''.join(ln + b'\n' for _lo, _i, ln in merged)
    ltext2 = b'%08X\n%d\n' % (keyv & 0xFFFFFFFF, len(merged)) + ltext2
    st['list_rows_before'] = len(ex_rows)
    st['list_rows_after'] = len(merged)
    # ---- 4. 布局 ----
    reg, order = _regions(pkg)
    list_region = reg.get(list_index, s_l)
    align = axp_build.ALIGN
    old_data_end = pkg.data_off + d['data_len']
    st['list_index'] = list_index
    st['list_off_before'] = o_l
    cur = pkg.data_off + ((d['data_len'] + align - 1) // align) * align
    list_off_new = o_l
    if len(ltext2) > list_region:
        # 整条挪到数据区末尾（旧区间成为未被引用的空洞；free@0x24 只统计 flag=0 条目，不动）
        st['list_fits'] = False
        st['list_moved'] = True
        list_off_new = cur
        cur += (len(ltext2) + align - 1) // align * align
    st['list_off_after'] = list_off_new
    for it in items:
        it[4] = cur
        off = cur
        cur = off + (len(it[2]) + align - 1) // align * align
        st['new_offsets'][it[0].decode('gbk', 'replace')] = off
        st['bytes_added'] += len(it[2])
    new_data_len = cur - pkg.data_off
    # ---- 5. 头部区（含哈希表/目录）就地修改副本 ----
    with open(pkg.path, 'rb') as f:
        f.seek(0)
        hdr = bytearray(f.read(pkg.data_off))
    if len(hdr) != pkg.data_off:
        raise IOError('头部区读取不足：%d/%d' % (len(hdr), pkg.data_off))
    struct.pack_into('<I', hdr, 0x14, n_old + len(items))
    struct.pack_into('<I', hdr, 0x20, new_data_len & 0xFFFFFFFF)
    if st['list_moved']:
        struct.pack_into('<3I', hdr, pkg.dir_off + list_index * 12,
                         list_off_new, len(ltext2), fl_l)
    else:
        # 原位：文本变长，size 必须跟着走（RAW 条目的 size=文本长度）
        struct.pack_into('<I', hdr, pkg.dir_off + list_index * 12 + 4, len(ltext2))
    for it in items:
        struct.pack_into('<3I', hdr, pkg.dir_off + it[3] * 12,
                         it[4], len(it[2]), 0x80000000)
    for it in items:
        lo = it[1]
        p1 = axp_build.name_hash(lo, 1)
        p2 = axp_build.name_hash(lo, 2)
        i = axp_build.name_hash(lo, 3) & 0x7FFF
        steps = 0
        while True:
            z = struct.unpack_from('<I', hdr, 0x28 + i * 12 + 8)[0]
            if z == 0:                                   # 空槽 = 12 字节全零；tombstone(z!=0) 视为已占
                struct.pack_into('<3I', hdr, 0x28 + i * 12, p1, p2, it[3] | 0x80000000)
                it[5] = i
                st['hash_slots'][it[0].decode('gbk', 'replace')] = i
                break
            i = (i + 1) & 0x7FFF
            steps += 1
            if steps >= 32768:
                raise IOError('哈希表装不下（全部槽已占）')
        st['hash_steps_max'] = max(st['hash_steps_max'], steps)
        it[5] = i
    st['count_before'] = n_old
    st['count_after'] = n_old + len(items)
    st['data_len_before'] = d['data_len']
    st['data_len_after'] = new_data_len
    # ---- 6. 落盘 ----
    tmp = out_path + '.part'
    done = False
    try:
        dd = os.path.dirname(out_path)
        if dd:
            os.makedirs(dd, exist_ok=True)
        total = len(order) + len(items) + 1
        with open(tmp, 'w+b') as g, open(pkg.path, 'rb') as src:
            g.write(bytes(hdr))
            if g.tell() != pkg.data_off:
                raise IOError('头部区落盘长度对不上：%d != %d' % (g.tell(), pkg.data_off))
            pos = pkg.data_off
            for k, i in enumerate(order):
                if cancel is not None and cancel.is_set():
                    st['cancelled'] = True
                    return st
                if progress:
                    progress(k + 1, total, '条目 %d' % i)
                o, s, _fl = pkg.entries[i]
                if o > pos:
                    # 数据区里的未被引用空洞（"搬家式"增长留下的旧区间、或包自带的对齐空档）：
                    # 原样搬运，不猜内容 —— 否则第一个条目被搬走就会让新增条目无法落包。
                    left = o - pos
                    src.seek(pos)
                    while left > 0:
                        chunk = src.read(min(left, BLOCK))
                        if not chunk:
                            raise IOError('空洞搬运读取不足：游标 %d 还差 %d 字节' % (pos, left))
                        g.write(chunk)
                        left -= len(chunk)
                    pos = o
                    st['holes'] = st.get('holes', 0) + 1
                elif o < pos:
                    raise IOError('数据区重叠：条目 %d 在 %d，游标 %d' % (i, o, pos))
                left = reg[i]
                src.seek(o)
                while left > 0:
                    chunk = src.read(min(left, BLOCK))
                    if not chunk:
                        raise IOError('条目 %d 搬运读取不足：还差 %d 字节' % (i, left))
                    g.write(chunk)
                    left -= len(chunk)
                pos += reg[i]
                if i == list_index and st['list_fits']:
                    # 原位换名字表文本：先整区间搬运，再回写头部若干字节（新文本一定更长）
                    here = g.tell()
                    g.seek(o_l)
                    g.write(ltext2)
                    g.seek(here)
                    st['list_rewritten'] = True
            if pos != old_data_end:
                raise IOError('数据区搬运后游标 %d != 旧末尾 %d' % (pos, old_data_end))
            # 追加区起点（真实包 data_len 是 256 的倍数，追加区紧贴旧末尾；否则补零对齐）
            append_at = list_off_new if st['list_moved'] else (items[0][4] if items else old_data_end)
            if pos < append_at:
                g.write(b'\0' * (append_at - pos))
                pos = append_at
            if st['list_moved']:
                if progress:
                    progress(len(order) + 1, total, '名字表搬家')
                g.write(ltext2)
                pad = (len(ltext2) + align - 1) // align * align - len(ltext2)
                if pad:
                    g.write(b'\0' * pad)
                pos += (len(ltext2) + align - 1) // align * align
                st['list_rewritten'] = True
            for k, it in enumerate(items):
                if cancel is not None and cancel.is_set():
                    st['cancelled'] = True
                    return st
                if progress:
                    progress(len(order) + (2 if st['list_moved'] else 1) + k, total,
                             '新增 %s' % it[0].decode('gbk', 'replace'))
                if it[4] != pos:
                    raise IOError('新增块位置对不上：%d != %d' % (it[4], pos))
                g.write(it[2])
                pad = (len(it[2]) + align - 1) // align * align - len(it[2])
                if pad:
                    g.write(b'\0' * pad)
                pos += (len(it[2]) + align - 1) // align * align
            if pos != pkg.data_off + new_data_len:
                raise IOError('数据区落盘末尾 %d != 计划 %d' % (pos, pkg.data_off + new_data_len))
            if tail > 0:
                src.seek(old_data_end)
                left = tail
                while left > 0:
                    chunk = src.read(min(left, BLOCK))
                    if not chunk:
                        break
                    g.write(chunk)
                    left -= len(chunk)
            g.flush()
        os.replace(tmp, out_path)
        done = True
        st['added'] = len(items)
        st['names'] = [it[0].decode('gbk', 'replace') for it in items]
        st['size'] = os.path.getsize(out_path)
    finally:
        if not done and os.path.exists(tmp):
            try:
                os.remove(tmp)
            except OSError:
                pass
    return st


# ---------- 官方 .xzip 补丁：文件夹改动 -> 补丁包 ----------
# 官方样本全量复验（复验_2026-10-09/official_xzip/验收报告.txt + 本次逐字段复测）：
#   * 条目名 = Data/<包文件名>/<资源路径>（GBK，/ 分隔）；负载 = LZMA 包裹的「存储块」；
#   * LZMA 包裹实测布局（9/9 条）：'LZMA' + 28×00 + u32(0)@32 + u32(存储块长度)@36
#     + 0x5D@40(=lc3/lp0/pb2) + u32(0x01000000)@41 + LZMA1 raw 流@45；
#   * 覆盖块的 96 字节块头 @24 == crc_axp(相位 0 解出的新明文)（官方 5 条带块头条目：4 条完全成立；
#     1 条 PocketCampaignTable 为官方自身异常——负载比 @20 多 1 字节，@24 与 body[:@20] 的相位 0 解码相符）；
#     @28..96 全零 5/5、@20==正文长度 4/5；本库 Config 763/763、Material8 133/133、Interface 1656 条
#     全部 @20/尾零相符、正文 crc 抽查 400 条全相符 → 覆盖时 @20/@24 必须按新明文重算，其余字节照抄原头；
#   * 脚本容器块 = encode_container(明文, 原 256 字节容器头)（等长闸门在 scriptcodec）；
#   * 无块头条目（(list)/(command)/(version)/ndata.dat 这类）整条原样替换；
#   * zip 外壳：local ver=45 / method=8（deflate 打在 LZMA 包裹字节上）/ local extra 20 字节
#     (0100100000000000000000000000000000000000) / central made=0 need=20 / EOCD 后 f5fba238；
#     xzip_pack 的 meta/tail 能力已按官方样本逐字节重打验证过，这里直接复用。

LZMA_WRAP_MAGIC = b'LZMA'
LZMA_WRAP_HDR_LEN = 45
LZMA_WRAP_DICT = 0x01000000
XZIP_LOCAL_VER = 45
XZIP_LEXTRA = bytes.fromhex('0100100000000000000000000000000000000000')
XZIP_TAIL = bytes.fromhex('f5fba238')


def lzma_wrap(data, dict_size=LZMA_WRAP_DICT):
    """官方补丁条目负载的 LZMA 包裹，按实测布局写。
    注意：官方 @32 恒 0、真实块长在 @36（xzipio 写的 @32+无@36 是非官方布局，别对照它写）。"""
    co = lzma.LZMACompressor(format=lzma.FORMAT_RAW, filters=[{
        'id': lzma.FILTER_LZMA1, 'dict_size': dict_size, 'lc': 3, 'lp': 0, 'pb': 2}])
    stream = co.compress(data) + co.flush()
    return (LZMA_WRAP_MAGIC + b'\x00' * 28 + struct.pack('<I', 0) +
            struct.pack('<I', len(data)) + b'\x5d' + struct.pack('<I', dict_size) + stream)


# ---- 文件夹 -> 条目匹配（与 server.api_repack_folder 同一口径，实现集中在这里，两处共用）----


def clean_seg(s):
    """导出安全名的一段（与 axpcore.safe_relpath 同规则）。"""
    return axpcore.BAD_CHARS.sub('_', s).strip().strip('.')


def pkg_key_index(pkg):
    """相对路径(归一化小写) -> [条目下标]。显示名与导出安全名两套键都收；
    名字表自身的行记 -1（文件夹里出现则自动维护，静默跳过）。"""
    idx_map = {}
    def add(k, i):
        if k:
            lst = idx_map.setdefault(k, [])
            if i not in lst:
                lst.append(i)
    for r in pkg.rows():
        disp = (r.display or '').replace('\\', '/').strip().lower()
        if getattr(r, 'named_by', None) == 'self':
            add(disp, -1)
            continue
        add(disp, r.index)
        segs = [clean_seg(x) for x in disp.split('/')]
        segs = [x for x in segs if x not in ('', '.', '..')]
        if segs:
            add('/'.join(segs), r.index)
    return idx_map


def export_equivalent(pkg, row):
    """条目在导出文件夹里对应的字节（与 axpcore.extract 落盘口径一致）；取不到返回 None。"""
    try:
        if row.script:
            return scriptcodec.decode_container(pkg.read(row))
        if row.encodable:
            return pkg.decode(row)
        return pkg.read(row)
    except Exception:
        return None


def _folder_manifest(pkg, folder, stem):
    """找导出清单（.axp_export_manifest.json，与 server.api_repack_folder 同口径）。
    返回 (清单 entries 或 None, 清单根目录)。"""
    for cand in (folder, os.path.join(folder, stem)):
        mp = os.path.join(cand, '.axp_export_manifest.json')
        try:
            if os.path.isfile(mp):
                with open(mp, encoding='utf-8') as f:
                    man = json.load(f)
                if str(man.get('pkg', '')).lower() == pkg.name.lower():
                    return man.get('entries') or {}, cand
        except Exception:
            pass
    return None, folder


def _match_folder_files(pkg, folder, progress=None, cancel=None):
    """按 api_repack_folder 同款匹配扫描文件夹。返回 dict：
       edits {条目下标: 字节}、newfiles [(资源相对路径, 字节)]、unchanged、list_files、
       skipped、files_seen、manifest_used；取消返回 None。"""
    stem = os.path.splitext(pkg.name)[0]
    idx_map = pkg_key_index(pkg)
    rows = {r.index: r for r in pkg.rows()}
    manifest, mroot = _folder_manifest(pkg, folder, stem)
    allfiles = []
    for root, _dirs, files in os.walk(folder):
        for fn in files:
            if fn == '.axp_export_manifest.json':
                continue
            allfiles.append(os.path.join(root, fn))
    edits = {}
    newfiles = []
    skipped = []
    unchanged = list_files = 0
    for k, full in enumerate(allfiles):
        if cancel is not None and cancel.is_set():
            return None
        if progress:
            progress(k + 1, len(allfiles), '核对文件：' + os.path.relpath(full, folder))
        rel = os.path.relpath(full, folder).replace('\\', '/')
        # 1) 清单快路径：只比 size+sha1，不解密
        if manifest is not None:
            try:
                mrel = os.path.relpath(full, mroot).replace('\\', '/').lower()
            except ValueError:
                mrel = rel.lower()
            rec = manifest.get(mrel)
            if rec is not None:
                try:
                    with open(full, 'rb') as f:
                        blob = f.read()
                except Exception as e:
                    skipped.append('%s（读取失败：%s）' % (rel, e))
                    continue
                if len(blob) == rec[0] and hashlib.sha1(blob).hexdigest() == rec[1]:
                    unchanged += 1
                else:
                    edits[rec[2]] = blob
                continue
        # 2) 名字匹配回退（清单里没有的文件 / 无清单）
        key = rel.lower()
        if key.endswith('.enc'):
            key = key[:-4]
        parts = key.split('/', 1)
        for pfx in (stem.lower(), (stem + '.axp').lower()):
            if parts[0] == pfx and len(parts) > 1:
                key = parts[1]
                break
        hit = idx_map.get(key)
        if hit is None:
            fb = key.rsplit('/', 1)[-1]
            cand2 = set()
            for k2, v in idx_map.items():
                if k2.rsplit('/', 1)[-1] == fb:
                    cand2.update(v)
            if cand2:
                real = sorted(set(ix for ix in cand2 if ix >= 0))
                if len(real) == 1:
                    hit = real
                elif not real:
                    hit = [-1]
                else:
                    skipped.append('%s（有 %d 个条目同名，对不上）' % (rel, len(real)))
                    continue
        if hit is None:
            # 新文件（包里没这个名字）
            try:
                with open(full, 'rb') as f:
                    blob = f.read()
            except Exception as e:
                skipped.append('%s（读取失败：%s）' % (rel, e))
                continue
            parts2 = rel.split('/', 1)
            if len(parts2) > 1 and parts2[0].lower() in (stem.lower(), (stem + '.axp').lower()):
                newfiles.append((parts2[1], blob))
            else:
                newfiles.append((rel, blob))
            continue
        real = sorted(set(ix for ix in hit if ix >= 0))
        if not real:
            list_files += 1          # 名字表导出文件：补丁不打回，静默跳过
            continue
        try:
            with open(full, 'rb') as f:
                blob = f.read()
        except Exception as e:
            skipped.append('%s（读取失败：%s）' % (rel, e))
            continue
        for ix in real:
            exp = export_equivalent(pkg, rows[ix])
            if exp is not None and blob == exp:
                unchanged += 1        # 没动过：不进补丁
                continue
            edits[ix] = blob
    return dict(edits=edits, newfiles=newfiles, unchanged=unchanged, list_files=list_files,
                skipped=skipped, files_seen=len(allfiles), manifest_used=manifest is not None)


class _SkipEntry(Exception):
    """该条目吃不准/不支持：降级为 skipped，不进补丁。"""


def _patch_block_override(pkg, row, blob):
    """被编辑的已有条目 -> 补丁里的存储块（LZMA 解出来的字节）。不支持则 raise _SkipEntry。"""
    with open(pkg.path, 'rb') as f:
        if row.script:
            # 脚本容器：只允许等长（容器头 252..256 字段未定），存储块 = 重封装的容器
            old_plain = row.content_len - scriptcodec.HDR_LEN
            try:
                scriptcodec.verify_container_editable(old_plain, len(blob))
            except ValueError as exc:
                raise _SkipEntry(str(exc))
            f.seek(row.offset)
            head = f.read(scriptcodec.HDR_LEN)
            if len(head) != scriptcodec.HDR_LEN:
                raise IOError('条目 %d 容器头读取不足' % row.index)
            return scriptcodec.encode_container(blob, head)
        if row.encodable:
            # 带块头的可解码条目：头照抄结构、@20/@24 按新明文重算（官方样本 + 本库交叉验证结论），
            # 正文按相位 0 重编（官方补丁块全部按相位 0 编码，见模块头证据）
            f.seek(row.offset)
            hdr96 = f.read(axpcodex.HDR_LEN)
            if len(hdr96) != axpcodex.HDR_LEN or hdr96[:6] != axpcore.HDR_PREFIX:
                raise IOError('条目 %d 块头读取不足/前缀不符' % row.index)
            ph = axpcodex.decode_header(hdr96)
            if ph[:15] != axpcodex.MAGIC or ph[15] != 0:
                raise _SkipEntry('块头明文不符合已知结构（未吃透，不猜）')
            algo = struct.unpack_from('<I', ph, 16)[0]
            if algo != row.algo:
                raise _SkipEntry('块头算法 %s 与行算法 %s 不一致（不猜）' % (algo, row.algo))
            newph = bytearray(ph)
            struct.pack_into('<II', newph, 20, len(blob) & 0xFFFFFFFF, axp_build.crc_axp(blob))
            return axpcodex.encode_header(bytes(newph)) + axpcodex.encode_body(algo, 0, blob)
        if row.form == axpcore.RAW:
            # 无块头条目：整条原样替换（官方 (list)/(command)/(version)/ndata.dat 同型）
            return blob
        raise _SkipEntry('带块头但算法未转写（algo=%s），补丁不能重编（不猜）' % row.algo)


def _id_header_template(pkg, rows):
    """新增条目 96 字节头的模板：优先本包真实 algo==19 条目的明文头，其次任一可解码条目的
    明文头（结构全库实测一致：magic+00 @0..16、algo@16、len@20、crc@24、28..96 全零）。
    返回 (模板描述, 96 字节明文头 或 None=用内置结构)。"""
    fallback = None
    for r in pkg.rows():
        if r.algo is None or r.form == axpcore.RAW:
            continue
        try:
            with open(pkg.path, 'rb') as f:
                f.seek(r.offset)
                hdr = f.read(axpcodex.HDR_LEN)
            if len(hdr) != axpcodex.HDR_LEN or hdr[:6] != axpcore.HDR_PREFIX:
                continue
            tmpl = axpcodex.decode_header(hdr)
            if tmpl[:15] != axpcodex.MAGIC or tmpl[15] != 0 or any(tmpl[28:]):
                continue
            if fallback is None:
                fallback = (r.index, tmpl)
            if r.algo == 19:
                return ('本包 #%d(algo19) 真实明文头' % r.index, tmpl)
        except Exception:
            continue
    if fallback is not None:
        return ('本包 #%d 真实明文头结构（全库与 algo19 同型）' % fallback[0], fallback[1])
    return ('内置结构（magic+00+algo/len/crc+28..96零；与 Model.axp #207 等真实 algo19 条目逐字节同构）', None)


def _id_block(blob, tmpl):
    """新增条目存储块 = 96 字节块头(algo=19 ID, 正文原样) + 正文。"""
    if tmpl is not None and len(tmpl) == axpcodex.HDR_LEN:
        h = bytearray(tmpl)
    else:
        h = bytearray(axpcodex.HDR_LEN)
        h[0:15] = axpcodex.MAGIC
    h[15] = 0
    struct.pack_into('<III', h, 16, 19, len(blob) & 0xFFFFFFFF, axp_build.crc_axp(blob))
    return axpcodex.encode_header(bytes(h)) + bytes(blob)


def make_xzip_patch(pkg, folder, out_path, include_new=True, progress=None, cancel=None):
    """把导出文件夹里「改过 / 新增」的文件按官方 .xzip 补丁格式打成补丁。

    匹配口径与 server.api_repack_folder 相同：.axp_export_manifest.json 快路径（size+sha1）
    优先，没命中再按名字回退；名字表自身的文件（下标 -1）静默跳过。
      覆盖已有条目：见 _patch_block_override（带块头条目重算 @20/@24、正文按相位 0 重编；
      脚本容器只等长；无块头条目整条替换；未转写算法跳过并说明）。
      新增文件：96 字节块头(抄真实明文头模板, algo=19) + 正文原样；条目名
      Data/<包文件名>/<资源相对路径>（/ 分隔，GBK）；include_new=False 时跳过并说明。
      没改动的跳过；没有任何可打包内容时 raise ValueError（不产出空补丁）。
    zip 外壳对齐官方：local ver=45 / method=8(deflate 打在 LZMA 包裹上) / local extra 20 字节 /
    central made=0 / EOCD 后 f5fba238（复用 xzip_pack 的 meta/tail）。
    返回 stats（out/overridden/added/skipped/errors/unchanged/files_seen/list_files/
    manifest_used/cancelled/written/size/new_template）。
    """
    if axpcodex is None or axp_build is None:
        raise IOError('制作补丁需要 axpcodex/axp_build（当前环境缺依赖）')
    if not os.path.isdir(folder):
        raise IOError('文件夹不存在：%s' % folder)
    out_path = os.path.abspath(out_path)
    st = dict(out=out_path, overridden=0, added=0, skipped=[], errors=[], unchanged=0,
              files_seen=0, list_files=0, manifest_used=False, cancelled=False,
              written=0, size=0, new_template=None)
    if cancel is not None and cancel.is_set():
        st['cancelled'] = True
        return st
    mt = _match_folder_files(pkg, folder, progress=progress, cancel=cancel)
    if mt is None:
        st['cancelled'] = True
        return st
    edits = mt['edits']
    newfiles = mt['newfiles']
    st['unchanged'] = mt['unchanged']
    st['list_files'] = mt['list_files']
    st['skipped'] = mt['skipped']
    st['files_seen'] = mt['files_seen']
    st['manifest_used'] = mt['manifest_used']
    if not include_new and newfiles:
        for rel, _blob in newfiles:
            st['skipped'].append('%s（新文件；include_new=False 时不打补丁）' % rel)
        newfiles = []

    rows = {r.index: r for r in pkg.rows()}
    order = [r.index for r in pkg.rows() if r.index in edits]
    for ix in edits:
        if ix not in rows:
            st['skipped'].append('条目 #%s 不在当前包目录里，丢弃' % ix)
    total_work = len(order) + len(newfiles)
    done = 0

    entries = []          # [(条目名, 存储块 bytes)]，条目名含 Data/<包名>/ 前缀
    seen_names = set()
    for ix in order:
        row = rows[ix]
        blob = edits[ix]
        done += 1
        if progress:
            progress(done, total_work, '制作补丁：%s' % row.display)
        if cancel is not None and cancel.is_set():
            st['cancelled'] = True
            return st
        try:
            block = _patch_block_override(pkg, row, blob)
        except _SkipEntry as exc:
            st['skipped'].append('%s：%s' % (row.display, exc))
            continue
        name = 'Data/%s/%s' % (pkg.name, (row.display or '').replace('\\', '/'))
        key = name.lower()
        if key in seen_names:
            st['skipped'].append('%s：与原条目重名（忽略大小写），本条不重复打' % row.display)
            continue
        seen_names.add(key)
        entries.append((name, block))
        st['overridden'] += 1

    tmpl_desc, tmpl = _id_header_template(pkg, rows)
    st['new_template'] = tmpl_desc
    for rel, blob in newfiles:
        done += 1
        if progress:
            progress(done, total_work, '制作补丁：新增 %s' % rel)
        if cancel is not None and cancel.is_set():
            st['cancelled'] = True
            return st
        rel_c = rel.replace('\\', '/')
        try:
            rel_c.encode('gbk')
        except UnicodeEncodeError:
            st['skipped'].append('%s（新增文件：路径无法 GBK 编码）' % rel)
            continue
        name = 'Data/%s/%s' % (pkg.name, rel_c)
        key = name.lower()
        if key in seen_names:
            st['skipped'].append('%s（新增文件：与已有条目重名，跳过）' % rel_c)
            continue
        seen_names.add(key)
        entries.append((name, _id_block(blob, tmpl)))
        st['added'] += 1

    if not entries:
        raise ValueError('没有可打包的改动：%d 个文件里没找到改动过的条目（未改动 %d，跳过 %d%s）'
                         % (st['files_seen'], st['unchanged'], len(st['skipped']),
                            ('：' + '；'.join(st['skipped'][:3])) if st['skipped'] else ''))

    d = os.path.dirname(out_path)
    if d:
        os.makedirs(d, exist_ok=True)
    tmpdir = tempfile.mkdtemp(prefix='mkpatch_', dir=d or None)
    wrote = False
    try:
        meta = {}
        names = []
        n = len(entries)
        for i, (name, block) in enumerate(entries):
            if progress:
                progress(i + 1, n, '制作补丁：打包 %s' % name)
            if cancel is not None and cancel.is_set():
                st['cancelled'] = True
                return st
            rel = name
            dest = os.path.join(tmpdir, rel.replace('/', os.sep))
            dd = os.path.dirname(dest)
            if dd:
                os.makedirs(dd, exist_ok=True)
            with open(dest, 'wb') as g:
                g.write(lzma_wrap(block))
            meta[rel] = dict(dost=0, dosd=0, method=8, lver=XZIP_LOCAL_VER,
                             lmade=0, lextra=XZIP_LEXTRA)
            names.append(rel)
        if progress:
            def _pack_cb(k, t, cur):
                progress(k, t, '写出补丁：%s' % cur)
        ps = xzip_pack(tmpdir, out_path, meta=meta, order=names, tail=XZIP_TAIL,
                       progress=_pack_cb if progress else None, cancel=cancel)
        st['written'] = ps.get('written', 0)
        st['errors'].extend(ps.get('errors', []))
        if ps.get('cancelled'):
            st['cancelled'] = True
            return st
        st['size'] = os.path.getsize(out_path)
        wrote = True
    finally:
        shutil.rmtree(tmpdir, ignore_errors=True)
        if not wrote and not st.get('cancelled') and os.path.exists(out_path + '.part'):
            try:
                os.remove(out_path + '.part')
            except OSError:
                pass
    return st
