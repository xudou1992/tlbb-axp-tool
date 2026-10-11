"""AXP 解包工具 — 主程序（打包后双击即运行）"""
import os, sys, json, time, threading, traceback, webbrowser, hashlib, zlib, struct, shutil

# 适配 PyInstaller 打包后的路径
if getattr(sys, 'frozen', False):
    RES_DIR = sys._MEIPASS          # 打包资源（HTML等）解压目录
    APP_DIR = os.path.dirname(sys.executable)  # exe所在目录（输出文件放这）
else:
    RES_DIR = os.path.dirname(os.path.abspath(__file__))
    APP_DIR = RES_DIR
sys.path.insert(0, RES_DIR)
os.chdir(APP_DIR)

from flask import Flask, request, jsonify, send_from_directory
import axpcore
import packcore
import scriptcodec
import axp_build
import axpcodex

app = Flask(__name__, static_folder=RES_DIR, static_url_path='')

state = {
    'data_dir': r'D:\XTLBB\Data',
    'packages': {},
    'pkg_stats': {},
    'logs': [],
    'progress': {'current': 0, 'total': 0, 'text': ''},
    'cancel': threading.Event(),
    'busy': False,
}

def log(msg):
    ts = time.strftime('%H:%M:%S')
    line = '[%s] %s' % (ts, msg)
    state['logs'].append(line)
    if len(state['logs']) > 300:
        state['logs'] = state['logs'][-300:]
    print(line, flush=True)

@app.after_request
def after_request(res):
    res.headers['Access-Control-Allow-Origin'] = '*'
    res.headers['Access-Control-Allow-Headers'] = 'Content-Type'
    res.headers['Access-Control-Allow-Methods'] = 'GET, POST, OPTIONS'
    return res

@app.route('/')
def index():
    return send_from_directory(RES_DIR, 'axp-tool.html')

def _pkg_entry(fn, s):
    """单包统计 -> 前端行数据（scan 与 open_pkg 共用，字段保持一致）。"""
    return {
        'name': fn,
        'entries': s['entries'],
        'raw': s['raw'],
        'plain': s['plain'],
        'opaque': s['opaque'],
        'decodable': s.get('decodable', 0),
        'undecoded': s.get('undecoded', 0),
        'named': s['named'],
    }


# ---------- 扫描 ----------
@app.route('/api/scan')
def api_scan():
    d = request.args.get('dir', state['data_dir'])
    state['data_dir'] = d
    state['packages'] = {}
    state['pkg_stats'] = {}
    state['logs'] = []
    state['progress'] = {'current': 0, 'total': 0, 'text': ''}
    log('开始扫描 %s ...' % d)

    axp_files = sorted(f for f in os.listdir(d) if f.lower().endswith('.axp'))
    results = []
    for i, fn in enumerate(axp_files):
        state['progress'] = {'current': i+1, 'total': len(axp_files), 'text': fn}
        path = os.path.join(d, fn)
        try:
            pkg = axpcore.Package(path)
            s = pkg.stats()
            state['packages'][fn] = pkg
            state['pkg_stats'][fn] = s
            results.append(_pkg_entry(fn, s))
        except Exception as e:
            log('  跳过 %s: %s' % (fn, e))
    total = sum(r['entries'] for r in results)
    log('扫描完成，发现 %d 个包（总条目 %d）' % (len(results), total))
    state['progress'] = {'current': 0, 'total': 0, 'text': ''}
    return jsonify({'dir': d, 'packages': results})


# ---------- 打开单个包（秒开，社区工具的主用法） ----------
@app.route('/api/open_pkg', methods=['POST'])
def api_open_pkg():
    path = (request.json or {}).get('path', '')
    if not path or not os.path.isfile(path) or not path.lower().endswith('.axp'):
        return jsonify({'error': '不是有效的 .axp 文件：%s' % path}), 404
    fn = os.path.basename(path)
    log('打开单个包 %s ...' % fn)
    try:
        t0 = time.time()
        pkg = axpcore.Package(path)
        s = pkg.stats()
        state['packages'][fn] = pkg
        state['pkg_stats'][fn] = s
        log('%s 已打开：%d 条（%.1fs）' % (fn, s['entries'], time.time() - t0))
        return jsonify(_pkg_entry(fn, s))
    except Exception as e:
        log('打开失败 %s: %s' % (fn, e))
        return jsonify({'error': '打开失败: %s' % e}), 500

# ---------- 文件列表 ----------
@app.route('/api/files')
def api_files():
    pkg_name = request.args.get('pkg', '')
    pkg = state['packages'].get(pkg_name)
    if not pkg:
        return jsonify({'error': '包未加载'}), 404
    rows = []
    for r in pkg.rows():
        rows.append({
            'name': r.display,
            'status': r.status_cn,
            'form': axpcore.FORM_CN.get(r.form, r.form),
            'stored': r.stored,
            'content': r.content_len,
        })
    s = state['pkg_stats'].get(pkg_name, {})
    return jsonify({'rows': rows, 'stats': s})

# ---------- 导出 ----------
@app.route('/api/extract', methods=['POST'])
def api_extract():
    data = request.json or {}
    pkg_name = data.get('pkg', '')
    all_pkgs = data.get('all', False)
    outdir = data.get('outdir') or os.path.join(APP_DIR, '解包结果')
    include_enc = data.get('include_enc', False)

    targets = []
    if all_pkgs:
        targets = list(state['packages'].items())
    elif pkg_name in state['packages']:
        targets = [(pkg_name, state['packages'][pkg_name])]
    if not targets:
        return jsonify({'error': '包未加载'}), 404

    state['cancel'].clear()
    summary = []
    for name, pkg in targets:
        log('正在处理 %s' % name)
        sub = os.path.splitext(name)[0]
        out_dir = os.path.join(outdir, sub)
        def progress_cb(done, total, cur):
            state['progress'] = {'current': done, 'total': total, 'text': name + ' ' + cur}
        result = axpcore.extract(pkg, out_dir, include_enc=include_enc,
                                 progress=progress_cb, cancel=state['cancel'],
                                 manifest=True)
        if result.get('cancelled'):
            log('%s: 用户取消' % name)
            return jsonify({'cancelled': True, 'summary': summary})
        mb = result['bytes'] / 1048576
        log('%s: 写出 %d 个文件（%.1f MB），跳过未解出 %d，错误 %d' % (
            name, result['written'], mb, result['skipped'], len(result['errors'])))
        for e in result['errors'][:3]:
            log('  错误: %s' % e)
        summary.append({'pkg': name, **result})
    state['progress'] = {'current': 0, 'total': 0, 'text': ''}
    return jsonify({'summary': summary, 'total_written': sum(s['written'] for s in summary)})

# ---------- 体检 ----------
@app.route('/api/audit')
def api_audit():
    pkg_name = request.args.get('pkg', '')
    pkg = state['packages'].get(pkg_name)
    if not pkg:
        return jsonify({'error': '包未加载'}), 404
    log('体检报告 %s ...' % pkg_name)
    result = axpcore.audit(pkg, deep=50)
    log('体检完成：%d 个问题' % result.get('issue_total', 0))
    return jsonify(result)

# ---------- 补丁包解包 ----------
@app.route('/api/xzip_unpack', methods=['POST'])
def api_xzip_unpack():
    data = request.json or {}
    path = data.get('path', '')
    outdir = data.get('outdir', '')
    if not path or not os.path.isfile(path):
        return jsonify({'error': '文件不存在'}), 404
    state['cancel'].clear()
    log('补丁包解包: %s' % path)
    def progress_cb(done, total, name):
        state['progress'] = {'current': done, 'total': total, 'text': name}
    result = packcore.xzip_unpack(path, outdir, progress=progress_cb, cancel=state['cancel'])
    log('补丁包解包完成: %d 个文件' % result['written'])
    state['progress'] = {'current': 0, 'total': 0, 'text': ''}
    return jsonify(result)

# ---------- 补丁包读取：条目清单 + 单条解码预览（不解盘就能看内容） ----------
@app.route('/api/xzip_list', methods=['POST'])
def api_xzip_list():
    data = request.json or {}
    path = data.get('path', '')
    if not path or not os.path.isfile(path):
        return jsonify({'error': '文件不存在'}), 404
    ents = packcore.xzip_entries(path)
    rows = []
    for i, e in enumerate(ents):
        rows.append({'i': i, 'name': e['name'], 'method': e['method'],
                     'usize': e['usize'], 'csize': e['csize'], 'crc': e['crc']})
    log('补丁包 %s：%d 条目' % (os.path.basename(path), len(rows)))
    return jsonify({'path': path, 'name': os.path.basename(path),
                    'size': os.path.getsize(path), 'entries': rows})

@app.route('/api/xzip_preview', methods=['POST'])
def api_xzip_preview():
    """按条目号解码预览：LZMA 包裹 → AXP 块 → 算法正文 →（容器）Lua 明文，
    与「XZIP 解包」同一口径；返回形态、真实长度与文本/十六进制预览。"""
    data = request.json or {}
    path = data.get('path', '')
    i = data.get('i')
    limit = int(data.get('limit') or 4096)
    if not path or not os.path.isfile(path):
        return jsonify({'error': '文件不存在'}), 404
    ents = packcore.xzip_entries(path)
    if i is None or not (0 <= int(i) < len(ents)):
        return jsonify({'error': '条目号超出范围'}), 400
    e = ents[int(i)]
    try:
        raw = packcore.xzip_read(path, e)
        crc_ok = (not e['crc']) or (zlib.crc32(raw) & 0xFFFFFFFF) == e['crc']
        plain, kind, note = packcore.patch_entry_to_file_bytes(raw)
    except Exception as exc:
        return jsonify({'error': '解码失败：%s' % exc}), 500
    head = plain[:limit]
    txt = None
    try:
        t = head.decode('gbk')
        if all(32 <= ord(c) or c in '\r\n\t' for c in t[:400]):
            txt = t
    except Exception:
        pass
    return jsonify({'i': int(i), 'name': e['name'], 'method': e['method'],
                    'wrapped': e['usize'], 'unwrapped': len(plain), 'kind': kind,
                    'note': note, 'crc_ok': crc_ok, 'text': txt,
                    'hex': None if txt is not None else head.hex(' ')})


# ---------- 独立加解密：不打包也能把单个文件加/解密 ----------
def _codec_form(blob):
    """认一个文件的加密形态：container（脚本容器）/ lzma（官方包裹）/ block（AXP 存储块）/ plain（明文）。"""
    if blob[:8] == scriptcodec.MAGIC:
        return 'container'
    if blob[:4] == b'LZMA':
        return 'lzma'
    if len(blob) >= axpcodex.HDR_LEN:
        hd = axpcodex.decode_header(blob[:axpcodex.HDR_LEN])
        if hd[:len(axpcodex.MAGIC)] == axpcodex.MAGIC:
            return 'block'
    return 'plain'


def _codec_block_decode(blob, pos, probe=True):
    """AXP 存储块 → 明文；里面套着脚本容器就再解一层。
    返回 (明文, 形态, 说明, CRC 是否对上, 上下文)。上下文给「加密回去」用：
    algo、实际相位、以及块正文解出来的原始字节（可能是整个容器）。

    块头 @20 是正文长、@24 是明文 CRC，所以相位不用人猜：密钥流周期 128，
    按 CRC 一个个试出来（先试传进来的 pos，再试 0..127）。太大就只用给定相位。
    """
    hd = axpcodex.decode_header(blob[:axpcodex.HDR_LEN])
    algo = struct.unpack_from('<I', hd, 16)[0]
    blen = struct.unpack_from('<I', hd, 20)[0]
    want = struct.unpack_from('<I', hd, 24)[0]
    body = blob[axpcodex.HDR_LEN:]
    if 0 < blen <= len(body):
        body = body[:blen]          # 去掉尾部对齐填充
    limit = 1 << 20                 # 超过 1MB 不做相位搜索，免得卡住界面
    search = axpcodex.algo_kind(algo) in ('X', 'A', 'B', 'S', 'B15')   # 这几类密钥流带相位

    def attempt(p):
        pl = axpcodex.decode_body(algo, p, body)
        return pl if (not want or axp_build.crc_axp(pl) == want) else None

    plain = attempt(pos)
    crc_ok = plain is not None
    used = pos
    if plain is None and probe and want and search and len(body) <= limit:
        # 同一个包里的块相位常常是同一个值：先试上次试出来的，省掉整轮 128 次搜索
        for first in (_PHASE_HINT.get(algo), 0):
            if first is None or first == (pos & 0x7F):
                continue
            plain = attempt(first)
            if plain is not None:
                crc_ok, used = True, first
                break
    if plain is None and probe and want and search and len(body) <= limit:
        for cand in range(128):
            if cand == (pos & 0x7F):
                continue
            plain = attempt(cand)
            if plain is not None:
                crc_ok, used = True, cand
                break
    if crc_ok and search:
        _PHASE_HINT[algo] = used
    if plain is None:
        plain = axpcodex.decode_body(algo, pos, body)
    ctx = {'algo': algo, 'pos': used, 'body_plain': plain}
    if plain[:8] == scriptcodec.MAGIC:
        c = scriptcodec.decode_container(plain)
        if c is not None:
            return (c, 'container',
                    '存储块里还套着脚本容器，一起解了（algo=%d 相位 %d）' % (algo, used), crc_ok, ctx)
    note = 'algo=%d 相位 %d 正文 %d 字节' % (algo, used, len(plain))
    if not crc_ok:
        note += '；没对上块头里的正文 CRC（%08X），相位不对的话去「高级」改 pos' % (want,)
    return plain, 'block', note, crc_ok, ctx


def _codec_block_encode(blob, algo, pos):
    """明文 → AXP 存储块。块头按实测规则生成：@16 algo、@20 正文长、@24 crc_axp(明文)。"""
    crc = axp_build.crc_axp(blob)
    ph = axp_build.make_plain_header(algo, len(blob), crc)
    out = axpcodex.encode_header(ph) + axpcodex.encode_body(algo, pos, blob)
    back = axpcodex.decode_body(algo, pos, out[axpcodex.HDR_LEN:])
    if back != blob:
        raise IOError('加密自验没过：解回来和原文不一样（algo=%d 相位 %d）' % (algo, pos))
    return out, 'block', '块头按实测规则生成（algo=%d 正文长 %d 正文CRC %08X），正文相位 %d；' \
                         '已解回来逐字节核对' % (algo, len(blob), crc, pos), True


def _codec_container_encode(blob, head, ref=''):
    out = scriptcodec.encode_container(blob, head)
    back = scriptcodec.decode_container(out)
    if back != blob:
        raise IOError('容器加密自验没过：照 %s 的头加密后解回来和原文不一样' % os.path.basename(ref))
    return out


class _CodecUser(Exception):
    """给用户看的失败原因（不是程序内部错误）。"""


# algo → 上次按 CRC 试出来的相位；同包块常同值，批量时省掉整轮搜索
_PHASE_HINT = {}


def _codec_decode_one(blob, pos=0):
    """认格式并解码一个文件。返回 (明文, 形态, 说明, CRC 是否对上, 上下文)。"""
    form = _codec_form(blob)
    if form == 'container':
        return scriptcodec.decode_container(blob), 'container', '脚本容器 → Lua 明文', None, None
    if form == 'lzma':
        plain, ok, note = packcore.lzma_unwrap(blob)
        return plain, ('lzma' if ok else 'raw'), note, ok, None
    if form == 'block':
        return _codec_block_decode(blob, pos)
    raise _CodecUser('这个文件已经是明文了，直接改就行；要让它变成游戏能读的样子，用「加密回去」。')


def _codec_encode_one(blob, rblob, refname='', pos=0):
    """照样子文件 rblob 的格式，把明文加密回去。返回 (结果字节, 形态, 说明, 是否自验通过)。"""
    form = _codec_form(rblob)
    if form == 'container':
        out = _codec_container_encode(blob, rblob[:scriptcodec.HDR_LEN], refname)
        return out, 'container', '照 %s 的容器头加密，正文 %d 字节；已解回来逐字节核对' % (
            os.path.basename(refname), len(blob)), True
    if form == 'lzma':
        out = packcore.lzma_wrap(blob)
        back, ok, _n = packcore.lzma_unwrap(out)
        if not ok or back != blob:
            raise IOError('LZMA 包裹自验没过')
        return out, 'lzma', '按官方补丁的 LZMA 包裹打好；已拆回来逐字节核对', True
    if form == 'block':
        _p, _k, _n, _c, ctx = _codec_block_decode(rblob, pos)
        algo, used = ctx['algo'], ctx['pos']
        inner = ctx['body_plain']
        layered = ''
        if inner[:8] == scriptcodec.MAGIC and blob[:8] != scriptcodec.MAGIC:
            src = _codec_container_encode(blob, inner[:scriptcodec.HDR_LEN], refname)
            layered = '先装进脚本容器再装进块，'
        else:
            src = blob
        out, kind, note, crc_ok = _codec_block_encode(src, algo, used)
        return out, kind, '%s%s（原块 algo=%d 相位 %d）' % (layered, note, algo, used), crc_ok
    raise _CodecUser('认不出「原来的加密文件」的格式（%s 不是容器/存储块/LZMA）；'
                     '换它试试，或用「高级」指定方式。' % os.path.basename(refname))


def _codec_files_under(root, skip_out=None):
    """root 下所有文件的相对路径（排序、稳定）；输出目录嵌在里面时跳过，别把自己的产物再吃一遍。"""
    out = []
    skip = os.path.abspath(skip_out) if skip_out else None
    for r, dirs, fs in os.walk(root):
        ap = os.path.abspath(r)
        if skip and (ap == skip or ap.startswith(skip + os.sep)):
            dirs[:] = []
            continue
        for f in fs:
            out.append(os.path.relpath(os.path.join(r, f), root))
    return sorted(out)


def _codec_find_ref(reference, rel):
    """明文 rel 对应的样子文件：同相对路径；再试去掉自动加的 _解密 后缀。"""
    cand = [os.path.join(reference, rel)]
    d, fn = os.path.split(rel)
    stem, ext = os.path.splitext(fn)
    if stem.endswith('_解密'):
        cand.append(os.path.join(reference, d, stem[:-len('_解密')] + ext))
    for p in cand:
        if os.path.isfile(p):
            return p
    return None


def _codec_walk_dir(mode, src, out, pos=0, reference=''):
    """整个文件夹一起解 / 一起加密回去：保持相对路径和文件名，认不出的原样搬过去并计数。"""
    if mode == 'auto_encode' and not (reference and os.path.isdir(reference)):
        return {'error': '批量「加密回去」要一个**同结构的加密文件夹**当样子（选文件夹，不是单个文件）。'}, 400
    st = {'mode': mode, 'kind': 'dir', 'in_dir': src, 'out_dir': out,
          'total': 0, 'done': 0, 'written': 0, 'by_kind': {}, 'plain_copied': 0,
          'already_encrypted': 0, 'plain_ref': 0, 'unmatched': [], 'crc_bad': 0,
          'errors': [], 'cancelled': False}
    rels = _codec_files_under(src, skip_out=out)
    st['total'] = len(rels)
    for i, rel in enumerate(rels, 1):
        if state['cancel'].is_set():
            st['cancelled'] = True
            break
        state['progress'] = {'current': i, 'total': len(rels), 'text': rel}
        sp = os.path.join(src, rel)
        dp = os.path.join(out, rel)
        d = os.path.dirname(dp)
        try:
            with open(sp, 'rb') as f:
                blob = f.read()
            if mode == 'auto_decode':
                form = _codec_form(blob)
                if form == 'plain':          # 本来就是明文：搬过去，文件夹保持完整
                    if d:
                        os.makedirs(d, exist_ok=True)
                    shutil.copyfile(sp, dp)
                    st['plain_copied'] += 1
                    st['done'] = i
                    continue
                data_out, kind, note, crc_ok, _ctx = _codec_decode_one(blob, pos)
                if crc_ok is False:
                    st['crc_bad'] += 1
            else:
                refp = _codec_find_ref(reference, rel)
                if not refp:
                    if d:
                        os.makedirs(d, exist_ok=True)
                    shutil.copyfile(sp, dp)
                    st['unmatched'].append(rel)
                    st['done'] = i
                    continue
                if _codec_form(blob) != 'plain':   # 已经是加密件，别再套一层
                    if d:
                        os.makedirs(d, exist_ok=True)
                    shutil.copyfile(sp, dp)
                    st['already_encrypted'] += 1
                    st['done'] = i
                    continue
                with open(refp, 'rb') as f:
                    rblob = f.read()
                if _codec_form(rblob) == 'plain':
                    # 样子文件本身也是明文（比如整包里就没加密的那类）：没什么可照的，原样搬
                    if d:
                        os.makedirs(d, exist_ok=True)
                    shutil.copyfile(sp, dp)
                    st['plain_ref'] += 1
                    st['done'] = i
                    continue
                data_out, kind, note, crc_ok = _codec_encode_one(blob, rblob, refp, pos)
            if d:
                os.makedirs(d, exist_ok=True)
            with open(dp, 'wb') as f:
                f.write(data_out)
            st['written'] += 1
            st['by_kind'][kind] = st['by_kind'].get(kind, 0) + 1
            st['done'] = i
        except (_CodecUser, IOError, ValueError) as e:
            st['errors'].append({'file': rel.replace('\\', '/'), 'error': str(e)})
        except Exception as e:
            st['errors'].append({'file': rel.replace('\\', '/'), 'error': '处理失败：%s' % e})
    state['progress'] = {'current': 0, 'total': 0, 'text': ''}
    log('批量加解密 %s：%s → %s 共 %d 个，写 %d，搬 %d，没配上 %d，错 %d%s' % (
        mode, src, out, st['total'], st['written'], st['plain_copied'], len(st['unmatched']),
        len(st['errors']), '（已取消）' if st['cancelled'] else ''))
    return st, 200


@app.route('/api/codec', methods=['POST'])
def api_codec():
    """mode：
      auto_decode     认格式后解码（容器 / 存储块 / LZMA 包裹），给 UI 的一键「解开」
      auto_encode     照「原来的加密文件」的格式把明文加密回去，给一键「加密回去」
      block_decode    AXP 存储块文件 → 明文（含脚本容器再解一层）
      block_encode    明文 → AXP 存储块（需 algo，可选 pos=密钥相位，默认 0=补丁块口径）
      container_decode 脚本容器文件 → Lua 明文
      container_encode Lua 明文 → 脚本容器（需 template=另一个容器文件，头部照抄）
      lzma_unwrap / lzma_wrap   官方补丁条目的 LZMA 包裹拆/装
    入参 {mode, path, out, algo?, pos?, template?, reference?}；原文件不动，只写 out。
    """
    data = request.json or {}
    mode = data.get('mode', '')
    src = data.get('path', '')
    out = data.get('out', '')
    pos = int(data.get('pos') or 0)
    ref = data.get('reference', '')
    if not src or not os.path.exists(src):
        return jsonify({'error': '输入的文件或文件夹不存在'}), 404
    if not out:
        return jsonify({'error': '没给输出路径'}), 400
    # 这工具对用户的承诺是「原文件不动」，先挡住自己盖自己的写法
    if os.path.abspath(out) == os.path.abspath(src):
        return jsonify({'error': '输出和输入是同一个，会把自己刚拿到的东西盖掉，换个名字。'}), 400
    if ref and os.path.abspath(out) == os.path.abspath(ref):
        return jsonify({'error': '输出会和「原来的加密文件」同名，那个要留着当样子，别盖它。'}), 400
    if os.path.isdir(src):        # 整个文件夹一起走：保持相对路径和文件名
        if mode not in ('auto_decode', 'auto_encode'):
            return jsonify({'error': '整文件夹只走「解开 / 加密回去」两页；单文件的指定方式在「高级」。'}), 400
        state['cancel'].clear()
        try:
            os.makedirs(out, exist_ok=True)
        except Exception as e:
            return jsonify({'error': '输出文件夹建不出来：%s' % e}), 400
        st, code = _codec_walk_dir(mode, src, out, pos=pos, reference=ref)
        if st.get('error'):
            return jsonify(st), code
        return jsonify(st)
    blob = open(src, 'rb').read()
    crc_ok = None
    try:
        if mode == 'auto_decode':
            plain, kind, note, crc_ok, _ctx = _codec_decode_one(blob, pos)
        elif mode == 'auto_encode':
            if not ref or not os.path.isfile(ref):
                return jsonify({'error': '「原来的加密文件」找不到：要给一个现成的加密文件，'
                                         '才知道按哪种格式加密。（整批就选它所在的文件夹）'}), 400
            plain, kind, note, crc_ok = _codec_encode_one(blob, open(ref, 'rb').read(), ref, pos)
        elif mode == 'block_decode':
            # 相位：补丁块是 0；包内块要按它在数据区里的位置（可选 pos 传进来）
            pos = int(data.get('pos') or 0)
            if _codec_form(blob) == 'block':
                plain, kind, note, crc_ok, _ctx = _codec_block_decode(blob, pos)
            else:
                plain, kind, note = blob, 'raw', '不是 AXP 存储块（块头不匹配），按原样输出'
        elif mode == 'block_encode':
            algo = int(data.get('algo') or 0)
            if algo <= 0:
                return jsonify({'error': '加密成存储块要给算法号 algo（1..25）'}), 400
            pos = int(data.get('pos') or 0)     # 密钥相位：补丁块用 0；包内块要按目标位置
            plain, kind, note, crc_ok = _codec_block_encode(blob, algo, pos)
        elif mode == 'container_decode':
            c = scriptcodec.decode_container(blob)
            if c is None:
                return jsonify({'error': '不是脚本容器（头 8 字节不匹配或太短）'}), 400
            plain, kind, note = c, 'container', None
        elif mode == 'container_encode':
            tpl = data.get('template', '')
            if not tpl or not os.path.isfile(tpl):
                return jsonify({'error': '加密容器要一个 template（照抄头部的现成容器文件）'}), 400
            head = open(tpl, 'rb').read(scriptcodec.HDR_LEN)
            if len(head) < scriptcodec.HDR_LEN:
                return jsonify({'error': 'template 容器头不足 256 字节'}), 400
            plain = _codec_container_encode(blob, head, tpl)
            kind, note = 'container', '容器头照抄 %s；正文长度 %d（变长已放开）；已解回来逐字节核对' % (
                os.path.basename(tpl), len(blob))
        elif mode == 'lzma_unwrap':
            plain, ok, note = packcore.lzma_unwrap(blob)
            kind = 'lzma' if ok else 'raw'
            if not ok:
                note = '不是 LZMA 包裹（前 4 字节非 "LZMA"），按原样输出'
        elif mode == 'lzma_wrap':
            plain, kind, note = packcore.lzma_wrap(blob), 'lzma', None
        else:
            return jsonify({'error': '未知 mode：%s' % mode}), 400
    except _CodecUser as exc:
        return jsonify({'error': str(exc)}), 400
    except Exception as exc:
        log('加解密失败: %s' % exc)
        return jsonify({'error': '处理失败：%s' % exc}), 500
    d = os.path.dirname(out)
    if d:
        os.makedirs(d, exist_ok=True)
    with open(out, 'wb') as f:
        f.write(plain)
    log('加解密 %s：%s %d -> %s %d 字节' % (mode, os.path.basename(src), len(blob),
                                          os.path.basename(out), len(plain)))
    return jsonify({'mode': mode, 'kind': kind, 'in_bytes': len(blob),
                    'out_bytes': len(plain), 'out': out, 'note': note, 'crc_ok': crc_ok})

# ---------- 补丁包打包 ----------
@app.route('/api/xzip_pack', methods=['POST'])
def api_xzip_pack():
    data = request.json or {}
    srcdir = data.get('srcdir', '')
    out_path = data.get('out_path', '')
    if not srcdir or not os.path.isdir(srcdir):
        return jsonify({'error': '目录不存在'}), 404
    state['cancel'].clear()
    log('补丁包打包: %s -> %s' % (srcdir, out_path))
    def progress_cb(done, total, name):
        state['progress'] = {'current': done, 'total': total, 'text': name}
    result = packcore.xzip_pack(srcdir, out_path, progress=progress_cb, cancel=state['cancel'])
    log('补丁包打包完成: %d 个文件' % result['written'])
    state['progress'] = {'current': 0, 'total': 0, 'text': ''}
    return jsonify(result)

# ---------- 回包（单文件按名字替换，保留兼容） ----------
def _export_equivalent(pkg, row):
    """条目在导出文件夹里对应的字节（与 axpcore.extract 落盘口径一致）；取不到返回 None。
    （实现集中在 packcore.export_equivalent，/api/repack_folder 与 /api/make_patch 共用同一口径）"""
    return packcore.export_equivalent(pkg, row)

def _clean_seg(s):
    return packcore.clean_seg(s)

def _pkg_key_index(pkg):
    """相对路径(归一化小写) -> [条目下标]。显示名与导出安全名两套键都收；
    名字表自身的行记 -1（文件夹里出现则自动维护，静默跳过）。
    （实现集中在 packcore.pkg_key_index，两个端点共用同一口径）"""
    return packcore.pkg_key_index(pkg)

def _prepare_edits(pkg, edits):
    """过滤编辑表：脚本容器只支持等长回写，长度不符的跳过并说明原因。"""
    rows = {r.index: r for r in pkg.rows()}
    valid, skipped = {}, []
    for idx, blob in edits.items():
        r = rows.get(idx)
        if r is not None and r.script:
            # 脚本容器：变长已放开（容器头校验只覆盖头部，与正文长度无关），
            # 只拦短到不足一个加密分组的情况，错误由回包抛出。
            pass
        valid[idx] = blob
    return valid, skipped

def _do_repack_and_verify(pkg, pkg_name, valid, out_path, extra=None, verify_async=False,
                          additions=None):
    state['cancel'].clear()
    def progress_cb(done, total, cur):
        state['progress'] = {'current': done, 'total': total, 'text': pkg_name + ' ' + str(cur)}
    try:
        t0 = time.time()
        st_add = None
        if additions:
            # 先按编辑表回包到临时底包，再往底包里新增条目（两段都走最小扰动路径）
            base = pkg
            stage = out_path + '.stage1'
            st_stage = None
            if valid:
                st_stage = packcore.axp_repack(pkg, valid, stage, progress=progress_cb,
                                               cancel=state['cancel'])
                if state['cancel'].is_set():
                    if os.path.exists(stage):
                        os.remove(stage)
                    return jsonify({'cancelled': True})
                base = axpcore.Package(stage)
            st_add = packcore.axp_add(base, additions, out_path, progress=progress_cb,
                                      cancel=state['cancel'])
            if valid:
                try:
                    os.remove(stage)
                except OSError:
                    pass
            if st_add.get('cancelled'):
                return jsonify({'cancelled': True})
            result = st_add
            if st_stage:
                for kk in ('replaced', 'recoded', 'copied', 'appended', 'list_updated'):
                    result[kk] = st_stage.get(kk)
            result['edited'] = len(valid)
            t_repack = time.time() - t0
            # 新增条目读回核对（哈希定位，与游戏同口径）
            p3 = axpcore.Package(out_path)
            rows3 = {r.index: r for r in p3.rows()}
            bad_add = []
            for nm, blob in additions.items():
                idx3 = packcore.entry_index_of(p3, nm)
                r3 = rows3.get(idx3) if idx3 is not None else None
                got3 = packcore.export_equivalent(p3, r3) if r3 is not None else None
                if got3 != blob:
                    bad_add.append(nm)
            if bad_add:
                result['errors'] = (result.get('errors') or []) + \
                    ['新增条目读回不一致：%s' % ', '.join(bad_add[:4])]
            resp = {'result': result}
            if extra:
                resp.update(extra)
            log('打包+新增完成（%.1fs）：改动 %d 条，新增 %d 条%s' % (
                t_repack, len(valid), st_add.get('added', 0),
                '' if not bad_add else '，读回异常 %d 条' % len(bad_add)))
            resp['verify'] = result.get('errors') or []
            return jsonify(resp)
        result = packcore.axp_repack(pkg, valid, out_path, progress=progress_cb, cancel=state['cancel'])
        t_repack = time.time() - t0
        if result.get('cancelled'):
            log('%s: 用户取消' % pkg_name)
            return jsonify({'cancelled': True})
        resp = {'result': result}
        if extra:
            resp.update(extra)
        if verify_async:
            log('打包写出完成（%.1fs），自检后台进行中...' % t_repack)
            def _run_verify():
                try:
                    tv = time.time()
                    bad = packcore.axp_verify_repack(
                        pkg, out_path, valid, appended=(result.get('appended') or None))
                    if bad:
                        log('自检发现问题：%s' % '; '.join(str(x) for x in bad[:3]))
                    else:
                        log('自检通过（%.1fs）' % (time.time() - tv))
                except Exception as e:
                    log('自检异常：%s' % e)
            threading.Thread(target=_run_verify, daemon=True).start()
            resp['verify'] = None
            resp['verify_pending'] = True
        else:
            t1 = time.time()
            bad = packcore.axp_verify_repack(
                pkg, out_path, valid, appended=(result.get('appended') or None))
            if bad:
                log('打包校验警告: %s' % '; '.join(bad[:3]))
            else:
                log('打包完成，校验通过（打包 %.1fs，自检 %.1fs）' % (t_repack, time.time() - t1))
            resp['verify'] = bad
        return jsonify(resp)
    except Exception as e:
        traceback.print_exc()
        log('打包失败: %s' % e)
        return jsonify({'error': '打包失败: %s' % e}), 500
    finally:
        state['progress'] = {'current': 0, 'total': 0, 'text': ''}

@app.route('/api/repack', methods=['POST'])
def api_repack():
    data = request.json or {}
    pkg_name = data.get('pkg', '')
    file_edits = data.get('edits', {})  # {filename: new_file_path}
    out_path = data.get('out_path', '')
    pkg = state['packages'].get(pkg_name)
    if not pkg:
        return jsonify({'error': '包未加载'}), 404

    edits = {}
    for fname, fpath in file_edits.items():
        idx = packcore.entry_index_of(pkg, fname)
        if idx is None:
            log('  跳过未找到: %s' % fname)
            continue
        with open(fpath, 'rb') as f:
            edits[idx] = f.read()
        log('  替换: %s (idx=%d, %d bytes)' % (fname, idx, len(edits[idx])))

    valid, script_skips = _prepare_edits(pkg, edits)
    if not valid:
        msg = script_skips[0] if script_skips else '没有有效的替换文件'
        return jsonify({'error': msg}), 400

    log('回包 %s -> %s ...' % (pkg_name, out_path))
    return _do_repack_and_verify(pkg, pkg_name, valid, out_path,
                                 extra={'script_skips': script_skips})

# ---------- 文件夹打包回 AXP：导出目录改完整体打回 ----------
@app.route('/api/repack_folder', methods=['POST'])
def api_repack_folder():
    data = request.json or {}
    pkg_name = data.get('pkg', '')
    folder = data.get('folder', '')
    out_path = data.get('out_path', '')
    add_new = bool(data.get('add_new', True))     # 对不上条目的文件：默认真加进包里
    pkg = state['packages'].get(pkg_name)
    if not pkg:
        # 没提前开包也行：请求里带 .axp 路径就当场打开
        pth = data.get('path', '')
        if pth and os.path.isfile(pth) and pth.lower().endswith('.axp'):
            pkg_name = os.path.basename(pth)
            try:
                pkg = axpcore.Package(pth)
                state['packages'][pkg_name] = pkg
                state['pkg_stats'][pkg_name] = pkg.stats()
                log('打包时自动打开 %s' % pkg_name)
            except Exception as e:
                return jsonify({'error': '打开包失败：%s' % e}), 400
    if not pkg:
        return jsonify({'error': '包未加载：先在列表里点开一个包，或把 .axp 路径一起传过来'}), 404
    if not folder or not os.path.isdir(folder):
        return jsonify({'error': '文件夹不存在：%s' % folder}), 404
    stem = os.path.splitext(pkg_name)[0]
    if not out_path:
        out_path = os.path.join(APP_DIR, '解包结果', stem + '_repack.axp')

    log('文件夹打包 %s <- %s ...' % (pkg_name, folder))
    t0 = time.time()
    idx_map = _pkg_key_index(pkg)
    rows = {r.index: r for r in pkg.rows()}

    # 导出时写的清单（文件→size+sha1+条目号）：有它就免解密核对，大包提速的关键
    manifest, mroot = None, folder
    for cand in (folder, os.path.join(folder, stem)):
        mp = os.path.join(cand, '.axp_export_manifest.json')
        try:
            if os.path.isfile(mp):
                with open(mp, encoding='utf-8') as f:
                    man = json.load(f)
                if str(man.get('pkg', '')).lower() == pkg_name.lower():
                    manifest, mroot = man.get('entries') or {}, cand
                    break
        except Exception:
            pass

    allfiles = []
    for root, _dirs, files in os.walk(folder):
        for fn in files:
            if fn == '.axp_export_manifest.json':
                continue
            allfiles.append(os.path.join(root, fn))
    files_seen = len(allfiles)
    log('  核对 %d 个文件（%s）...' % (files_seen, '导出清单' if manifest is not None else '逐条解密'))

    edits, skipped_files, unchanged = {}, [], 0
    unmatched = []
    list_files = 0
    warmed = {} if manifest is None else None   # 无清单时核对完补写，下次直接命中
    for k, full in enumerate(allfiles):
        if files_seen > 40 and (k % 25 == 0 or k == files_seen - 1):
            state['progress'] = {'current': k, 'total': files_seen, 'text': '核对文件'}
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
                    skipped_files.append('%s（读取失败：%s）' % (rel, e))
                    continue
                if len(blob) == rec[0] and hashlib.sha1(blob).hexdigest() == rec[1]:
                    unchanged += 1
                else:
                    edits[rec[2]] = blob
                continue
        # 2) 名字匹配回退（无清单 / 清单里没有的文件）
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
            cand = set()
            for k2, v in idx_map.items():
                if k2.rsplit('/', 1)[-1] == fb:
                    cand.update(v)
            if cand:
                real = sorted(set(ix for ix in cand if ix >= 0))
                if len(real) == 1:
                    hit = real
                elif not real:
                    hit = [-1]
                else:
                    skipped_files.append('%s（有 %d 个条目同名，对不上）' % (rel, len(real)))
                    continue
        if hit is None:
            skipped_files.append(rel)
            unmatched.append((rel, full))
            continue
        real = sorted(set(ix for ix in hit if ix >= 0))
        if not real:
            list_files += 1          # 名字表导出文件：回包自动维护，无需打回
            continue
        try:
            with open(full, 'rb') as f:
                blob = f.read()
        except Exception as e:
            skipped_files.append('%s（读取失败：%s）' % (rel, e))
            continue
        for ix in real:
            exp = _export_equivalent(pkg, rows[ix])
            if exp is not None and blob == exp:
                unchanged += 1        # 没动过：回包走原样搬运，快
                if warmed is not None:
                    warmed[rel.lower()] = [len(blob), hashlib.sha1(blob).hexdigest(), ix]
                continue
            edits[ix] = blob
    log('  核对完成（%.1fs）' % (time.time() - t0))
    if warmed:
        try:
            with open(os.path.join(folder, '.axp_export_manifest.json'), 'w',
                      encoding='utf-8') as f:
                json.dump({'pkg': pkg_name, 'entries': warmed}, f, ensure_ascii=False)
            log('  已补写导出清单（%d 条），下次核对直接命中' % len(warmed))
        except Exception as e:
            log('  导出清单写入失败（不影响打包）：%s' % e)

    valid, script_skips = _prepare_edits(pkg, edits)
    # 对不上条目的文件：默认真正加进包里（axp_add），不再只是"跳过"
    additions = {}
    if add_new and unmatched:
        # axp_add 只认标准游戏包布局（目录区 0x60028 / 数据区 0x160028）；
        # 合成小夹具是紧凑布局，硬加会写飞 —— 这里提前判定并如实说明，不影响正常回包。
        std = (axp_build is not None and pkg.dir_off == axp_build.DIR_OFF
               and pkg.data_off == axp_build.DATA_OFF)
        if not std:
            for rel, _full in unmatched:
                skipped_files.append('%s（包不是标准游戏布局，无法新增条目；改动条目照常回包）' % rel)
            unmatched = []
    if add_new and unmatched:
        stem_l = stem.lower()
        for rel, full in unmatched:
            nm = rel
            parts = nm.split('/', 1)
            if len(parts) == 2 and parts[0] in (stem_l, stem_l + '.axp'):
                nm = parts[1]
            if nm.lower().endswith('.enc'):
                nm = nm[:-4]
            try:
                with open(full, 'rb') as fh:
                    b = fh.read()
            except Exception as e:
                skipped_files.append('%s（读取失败：%s）' % (rel, e))
                continue
            if not b:
                skipped_files.append('%s（空文件，不入包）' % rel)
                continue
            if nm in additions:
                skipped_files.append('%s（与要新增的 %s 同名）' % (rel, nm))
                continue
            additions[nm] = b
            if rel in skipped_files:
                skipped_files.remove(rel)
    for s in (skipped_files[:5] + script_skips[:5]):
        log('  跳过: %s' % s)
    if not valid and not additions:
        msg = '没有可打包的改动：%d 个文件里没找到改动过的条目' % files_seen
        if skipped_files:
            msg += '（%d 个文件对不上名字）' % len(skipped_files)
        if script_skips:
            msg += '；' + script_skips[0]
        log(msg)
        return jsonify({'error': msg}), 400

    log('  改动 %d 条，未改动 %d 条，新增条目 %d 条，跳过 %d 文件 %d 脚本，名字表文件 %d' % (
        len(valid), unchanged, len(additions), len(skipped_files), len(script_skips), list_files))
    return _do_repack_and_verify(pkg, pkg_name, valid, out_path, verify_async=True,
                                 additions=additions or None, extra={
        'matched': len(valid), 'unchanged': unchanged, 'files_seen': files_seen,
        'added_new': len(additions), 'added_names': sorted(additions)[:20],
        'list_files': list_files,
        'skipped_files': skipped_files, 'script_skips': script_skips})

# ---------- 制作补丁（XZIP）：把文件夹里改过/新增的文件按官方格式打成 .xzip 补丁 ----------
@app.route('/api/make_patch', methods=['POST'])
def api_make_patch():
    data = request.json or {}
    pkg_name = data.get('pkg', '')
    folder = data.get('folder', '')
    out_path = data.get('out_path', '')
    pkg = state['packages'].get(pkg_name)
    if not pkg:
        return jsonify({'error': '包未加载'}), 404
    if not folder or not os.path.isdir(folder):
        return jsonify({'error': '文件夹不存在：%s' % folder}), 404
    stem = os.path.splitext(pkg_name)[0]
    if not out_path:
        out_path = os.path.join(APP_DIR, '解包结果', stem + '_补丁.xzip')

    state['cancel'].clear()
    log('制作补丁 %s <- %s ...' % (pkg_name, folder))
    t0 = time.time()

    def progress_cb(done, total, cur):
        # 阶段词由 packcore 传入（核对文件/制作补丁/写出补丁），这里补上 k/n 计数
        state['progress'] = {'current': done, 'total': total,
                             'text': '%s（%d/%d）' % (cur, done, total)}

    try:
        result = packcore.make_xzip_patch(pkg, folder, out_path, include_new=True,
                                          progress=progress_cb, cancel=state['cancel'])
    except ValueError as e:
        log('制作补丁失败: %s' % e)
        return jsonify({'error': str(e)}), 400
    except Exception as e:
        traceback.print_exc()
        log('制作补丁失败: %s' % e)
        return jsonify({'error': '制作补丁失败: %s' % e}), 500
    finally:
        state['progress'] = {'current': 0, 'total': 0, 'text': ''}

    if result.get('cancelled'):
        log('%s: 用户取消' % pkg_name)
        return jsonify({'cancelled': True})
    for s in result['skipped'][:5]:
        log('  跳过: %s' % s)
    log('制作补丁完成：覆盖 %d，新增 %d，未改动 %d，跳过 %d（%.1fs）-> %s' % (
        result['overridden'], result['added'], result['unchanged'],
        len(result['skipped']), time.time() - t0, out_path))
    return jsonify({'out': result['out'], 'overridden': result['overridden'],
                    'added': result['added'], 'skipped': result['skipped'],
                    'errors': result['errors']})

# ---------- 取消 ----------
@app.route('/api/cancel', methods=['POST'])
def api_cancel():
    state['cancel'].set()
    log('用户取消操作')
    return jsonify({'ok': True})

# ---------- 日志/进度 ----------
@app.route('/api/logs')
def api_logs():
    return jsonify({'logs': state['logs'], 'progress': state['progress']})

# ---------- 打开目录 ----------
@app.route('/api/open', methods=['POST'])
def api_open():
    import subprocess
    d = (request.json or {}).get('dir', '')
    if d and os.path.isdir(d):
        os.makedirs(d, exist_ok=True)
        subprocess.Popen(['explorer', d])
        return jsonify({'ok': True})
    return jsonify({'ok': False, 'error': '目录不存在'}), 404

# ---------- 原生对话框（pywebview js_api） ----------
def _one(r):
    """对话框返回可能是 (path,) 元组、字符串或 None，统一成字符串。"""
    if isinstance(r, (list, tuple)):
        return r[0] if r else ''
    return r or ''

class Api:
    """暴露给前端 JS 的 pywebview API（window.pywebview.api.xxx()）。
    约定：返回 '' = 用户取消；返回 None = 对话框不可用/异常（前端会退回手输路径）。"""

    def pick_file(self, kind='all'):
        types = {
            'all': ('AXP 包 (*.axp)', 'XZIP 补丁包 (*.xzip)', '全部文件 (*.*)'),
            'xzip': ('XZIP 补丁包 (*.xzip)', '全部文件 (*.*)'),
            'repack': ('替换文件 (*.*)',),
        }.get(kind, ('全部文件 (*.*)',))
        try:
            return _one(window.create_file_dialog(webview.FileDialog.OPEN, allow_multiple=False, file_types=types))
        except Exception as e:
            log('原生文件对话框不可用: %s' % e)
            return None

    def pick_dir(self, directory=''):
        try:
            return _one(window.create_file_dialog(webview.FileDialog.FOLDER, directory=directory or ''))
        except Exception as e:
            log('原生目录对话框不可用: %s' % e)
            return None

    def pick_save(self, name='output'):
        try:
            return _one(window.create_file_dialog(webview.FileDialog.SAVE, save_filename=name))
        except Exception as e:
            log('原生保存对话框不可用: %s' % e)
            return None

if __name__ == '__main__':
    import threading, webview
    log('AXP 解包工具启动中...')
    t = threading.Thread(target=lambda: app.run(host='127.0.0.1', port=5000, debug=False), daemon=True)
    t.start()
    window = webview.create_window('AXP 解包工具 — 天龙八部',
        'http://127.0.0.1:5000', width=1280, height=820, min_size=(1000, 650),
        js_api=Api())
    webview.start()
