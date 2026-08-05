import socket, struct, zstandard as zstd, hashlib, json, sys, os
from Crypto.Cipher import AES
try: import socks; _HAS_SOCKS = True
except: _HAS_SOCKS = False

AES_KEY = bytes.fromhex('f5a193d50ade553e9835595f5cd75ddd')
AES_IV = b'\x00' * 16
CLIENT_VERSION = '2.1.88.1202.1'
CHANNEL = 'and_usa'
GLOBAL_SERVERS = [
    ('global-login.ml.youngjoygame.com', 30021),
    ('login.ml.youngjoygame.com', 30021),
    ('login-mlus.mproject.skystone.games', 30021),
]

def _parse_proxy(proxy_str):
    """Parse proxy string in any of these formats:
       user:pass@host:port | host:port:user:pass | host:port | host:user:pass | host
    """
    if not proxy_str: return None
    s = proxy_str.strip()
    for prefix in ['socks5://', 'socks4://', 'http://', 'https://', 'socks5h://']:
        if s.startswith(prefix):
            s = s[len(prefix):]; break
    if '@' in s:
        auth, rest = s.rsplit('@', 1)
        user, pw = auth.split(':', 1) if ':' in auth else (auth, '')
        host, port = rest.split(':', 1) if ':' in rest else (rest, '823')
        return {'host': host, 'port': int(port), 'user': user, 'pw': pw}
    parts = s.split(':')
    if len(parts) >= 4:
        return {'host': parts[0], 'port': int(parts[1]), 'user': parts[2], 'pw': ':'.join(parts[3:])}
    if len(parts) == 3:
        a, b, c = parts
        if a.isdigit() and not b.isdigit():
            return None
        if b.isdigit():
            return {'host': a, 'port': int(b), 'user': c, 'pw': ''}
        return {'host': a, 'port': 823, 'user': b, 'pw': c}
    if len(parts) == 2:
        a, b = parts
        if b.isdigit():
            return {'host': a, 'port': int(b), 'user': '', 'pw': ''}
        return {'host': a, 'port': 823, 'user': b, 'pw': ''}
    if parts[0].isdigit():
        return None
    return {'host': s, 'port': 823, 'user': '', 'pw': ''}

def _make_socket(proxy=None):
    if not proxy:
        return socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    if _HAS_SOCKS:
        try:
            s = socks.socksocket()
            s.set_proxy(socks.SOCKS5, proxy['host'], proxy['port'],
                        username=proxy.get('user','') or None,
                        password=proxy.get('pw','') or None)
            return s
        except Exception:
            pass
    return socket.socket(socket.AF_INET, socket.SOCK_STREAM)

def _proxy_connect(s, target_host, target_port, proxy):
    if not proxy:
        s.connect((target_host, target_port))
        return
    ph = proxy['host']; pp = proxy['port']
    s.connect((ph, pp))
    if proxy.get('user'):
        import base64
        auth = base64.b64encode(f"{proxy['user']}:{proxy['pw']}".encode()).decode()
        req = f"CONNECT {target_host}:{target_port} HTTP/1.1\r\nHost: {target_host}:{target_port}\r\nProxy-Authorization: Basic {auth}\r\n\r\n"
    else:
        req = f"CONNECT {target_host}:{target_port} HTTP/1.1\r\nHost: {target_host}:{target_port}\r\n\r\n"
    s.send(req.encode())
    resp = s.recv(4096)
    if b'200' not in resp[:16]:
        raise ConnectionError(f"Proxy CONNECT failed: {resp[:100].decode(errors='ignore')}")

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
    if dtype in (0, 1):
        val, offset = _read_varint(data, offset)
        return tag, (-val if dtype == 1 else val), offset
    elif dtype == 2:
        length, offset = _read_varint(data, offset)
        raw = data[offset:offset+length]; offset += length
        return tag, struct.unpack('<f', raw)[0], offset
    elif dtype == 3:
        length, offset = _read_varint(data, offset)
        raw = data[offset:offset+length]; offset += length
        return tag, struct.unpack('<d', raw)[0], offset
    elif dtype == 4:
        length, offset = _read_varint(data, offset)
        raw = data[offset:offset+length]; offset += length
        try: return tag, raw.decode('utf-8'), offset
        except: return tag, raw, offset
    elif dtype == 5:
        length, offset = _read_varint(data, offset)
        items = []
        for _ in range(length):
            _, item, offset = _unpack_field(data, offset)
            items.append(item)
        return tag, items, offset
    elif dtype == 6:
        length, offset = _read_varint(data, offset)
        d = {}
        for _ in range(length):
            _, k, offset = _unpack_field(data, offset)
            _, v, offset = _unpack_field(data, offset)
            d[k] = v
        return tag, d, offset
    elif dtype == 7:
        sub = {}
        while offset < len(data):
            if data[offset] >> 4 == 8: offset += 1; break
            st, sv, offset = _unpack_field(data, offset)
            sub[st] = sv
        return tag, sub, offset
    return tag, None, offset

def parse_sdp(data):
    result = {}
    if not data: return result
    offset = 0
    if data[0] >> 4 == 7: offset = 1
    while offset < len(data):
        header = data[offset]
        if header >> 4 == 8: offset += 1; break
        tag, val, offset = _unpack_field(data, offset)
        result[tag] = val
    return result

def decompress(body, ctype):
    if ctype == 16: return zstd.decompress(body)
    if ctype == 2:
        c = AES.new(AES_KEY, AES.MODE_CBC, iv=AES_IV)
        return c.decrypt(body).rstrip(b'\x00')
    if ctype == 18:
        c = AES.new(AES_KEY, AES.MODE_CBC, iv=AES_IV)
        return zstd.decompress(c.decrypt(body).rstrip(b'\x00'))
    return body

def device_login(device_id, host=None, port=30021, timeout=10, proxy=None):
    servers = [(host, port)] if host else GLOBAL_SERVERS
    for h, p in servers:
        result = _try_login(device_id, h, p, timeout, proxy=proxy)
        if result is not None and '_error' not in result:
            return result
    return None

def _try_login(device_id, host, port, timeout, proxy=None):
    s = _make_socket(proxy)
    s.settimeout(timeout)
    try:
        _proxy_connect(s, host, port, proxy)
        parts = device_id.split('_')
        platform = parts[0]
        if platform == 'ios':
            ios_uuid = parts[1]
            imei = hashlib.md5(ios_uuid.encode()).hexdigest()
            aid = ''
            adv = ios_uuid
        elif len(parts) >= 4:
            imei, aid, adv = parts[1], parts[2], '_'.join(parts[3:])
        elif len(parts) == 3:
            mid = parts[1]
            imei = mid[:32]; aid = mid[32:48] if len(mid) >= 48 else ''; adv = mid[48:] if len(mid) > 48 else parts[2]
        elif len(parts) == 2:
            info = parts[1]
            imei = info[:32]; aid = info[32:48] if len(info) >= 48 else ''; adv = info[48:] if len(info) > 48 else ''
        else:
            imei, aid, adv = device_id, '', ''

        auth_str = f'gps_adid={adv}&android_id={aid}&device_unique_id={imei}'
        inner = build_sdp({0: device_id, 1: auth_str, 2: CLIENT_VERSION, 3: CHANNEL, 4: 'en'})
        outer = build_sdp({0: 1, 1: 1, 5: inner})
        compressed = zstd.compress(outer)
        flags = (len(compressed) + 4) | (16 << 24)
        s.send(flags.to_bytes(4, 'big') + compressed)

        q = b''
        while len(q) < 4:
            d = s.recv(4096)
            if not d: return None
            q += d
        fr = struct.unpack('>I', q[:4])[0]
        size, ctype = fr & 0xFFFFFF, fr >> 24
        while len(q) < size:
            d = s.recv(4096)
            if not d: break
            q += d
        decoded = decompress(q[4:size], ctype)
        outer_f = parse_sdp(decoded)
        raw = outer_f.get(6) or outer_f.get(5)
        if isinstance(raw, int):
            return {'_error': raw}
        if isinstance(raw, (bytes, str)):
            buf = raw if isinstance(raw, bytes) else raw.encode()
            inner_f = parse_sdp(buf)
            return {
                'device_id': device_id,
                'account_id': inner_f.get(0),
                'session_key': str(inner_f.get(1)) if inner_f.get(1) else '',
                'zone_id': inner_f.get(2) if isinstance(inner_f.get(2), int) else (inner_f.get(2, {}).get(0, 0) if isinstance(inner_f.get(2), dict) else 0),
                'creation_ts': inner_f.get(19, 0),
                'server': f'{host}:{port}'
            }
        return None
    except socket.timeout: return None
    except ConnectionError as e: return {'_proxy_error': str(e)[:80]}
    except Exception: return None
    finally:
        try: s.close()
        except: pass

def query_game_server(account_id, session_key, zone_id, timeout=5):
    """Query game server address — proves account is actually live."""
    servers = GLOBAL_SERVERS
    for host, port in servers:
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(timeout)
            s.connect((host, port))
            inner = build_sdp({0: int(account_id), 1: session_key, 2: CLIENT_VERSION, 5: zone_id, 6: CHANNEL})
            outer = build_sdp({0: 5, 1: 2, 5: inner})
            compressed = zstd.compress(outer)
            flags = (len(compressed) + 4) | (16 << 24)
            s.send(flags.to_bytes(4, 'big') + compressed)
            q = b''
            while len(q) < 4:
                d = s.recv(4096)
                if not d: break
                q += d
            if len(q) < 4:
                s.close()
                continue
            fr = struct.unpack('>I', q[:4])[0]
            size, ctype = fr & 0xFFFFFF, fr >> 24
            while len(q) < size:
                d = s.recv(4096)
                if not d: break
                q += d
            if len(q) < 4:
                s.close()
                continue
            decoded = decompress(q[4:size], ctype)
            outer_f = parse_sdp(decoded)
            raw = outer_f.get(6) or outer_f.get(5)
            if isinstance(raw, (bytes, str)):
                buf = raw if isinstance(raw, bytes) else raw.encode()
                inner_f = parse_sdp(buf)
                gs = inner_f.get(1, '')
                if gs and ':' in str(gs):
                    s.close()
                    return str(gs)
            s.close()
        except:
            try: s.close()
            except: pass
    return None

def quick_check(device_id, timeout=5):
    """Like device_login but returns ('hit', dict) or ('error', code) or ('timeout',) or ('fail', reason)."""
    for host, port in GLOBAL_SERVERS:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(timeout)
        try:
            s.connect((host, port))
            parts = device_id.split('_')
            if len(parts) == 2:
                info = parts[1]; imei = info[:32]; aid = info[32:48] if len(info) >= 48 else ''; adv = info[48:] if len(info) > 48 else ''
            else:
                imei, aid, adv = parts[1], parts[2], '_'.join(parts[3:])
            auth_str = f'gps_adid={adv}&android_id={aid}&device_unique_id={imei}'
            inner = build_sdp({0: device_id, 1: auth_str, 2: CLIENT_VERSION, 3: CHANNEL, 4: 'en'})
            outer = build_sdp({0: 1, 1: 1, 5: inner})
            compressed = zstd.compress(outer)
            flags = (len(compressed) + 4) | (16 << 24)
            s.send(flags.to_bytes(4, 'big') + compressed)
            q = b''
            while len(q) < 4:
                d = s.recv(4096)
                if not d: s.close(); continue
                q += d
            fr = struct.unpack('>I', q[:4])[0]
            size, ctype = fr & 0xFFFFFF, fr >> 24
            while len(q) < size:
                d = s.recv(4096)
                if not d: break
                q += d
            decoded = decompress(q[4:size], ctype)
            outer_f = parse_sdp(decoded)
            raw = outer_f.get(6) or outer_f.get(5)
            if isinstance(raw, (bytes, str)):
                buf = raw if isinstance(raw, bytes) else raw.encode()
                inner_f = parse_sdp(buf)
                acc = inner_f.get(0)
                if acc:
                    s.close()
                    return ('hit', {
                        'device_id': device_id, 'account_id': acc,
                        'session_key': str(inner_f.get(1)) if inner_f.get(1) else '',
                        'zone_id': inner_f.get(2) if isinstance(inner_f.get(2), int) else (inner_f.get(2, {}).get(0, 0) if isinstance(inner_f.get(2), dict) else 0),
                        'creation_ts': inner_f.get(19, 0),
                        'server': f'{host}:{port}'
                    })
                s.close()
                return ('no_account',)
            if isinstance(raw, int):
                s.close()
                return ('error', raw)
            s.close()
            return ('no_data',)
        except socket.timeout:
            s.close(); continue
        except Exception:
            s.close(); continue
        finally:
            try: s.close()
            except: pass
    return ('timeout',)

def main():
    import argparse
    parser = argparse.ArgumentParser(description='MLBB device login - authenticate using device ID')
    parser.add_argument('device_id', help='Device ID (and_xxx or ios_xxx)')
    parser.add_argument('--server', help='Custom login server (host:port)')
    parser.add_argument('--timeout', type=int, default=10, help='Connection timeout')
    args = parser.parse_args()

    host, port = None, 30021
    if args.server and ':' in args.server:
        host, port = args.server.split(':')
        port = int(port)
    elif args.server:
        host = args.server

    print(f"Logging in with device ID: {args.device_id[:50]}...")
    result = device_login(args.device_id, host, port, args.timeout)

    if result:
        print(f"\n{'='*50}")
        print(f"  Login successful!")
        print(f"  Account ID:  {result['account_id']}")
        print(f"  Session Key: {result['session_key'][:40]}...")
        print(f"  Zone ID:     {result['zone_id']}")
        print(f"  Server:      {result['server']}")
        print(f"{'='*50}")
        print(f"\nFull result: {json.dumps(result, indent=2)}")
    else:
        print("Login failed - no response from any server")
        sys.exit(1)

if __name__ == '__main__':
    main()
