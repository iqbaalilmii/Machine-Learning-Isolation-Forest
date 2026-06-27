"""
Engram v2 - Per-Process Feature Extractor
============================================
Mengkonversi output mentah Volatility 3 menjadi tabel fitur PER PROSES
(bukan per case seperti feature_extractor.py v1), untuk keperluan
per-case relative anomaly scoring.

Setiap row = satu proses (identified by PID).
"""

import pandas as pd
import numpy as np
from typing import List, Dict, Any


def _safe_get(record: Dict, *keys, default=None):
    """Ambil nilai dari dict dengan mencoba beberapa kemungkinan nama key."""
    for key in keys:
        if key in record:
            return record[key]
    return default


def _is_valid_pid(pid) -> bool:
    """Filter PID yang tidak masuk akal (data corrupt dari scan)."""
    try:
        return 0 <= int(pid) <= 99999
    except (ValueError, TypeError):
        return False


def extract_per_process_features(volatility_results: Dict[str, List[Dict[str, Any]]]) -> pd.DataFrame:
    """
    Entry point utama. Terima dict hasil semua plugin Volatility 3,
    return DataFrame dengan satu row per proses.

    Parameters
    ----------
    volatility_results : dict
        {
            'pslist': [...],
            'dlllist': [...],
            'handles': [...],
            'ldrmodules': [...],
            'malfind': [...],
            'psscan': [...],
        }

    Returns
    -------
    pd.DataFrame dengan kolom:
        pid, name, ppid, n_threads, has_path, wow64,
        n_dlls, n_handles,
        malfind_hits, malfind_rwx_count,
        dll_not_in_load, dll_not_in_init, dll_not_in_mem,
        dll_hidden_ratio,
        is_hidden_process (tidak ada di pslist tapi ada di psscan)
    """
    pslist = volatility_results.get('pslist', [])
    dlllist = volatility_results.get('dlllist', [])
    handles = volatility_results.get('handles', [])
    ldrmodules = volatility_results.get('ldrmodules', [])
    malfind = volatility_results.get('malfind', [])
    psscan = volatility_results.get('psscan', [])

    # ── Base table dari pslist (proses valid saja) ──────────────
    rows = []
    for p in pslist:
        pid = _safe_get(p, 'PID', 'pid')
        if not _is_valid_pid(pid):
            continue

        rows.append({
            'pid': int(pid),
            'name': _safe_get(p, 'ImageFileName', 'imagefilename', default='unknown'),
            'ppid': _safe_get(p, 'PPID', 'ppid', default=0),
            'n_threads': _safe_get(p, 'Threads', 'threads', default=0) or 0,
            'wow64': _safe_get(p, 'Wow64', 'wow64', default=False),
        })

    if not rows:
        return pd.DataFrame()

    df = pd.DataFrame(rows).set_index('pid')

    # ── n_dlls per proses ────────────────────────────────────────
    dll_counts = {}
    for row in dlllist:
        pid = _safe_get(row, 'PID', 'pid')
        if _is_valid_pid(pid):
            pid = int(pid)
            dll_counts[pid] = dll_counts.get(pid, 0) + 1
    df['n_dlls'] = df.index.map(lambda pid: dll_counts.get(pid, 0))

    # ── n_handles per proses ─────────────────────────────────────
    handle_counts = {}
    for row in handles:
        pid = _safe_get(row, 'PID', 'pid')
        if _is_valid_pid(pid):
            pid = int(pid)
            handle_counts[pid] = handle_counts.get(pid, 0) + 1
    df['n_handles'] = df.index.map(lambda pid: handle_counts.get(pid, 0))

    # ── malfind hits per proses ──────────────────────────────────
    malfind_hits = {}
    malfind_rwx = {}
    for row in malfind:
        pid = _safe_get(row, 'PID', 'pid')
        if _is_valid_pid(pid):
            pid = int(pid)
            malfind_hits[pid] = malfind_hits.get(pid, 0) + 1
            protection = str(_safe_get(row, 'Protection', 'protection', default=''))
            if 'EXECUTE_READWRITE' in protection:
                malfind_rwx[pid] = malfind_rwx.get(pid, 0) + 1

    df['malfind_hits'] = df.index.map(lambda pid: malfind_hits.get(pid, 0))
    df['malfind_rwx_count'] = df.index.map(lambda pid: malfind_rwx.get(pid, 0))

    # ── ldrmodules anomaly per proses ────────────────────────────
    ldr_not_in_load = {}
    ldr_not_in_init = {}
    ldr_not_in_mem = {}
    ldr_total_dlls = {}

    for row in ldrmodules:
        pid = _safe_get(row, 'Pid', 'pid', 'PID')
        if not _is_valid_pid(pid):
            continue
        pid = int(pid)

        ldr_total_dlls[pid] = ldr_total_dlls.get(pid, 0) + 1

        if _safe_get(row, 'InLoad', 'inload', default=True) is False:
            ldr_not_in_load[pid] = ldr_not_in_load.get(pid, 0) + 1
        if _safe_get(row, 'InInit', 'ininit', default=True) is False:
            ldr_not_in_init[pid] = ldr_not_in_init.get(pid, 0) + 1
        if _safe_get(row, 'InMem', 'inmem', default=True) is False:
            ldr_not_in_mem[pid] = ldr_not_in_mem.get(pid, 0) + 1

    df['dll_not_in_load'] = df.index.map(lambda pid: ldr_not_in_load.get(pid, 0))
    df['dll_not_in_init'] = df.index.map(lambda pid: ldr_not_in_init.get(pid, 0))
    df['dll_not_in_mem'] = df.index.map(lambda pid: ldr_not_in_mem.get(pid, 0))

    # dll_hidden_ratio: proporsi DLL yang hidden dari SALAH SATU
    # tracking list, terhadap total DLL proses itu
    def _hidden_ratio(pid):
        total = ldr_total_dlls.get(pid, 0)
        if total == 0:
            return 0.0
        hidden = max(
            ldr_not_in_load.get(pid, 0),
            ldr_not_in_init.get(pid, 0),
            ldr_not_in_mem.get(pid, 0),
        )
        return hidden / total

    df['dll_hidden_ratio'] = df.index.map(_hidden_ratio)

    # ── is_hidden_process: ada di psscan tapi tidak di pslist ────
    pslist_pids = set(df.index)
    psscan_pids = set()
    for row in psscan:
        pid = _safe_get(row, 'PID', 'pid')
        if _is_valid_pid(pid):
            psscan_pids.add(int(pid))

    hidden_pids = psscan_pids - pslist_pids

    # Tambahkan proses hidden ini sebagai row baru kalau ada
    # (karena mereka tidak ada di pslist sama sekali, tapi tetap
    # perlu masuk tabel untuk dianalisis/diflag)
    if hidden_pids:
        hidden_rows = []
        for row in psscan:
            pid = _safe_get(row, 'PID', 'pid')
            if _is_valid_pid(pid) and int(pid) in hidden_pids:
                hidden_rows.append({
                    'pid': int(pid),
                    'name': _safe_get(row, 'ImageFileName', 'imagefilename', default='unknown'),
                    'ppid': _safe_get(row, 'PPID', 'ppid', default=0),
                    'n_threads': _safe_get(row, 'Threads', 'threads', default=0) or 0,
                    'wow64': _safe_get(row, 'Wow64', 'wow64', default=False),
                    'n_dlls': dll_counts.get(int(pid), 0),
                    'n_handles': handle_counts.get(int(pid), 0),
                    'malfind_hits': malfind_hits.get(int(pid), 0),
                    'malfind_rwx_count': malfind_rwx.get(int(pid), 0),
                    'dll_not_in_load': 0, 'dll_not_in_init': 0, 'dll_not_in_mem': 0,
                    'dll_hidden_ratio': 0.0,
                })
        if hidden_rows:
            hidden_df = pd.DataFrame(hidden_rows).set_index('pid')
            df = pd.concat([df, hidden_df])

    df['is_hidden_process'] = df.index.map(lambda pid: pid in hidden_pids)

    df = df.reset_index()
    return df


# ──────────────────────────────────────────────────────────────
# Test dengan dummy data
# ──────────────────────────────────────────────────────────────
if __name__ == '__main__':
    dummy_results = {
        'pslist': [
            {'PID': 4, 'PPID': 0, 'ImageFileName': 'System', 'Threads': 105, 'Wow64': False},
            {'PID': 692, 'PPID': 484, 'ImageFileName': 'services.exe', 'Threads': 8, 'Wow64': False},
            {'PID': 5120, 'PPID': 692, 'ImageFileName': 'rundll32.exe', 'Threads': 2, 'Wow64': False},
        ],
        'dlllist': [
            {'PID': 692, 'Name': 'kernel32.dll'},
            {'PID': 692, 'Name': 'ntdll.dll'},
            {'PID': 5120, 'Name': 'kernel32.dll'},
        ],
        'handles': [
            {'PID': 692, 'Type': 'File'},
            {'PID': 692, 'Type': 'Key'},
            {'PID': 5120, 'Type': 'File'},
        ],
        'ldrmodules': [
            {'Pid': 692, 'InLoad': True, 'InInit': True, 'InMem': True},
            {'Pid': 5120, 'InLoad': False, 'InInit': False, 'InMem': True},  # anomali
        ],
        'malfind': [
            {'PID': 5120, 'Protection': 'PAGE_EXECUTE_READWRITE'},
        ],
        'psscan': [
            {'PID': 4, 'PPID': 0, 'ImageFileName': 'System'},
            {'PID': 692, 'PPID': 484, 'ImageFileName': 'services.exe'},
            {'PID': 5120, 'PPID': 692, 'ImageFileName': 'rundll32.exe'},
            {'PID': 6916, 'PPID': 692, 'ImageFileName': 'hidden_proc.exe'},  # hidden!
        ],
    }

    df = extract_per_process_features(dummy_results)
    print(df.to_string())
    print(f"\nTotal proses: {len(df)}")
    print(f"Proses hidden: {df['is_hidden_process'].sum()}")
