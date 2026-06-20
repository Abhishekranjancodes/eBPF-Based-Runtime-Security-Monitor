#!/usr/bin/env python3
"""
eBPF System Call Data Collector for Privilege Escalation Detection.

Based on: "Privilege Escalation Detection and Prediction Method
Based on eBPF and Machine Learning" (IEEE 2024)

Uses BCC to attach eBPF tracepoints on privilege-escalation-relevant
system calls. Outputs collected data in CSV and JSON formats.

Usage:
    sudo python3 collector.py --label normal   # Collect normal data
    sudo python3 collector.py --label attack   # Collect attack data
    Press Ctrl+C to stop.
"""

from bcc import BPF
import ctypes as ct
import os
import sys
import signal
import json
import csv
import time
import argparse
from datetime import datetime
from collections import defaultdict

# ── x86_64 Syscall Numbers ──────────────────────────────────────────
SYSCALL_MAP = {
    59: "execve",     56: "clone",      2: "open",
    257: "openat",    105: "setuid",    106: "setgid",
    113: "setreuid",  114: "setregid",  117: "setresuid",
    119: "setresgid", 101: "ptrace",    9: "mmap",
    90: "chmod",      91: "fchmod",     92: "chown",
    93: "fchown",     165: "mount",     322: "execveat",
    157: "prctl",     125: "capset",    272: "unshare",
}

# ── BPF C Program ───────────────────────────────────────────────────
BPF_SRC = r"""
#include <uapi/linux/ptrace.h>
#include <linux/sched.h>

#define FNAME_LEN 256

/* Entry info stored between sys_enter and sys_exit */
struct entry_t {
    u64 ts;
    int nr;
    int _pad;
    long a1;
    long a2;
    long a3;
    char fname[FNAME_LEN];
};

/* Event sent to userspace */
struct event_t {
    u64 ts;
    u32 pid;
    u32 ppid;
    u32 uid;
    u32 gid;
    u32 tid;
    int nr;
    long ret;
    long a1;
    long a2;
    long a3;
    char comm[TASK_COMM_LEN];
    char fname[FNAME_LEN];
};

BPF_HASH(entries, u64, struct entry_t);
BPF_PERCPU_ARRAY(scratch, struct event_t, 1);
BPF_PERF_OUTPUT(events);

static __always_inline int is_monitored(int nr) {
    switch (nr) {
        case 59: case 56: case 2: case 257:
        case 105: case 106: case 113: case 114:
        case 117: case 119: case 101: case 9:
        case 90: case 91: case 92: case 93:
        case 165: case 322: case 157: case 125:
        case 272:
            return 1;
        default:
            return 0;
    }
}

TRACEPOINT_PROBE(raw_syscalls, sys_enter) {
    int nr = args->id;
    if (!is_monitored(nr))
        return 0;

    u64 pid_tid = bpf_get_current_pid_tgid();
    u32 pid = pid_tid >> 32;

    /* Skip our own process */
    if (pid == SELF_PID)
        return 0;

    struct entry_t e = {};
    e.ts = bpf_ktime_get_ns();
    e.nr = nr;
    e.a1 = (long)args->args[0];
    e.a2 = (long)args->args[1];
    e.a3 = (long)args->args[2];

    /* Read filename for file-related syscalls */
    switch (nr) {
        case 59:  /* execve: filename = arg0 */
        case 2:   /* open:   filename = arg0 */
        case 90:  /* chmod:  filename = arg0 */
        case 92:  /* chown:  filename = arg0 */
            bpf_probe_read_user_str(e.fname, sizeof(e.fname),
                                    (void *)args->args[0]);
            break;
        case 257: /* openat:   filename = arg1 */
        case 322: /* execveat: filename = arg1 */
            bpf_probe_read_user_str(e.fname, sizeof(e.fname),
                                    (void *)args->args[1]);
            break;
        case 165: /* mount: source = arg0 */
            bpf_probe_read_user_str(e.fname, sizeof(e.fname),
                                    (void *)args->args[0]);
            break;
    }

    entries.update(&pid_tid, &e);
    return 0;
}

TRACEPOINT_PROBE(raw_syscalls, sys_exit) {
    u64 pid_tid = bpf_get_current_pid_tgid();

    struct entry_t *e = entries.lookup(&pid_tid);
    if (!e)
        return 0;

    int zero = 0;
    struct event_t *evt = scratch.lookup(&zero);
    if (!evt) {
        entries.delete(&pid_tid);
        return 0;
    }

    /* Fill event from entry + current context */
    evt->ts  = e->ts;
    evt->nr  = e->nr;
    evt->a1  = e->a1;
    evt->a2  = e->a2;
    evt->a3  = e->a3;
    evt->ret = args->ret;

    evt->pid = pid_tid >> 32;
    evt->tid = (u32)pid_tid;

    u64 uid_gid = bpf_get_current_uid_gid();
    evt->uid = (u32)uid_gid;
    evt->gid = (u32)(uid_gid >> 32);

    bpf_get_current_comm(&evt->comm, sizeof(evt->comm));
    __builtin_memcpy(evt->fname, e->fname, sizeof(evt->fname));

    /* Read PPID from task_struct */
    struct task_struct *task = (struct task_struct *)bpf_get_current_task();
    struct task_struct *parent;
    bpf_probe_read_kernel(&parent, sizeof(parent), &task->real_parent);
    bpf_probe_read_kernel(&evt->ppid, sizeof(evt->ppid), &parent->tgid);

    events.perf_submit(args, evt, sizeof(*evt));
    entries.delete(&pid_tid);
    return 0;
}
"""

# ── Python ctypes struct (must match BPF event_t exactly) ───────────
class Event(ct.Structure):
    _fields_ = [
        ("ts",    ct.c_uint64),
        ("pid",   ct.c_uint32),
        ("ppid",  ct.c_uint32),
        ("uid",   ct.c_uint32),
        ("gid",   ct.c_uint32),
        ("tid",   ct.c_uint32),
        ("nr",    ct.c_int32),
        ("ret",   ct.c_long),
        ("a1",    ct.c_long),
        ("a2",    ct.c_long),
        ("a3",    ct.c_long),
        ("comm",  ct.c_char * 16),
        ("fname", ct.c_char * 256),
    ]


# ── CSV column headers ──────────────────────────────────────────────
CSV_HEADERS = [
    "timestamp_ns", "timestamp_human", "pid", "ppid", "tid",
    "uid", "gid", "comm", "syscall_nr", "syscall_name",
    "arg1", "arg2", "arg3", "return_value", "filename",
    "is_root", "label",
]


class DataCollector:
    """Manages BPF attachment, event processing, and file output."""

    def __init__(self, label: str, output_dir: str):
        self.label = 0 if label == "normal" else 1
        self.label_str = label
        self.output_dir = output_dir
        os.makedirs(output_dir, exist_ok=True)

        ts = datetime.now().strftime("%Y%m%d_%H%M%S")
        tag = label
        self.csv_path = os.path.join(output_dir, f"syscalls_{tag}_{ts}.csv")
        self.json_path = os.path.join(output_dir, f"syscalls_{tag}_{ts}.json")
        self.summary_path = os.path.join(output_dir, f"summary_{tag}_{ts}.json")

        self.events_list = []
        self.count = 0
        self.start = None
        self.running = True
        self.stats = defaultdict(int)
        self.csv_file = None
        self.csv_writer = None

    # ── CSV setup ───────────────────────────────────────────────────
    def _open_csv(self):
        self.csv_file = open(self.csv_path, "w", newline="", buffering=1)
        self.csv_writer = csv.writer(self.csv_file)
        self.csv_writer.writerow(CSV_HEADERS)

    # ── Event callback ──────────────────────────────────────────────
    def _on_event(self, cpu, data, size):
        e = ct.cast(data, ct.POINTER(Event)).contents
        name = SYSCALL_MAP.get(e.nr, f"syscall_{e.nr}")
        comm = e.comm.decode("utf-8", errors="replace").rstrip("\x00")
        fname = e.fname.decode("utf-8", errors="replace").rstrip("\x00")
        ts_human = datetime.now().strftime("%Y-%m-%d %H:%M:%S.%f")
        is_root = 1 if e.uid == 0 else 0

        row = [
            e.ts, ts_human, e.pid, e.ppid, e.tid,
            e.uid, e.gid, comm, e.nr, name,
            e.a1, e.a2, e.a3, e.ret, fname,
            is_root, self.label,
        ]
        self.csv_writer.writerow(row)

        record = dict(zip(CSV_HEADERS, row))
        self.events_list.append(record)

        self.count += 1
        self.stats[name] += 1

        # Print important events always; others every 25th
        important = name in ("execve", "setuid", "setgid", "setreuid",
                             "setresuid", "ptrace", "mount", "capset",
                             "unshare", "chmod", "chown")
        if important or self.count % 25 == 0:
            flag = " ★" if important else ""
            print(f"  [{ts_human}] {name:<12} PID={e.pid:<6} "
                  f"UID={e.uid} ret={e.ret} "
                  f"{fname[:60]}{flag}  [{comm}]")

    # ── Signal handler ──────────────────────────────────────────────
    def _stop(self, *_):
        print("\n[*] Stopping collection...")
        self.running = False

    # ── Main loop ───────────────────────────────────────────────────
    def run(self):
        if os.geteuid() != 0:
            print("[ERROR] Must run as root: sudo python3 collector.py ...")
            sys.exit(1)

        print("=" * 65)
        print("  eBPF Privilege-Escalation Data Collector")
        print("  Label: " + self.label_str.upper())
        print("=" * 65)

        # Inject our PID into BPF source to self-filter
        src = BPF_SRC.replace("SELF_PID", str(os.getpid()))

        print("[*] Loading eBPF program...")
        try:
            b = BPF(text=src)
        except Exception as ex:
            print(f"[ERROR] BPF load failed: {ex}")
            sys.exit(1)

        print(f"[*] Monitoring {len(SYSCALL_MAP)} syscalls")
        print(f"[*] CSV → {self.csv_path}")
        print(f"[*] JSON → {self.json_path}")
        print("[*] Press Ctrl+C to stop.\n")

        self._open_csv()
        b["events"].open_perf_buffer(self._on_event, page_cnt=128)

        signal.signal(signal.SIGINT, self._stop)
        signal.signal(signal.SIGTERM, self._stop)

        self.start = time.time()

        while self.running:
            try:
                b.perf_buffer_poll(timeout=100)
            except KeyboardInterrupt:
                break

        elapsed = time.time() - self.start
        self._finalise(elapsed)

    # ── Write JSON + summary ────────────────────────────────────────
    def _finalise(self, elapsed):
        if self.csv_file:
            self.csv_file.close()

        print(f"[*] Writing {len(self.events_list)} events to JSON...")
        with open(self.json_path, "w") as f:
            json.dump({
                "metadata": {
                    "label": self.label_str,
                    "start": datetime.fromtimestamp(self.start).isoformat(),
                    "duration_s": round(elapsed, 2),
                    "total_events": self.count,
                    "kernel": os.uname().release,
                    "hostname": os.uname().nodename,
                },
                "events": self.events_list,
            }, f, indent=2, default=str)

        summary = {
            "label": self.label_str,
            "duration_s": round(elapsed, 2),
            "total_events": self.count,
            "events_per_sec": round(self.count / max(elapsed, 0.001), 2),
            "syscall_distribution": dict(self.stats),
            "unique_pids": len({e["pid"] for e in self.events_list}),
            "unique_uids": len({e["uid"] for e in self.events_list}),
            "files": {"csv": self.csv_path, "json": self.json_path},
        }
        with open(self.summary_path, "w") as f:
            json.dump(summary, f, indent=2)

        print("\n" + "=" * 65)
        print("  Collection Summary")
        print("=" * 65)
        print(f"  Label:          {self.label_str}")
        print(f"  Duration:       {elapsed:.1f}s")
        print(f"  Total events:   {self.count}")
        print(f"  Events/sec:     {summary['events_per_sec']}")
        print(f"  Unique PIDs:    {summary['unique_pids']}")
        print(f"  Unique UIDs:    {summary['unique_uids']}")
        print()
        print("  Syscall breakdown:")
        for name, cnt in sorted(self.stats.items(), key=lambda x: -x[1]):
            pct = cnt / max(self.count, 1) * 100
            bar = "█" * int(pct / 2)
            print(f"    {name:<14} {cnt:>7}  ({pct:5.1f}%) {bar}")
        print()
        print(f"  CSV  → {self.csv_path}")
        print(f"  JSON → {self.json_path}")
        print(f"  Summary → {self.summary_path}")
        print("=" * 65)


# ── Entry point ─────────────────────────────────────────────────────
if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="eBPF syscall collector for privilege escalation detection"
    )
    parser.add_argument(
        "--label", choices=["normal", "attack"], default="normal",
        help="Label for collected data: 'normal' (0) or 'attack' (1)"
    )
    parser.add_argument(
        "--output-dir", default="collected_data",
        help="Directory for output files (default: collected_data)"
    )
    args = parser.parse_args()

    collector = DataCollector(label=args.label, output_dir=args.output_dir)
    collector.run()
