# eBPF Data Collector for Privilege Escalation Detection

Based on: *"Privilege Escalation Detection and Prediction Method Based on eBPF and Machine Learning"* (IEEE 2024)

This tool uses eBPF (via BCC/Python) to monitor privilege-escalation-relevant system calls in real time and produce labeled datasets for the ML detection pipeline.

---

## Prerequisites

```bash
# These should already be installed on your system:
sudo apt install bpfcc-tools python3-bpfcc linux-headers-$(uname -r) gcc
```

Verify:
```bash
dpkg -l | grep bpfcc          # Should show bpfcc-tools, python3-bpfcc
python3 -c "from bcc import BPF; print('BCC OK')"
```

---

## Files

| File | Description |
|------|-------------|
| `collector.py` | Main eBPF data collector (BCC/Python) |
| `simulate_attacks.sh` | Generates attack syscall patterns (label=1) |
| `simulate_normal.sh` | Generates normal syscall patterns (label=0) |
| `merge_data.py` | Merges normal + attack CSVs into one labeled dataset |

---

## How to Run

### Step 1: Collect Normal Data

Open **Terminal 1** — start the collector:
```bash
cd data_collector
sudo python3 collector.py --label normal
```

Open **Terminal 2** — run normal workload:
```bash
cd data_collector
bash simulate_normal.sh
```

After the simulation finishes, go back to Terminal 1 and press **Ctrl+C**.

### Step 2: Collect Attack Data

Open **Terminal 1** — start the collector again:
```bash
sudo python3 collector.py --label attack
```

Open **Terminal 2** — run attack simulation:
```bash
cd data_collector
sudo bash simulate_attacks.sh
```

After the simulation finishes, press **Ctrl+C** in Terminal 1.

### Step 3: Merge into Labeled Dataset

```bash
python3 merge_data.py --output-dir collected_data
```

This produces `collected_data/merged_dataset_<timestamp>.csv` — ready for the ML pipeline.

---

## Output Format

### CSV Columns

| Column | Type | Description |
|--------|------|-------------|
| `timestamp_ns` | int | Kernel timestamp (nanoseconds) |
| `timestamp_human` | string | Human-readable timestamp |
| `pid` | int | Process ID |
| `ppid` | int | Parent Process ID |
| `tid` | int | Thread ID |
| `uid` | int | User ID |
| `gid` | int | Group ID |
| `comm` | string | Command name (COMM) |
| `syscall_nr` | int | Syscall number (x86_64) |
| `syscall_name` | string | Syscall name (e.g., `execve`) |
| `arg1`–`arg3` | int | First three syscall arguments |
| `return_value` | int | Syscall return value |
| `filename` | string | File path (for file-related syscalls) |
| `is_root` | int | 1 if UID=0, else 0 |
| `label` | int | **0 = normal, 1 = attack** |

### JSON Structure

```json
{
  "metadata": {
    "label": "normal",
    "start": "2025-01-01T12:00:00",
    "duration_s": 30.5,
    "total_events": 1234,
    "kernel": "7.0.0-22-generic",
    "hostname": "myhost"
  },
  "events": [ ... ]
}
```

### Summary JSON

```json
{
  "label": "normal",
  "duration_s": 30.5,
  "total_events": 1234,
  "events_per_sec": 40.46,
  "syscall_distribution": {
    "openat": 800,
    "execve": 50,
    "clone": 200,
    "setuid": 5,
    ...
  },
  "unique_pids": 45,
  "unique_uids": 3
}
```

---

## Monitored System Calls

| Syscall | Nr | Why It Matters |
|---------|----|----------------|
| `execve` / `execveat` | 59/322 | Process execution — key indicator of shell spawning |
| `setuid` / `setgid` | 105/106 | Direct privilege changes |
| `setreuid` / `setregid` | 113/114 | Real/effective UID/GID changes |
| `setresuid` / `setresgid` | 117/119 | All three UID/GID values |
| `openat` / `open` | 257/2 | File access — sensitive file reads |
| `clone` | 56 | Process/thread creation |
| `ptrace` | 101 | Process injection / debugging |
| `chmod` / `fchmod` | 90/91 | Permission modification |
| `chown` / `fchown` | 92/93 | Ownership changes |
| `mount` | 165 | Filesystem mounting |
| `mmap` | 9 | Memory mapping (exploit payloads) |
| `prctl` | 157 | Process control |
| `capset` | 125 | Capability changes |
| `unshare` | 272 | Namespace manipulation |

---

## How to Interpret the Output

### Normal Data Characteristics
- Dominated by `openat` (file reads) and `clone` (process creation)
- Few `setuid`/`setgid` calls
- File paths are common locations (`/usr/`, `/lib/`, `/tmp/`)
- Return values mostly 0 (success)

### Attack Data Characteristics
- **Elevated `setuid`/`setgid` frequency** — repeated rapid calls
- **`execve` of shells** (`/bin/sh`, `/bin/bash`) after `setuid`
- **Sensitive file access** — `/etc/shadow`, `/etc/sudoers`, `/proc/kallsyms`
- **SUID bit operations** — `chmod` with mode `4755`, `6755`
- **`ptrace` calls** — process attachment/injection
- **Return value `-1`** (EPERM) on privilege calls — failed escalation attempts

### Key Patterns to Look For
1. **setuid → execve chain**: Classic privilege escalation sequence
2. **Rapid setuid/setgid bursts**: >10 calls in short succession = anomalous
3. **Root UID (0) in non-root processes**: `is_root=1` unexpectedly
4. **Sensitive file opens**: `/etc/shadow`, `/etc/sudoers` from unusual processes

---

## Feeding into ML Pipeline (Part 2)

The merged CSV is designed to feed directly into:
1. **Isolation Forest** — for anomaly scoring
2. **LEA-XGBoost** — for classification/prediction

Feature engineering suggestions from the paper:
- Syscall frequency per PID (sliding window)
- UID change events per time window
- Process-parent relationship chains (PID→PPID)
- File path sensitivity score
- Anomaly score from Isolation Forest
