#!/bin/bash
# ─────────────────────────────────────────────────────────────────────
# Normal Workload Simulation Script for eBPF Data Collection
#
# Generates typical, non-malicious syscall patterns so the
# collector captures them with label=normal.
#
# Run in a SEPARATE terminal while collector.py --label normal runs.
#
# Usage:  bash simulate_normal.sh
# ─────────────────────────────────────────────────────────────────────

echo "============================================="
echo "  Normal Workload Simulator"
echo "============================================="
echo

sleep 2  # Give collector time to attach

# ── 1. Regular File Operations ──────────────────────────────────────
echo "[1/6] Performing regular file operations..."

ls -la /tmp/ > /dev/null 2>&1
ls -la /home/ > /dev/null 2>&1
ls -la /var/log/ > /dev/null 2>&1
cat /etc/hostname 2>/dev/null
cat /etc/os-release 2>/dev/null
cat /etc/timezone 2>/dev/null || true
wc -l /etc/passwd 2>/dev/null

echo "  Done."
echo

# ── 2. Standard Process Creation ───────────────────────────────────
echo "[2/6] Creating standard processes..."

echo "Hello World" | grep "Hello" > /dev/null
date > /dev/null
whoami > /dev/null
uname -a > /dev/null
id > /dev/null
ps aux > /dev/null 2>&1
uptime > /dev/null

echo "  Done."
echo

# ── 3. Normal File Read/Write ──────────────────────────────────────
echo "[3/6] Normal file read/write operations..."

TMPDIR=$(mktemp -d /tmp/pe_normal_sim.XXXXXX)
trap "rm -rf $TMPDIR" EXIT

for i in $(seq 1 10); do
    echo "This is test line $i" > "$TMPDIR/testfile_$i.txt"
done

cat "$TMPDIR"/testfile_*.txt > "$TMPDIR/combined.txt"
wc -l "$TMPDIR/combined.txt" > /dev/null
grep "test line 5" "$TMPDIR/combined.txt" > /dev/null
sort "$TMPDIR/combined.txt" > "$TMPDIR/sorted.txt"
rm "$TMPDIR"/testfile_*.txt

echo "  Done."
echo

# ── 4. Directory Traversal ─────────────────────────────────────────
echo "[4/6] Normal directory traversal..."

find /usr/bin -maxdepth 1 -name "*.sh" 2>/dev/null | head -5 > /dev/null
find /etc -maxdepth 1 -type f 2>/dev/null | head -10 > /dev/null
du -sh /tmp 2>/dev/null > /dev/null

echo "  Done."
echo

# ── 5. Normal Process Fork/Wait ────────────────────────────────────
echo "[5/6] Normal process fork/wait patterns..."

for i in $(seq 1 5); do
    (sleep 0.1 && echo "subprocess $i" > /dev/null) &
done
wait

# Pipe chain (creates multiple processes)
cat /etc/passwd 2>/dev/null | grep "root" | wc -l > /dev/null

echo "  Done."
echo

# ── 6. Safe System Queries ─────────────────────────────────────────
echo "[6/6] Standard system queries..."

df -h > /dev/null 2>&1
free -m > /dev/null 2>&1
mount 2>/dev/null | head -3 > /dev/null
env > /dev/null 2>&1
stat /etc/passwd > /dev/null 2>&1

echo "  Done."
echo

echo "============================================="
echo "  Normal workload simulation complete."
echo "  Switch to the collector terminal and"
echo "  press Ctrl+C to stop data collection."
echo "============================================="
