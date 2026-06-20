#!/bin/bash
# ─────────────────────────────────────────────────────────────────────
# Attack Simulation Script for eBPF Data Collection
#
# Generates privilege-escalation-like syscall patterns so the
# collector captures them with label=attack.
#
# Run in a SEPARATE terminal while collector.py --label attack runs.
#
# Usage:  sudo bash simulate_attacks.sh
# ─────────────────────────────────────────────────────────────────────
set -e

WORKDIR=$(mktemp -d /tmp/pe_attack_sim.XXXXXX)
trap "rm -rf $WORKDIR" EXIT

echo "============================================="
echo "  Privilege Escalation Attack Simulator"
echo "  Working directory: $WORKDIR"
echo "============================================="
echo

sleep 2  # Give collector time to attach

# ── 1. SUID Program Exploitation Pattern ────────────────────────────
echo "[1/5] Simulating SUID privilege escalation pattern..."

cat > "$WORKDIR/suid_exploit.c" << 'CEOF'
#include <stdio.h>
#include <unistd.h>
#include <sys/types.h>

int main() {
    printf("[attack] Attempting setuid(0)...\n");
    int ret = setuid(0);
    printf("[attack] setuid(0) returned: %d\n", ret);

    ret = setgid(0);
    printf("[attack] setgid(0) returned: %d\n", ret);

    /* Try to exec a shell (mimics SUID exploitation) */
    char *args[] = {"/bin/sh", "-c", "echo 'escalation attempt'; id; whoami", NULL};
    execve("/bin/sh", args, NULL);
    return 0;
}
CEOF

gcc -o "$WORKDIR/suid_exploit" "$WORKDIR/suid_exploit.c" 2>/dev/null
chmod u+s "$WORKDIR/suid_exploit"
"$WORKDIR/suid_exploit" || true

echo "  Done."
echo

# ── 2. Rapid setuid/setgid Chain (Illegal Syscall Chain) ───────────
echo "[2/5] Simulating rapid setuid/setgid syscall chain..."

cat > "$WORKDIR/rapid_chain.c" << 'CEOF'
#include <stdio.h>
#include <unistd.h>
#include <sys/types.h>

int main() {
    printf("[attack] Starting rapid privilege syscall chain...\n");
    for (int i = 0; i < 50; i++) {
        setuid(0);
        setgid(0);
        setreuid(0, 0);
        setregid(0, 0);
    }
    printf("[attack] Rapid chain complete (200 calls).\n");

    /* Follow up with execve — classic escalation pattern */
    char *args[] = {"/bin/echo", "chain-execve-done", NULL};
    execve("/bin/echo", args, NULL);
    return 0;
}
CEOF

gcc -o "$WORKDIR/rapid_chain" "$WORKDIR/rapid_chain.c" 2>/dev/null
"$WORKDIR/rapid_chain" || true

echo "  Done."
echo

# ── 3. Sensitive File Access ────────────────────────────────────────
echo "[3/5] Simulating suspicious file access patterns..."

# Read sensitive files
cat /etc/shadow 2>/dev/null || true
cat /etc/sudoers 2>/dev/null || true
cat /etc/gshadow 2>/dev/null || true
ls -la /root/ 2>/dev/null || true

# Try to open sensitive kernel files
cat /proc/kallsyms 2>/dev/null | head -5 || true
cat /proc/kcore 2>/dev/null | head -c 1 || true

# Write to sensitive location (will fail for non-root, generates syscall)
echo "test" > /etc/pe_test_file 2>/dev/null && rm /etc/pe_test_file 2>/dev/null || true

echo "  Done."
echo

# ── 4. Suspicious chmod/chown Operations ───────────────────────────
echo "[4/5] Simulating suspicious permission changes..."

touch "$WORKDIR/fake_suid_binary"
chmod 4755 "$WORKDIR/fake_suid_binary" 2>/dev/null || true
chmod 2755 "$WORKDIR/fake_suid_binary" 2>/dev/null || true
chmod 6755 "$WORKDIR/fake_suid_binary" 2>/dev/null || true
chown root:root "$WORKDIR/fake_suid_binary" 2>/dev/null || true

# Attempt to change ownership of system files
chown root:root /tmp/.test_chown 2>/dev/null || true
chmod 777 /tmp/.test_chown 2>/dev/null || true

echo "  Done."
echo

# ── 5. Process Injection / ptrace Pattern ───────────────────────────
echo "[5/5] Simulating ptrace and process manipulation..."

cat > "$WORKDIR/ptrace_sim.c" << 'CEOF'
#include <stdio.h>
#include <sys/ptrace.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

int main() {
    pid_t child = fork();
    if (child == 0) {
        /* Child: allow tracing */
        ptrace(PTRACE_TRACEME, 0, NULL, NULL);
        execve("/bin/echo", (char*[]){"echo","traced",NULL}, NULL);
    } else {
        /* Parent: attach and inspect */
        int status;
        waitpid(child, &status, 0);
        printf("[attack] ptrace attached to child PID %d\n", child);
        ptrace(PTRACE_CONT, child, NULL, NULL);
        waitpid(child, &status, 0);
    }
    return 0;
}
CEOF

gcc -o "$WORKDIR/ptrace_sim" "$WORKDIR/ptrace_sim.c" 2>/dev/null
"$WORKDIR/ptrace_sim" || true

# Additional suspicious patterns: rapid clone/fork
for i in $(seq 1 20); do
    /bin/true &
done
wait

echo "  Done."
echo

echo "============================================="
echo "  Attack simulation complete."
echo "  Switch to the collector terminal and"
echo "  press Ctrl+C to stop data collection."
echo "============================================="
