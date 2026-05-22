#!/usr/bin/env bash
# retrofit-remediation.sh
#
# Bulk STIG remediation applied on top of a stock Ubuntu 22.04 base.
# This is the script the "retrofit" path in the use case actually runs.
# Roughly 340 lines of config rewrites. The point of including it
# verbatim is to show the surface area you take ownership of when
# you choose the retrofit path.
#
# Mapped (loosely) to DISA STIG container baseline + Ubuntu 22.04 STIG.
# Not a substitute for the official benchmark — this is illustrative.

set -euo pipefail

log() { echo "[remediation] $*"; }

# -----------------------------------------------------------------------------
# Section 1: /etc/login.defs — password aging, umask, encryption
# -----------------------------------------------------------------------------
log "Hardening /etc/login.defs"

sed -i 's/^PASS_MAX_DAYS.*/PASS_MAX_DAYS 60/'   /etc/login.defs
sed -i 's/^PASS_MIN_DAYS.*/PASS_MIN_DAYS 1/'    /etc/login.defs
sed -i 's/^PASS_WARN_AGE.*/PASS_WARN_AGE 7/'    /etc/login.defs
sed -i 's/^UMASK.*/UMASK 077/'                  /etc/login.defs
sed -i 's/^ENCRYPT_METHOD.*/ENCRYPT_METHOD SHA512/' /etc/login.defs

# SHA512 rounds (STIG requires >= 5000)
grep -q '^SHA_CRYPT_MIN_ROUNDS' /etc/login.defs || \
    echo 'SHA_CRYPT_MIN_ROUNDS 5000' >> /etc/login.defs
grep -q '^SHA_CRYPT_MAX_ROUNDS' /etc/login.defs || \
    echo 'SHA_CRYPT_MAX_ROUNDS 10000' >> /etc/login.defs

# -----------------------------------------------------------------------------
# Section 2: PAM password quality (pwquality)
# -----------------------------------------------------------------------------
log "Configuring PAM password quality"

cat > /etc/security/pwquality.conf <<'EOF'
# STIG-mandated password complexity
minlen      = 15
dcredit     = -1
ucredit     = -1
lcredit     = -1
ocredit     = -1
minclass    = 4
maxrepeat   = 3
maxclassrepeat = 4
gecoscheck  = 1
difok       = 8
dictcheck   = 1
EOF

# Enforce pwquality + faillock in common-password / common-auth
if ! grep -q 'pam_pwquality.so' /etc/pam.d/common-password; then
    sed -i '/pam_unix.so/i password requisite pam_pwquality.so retry=3 enforce_for_root' \
        /etc/pam.d/common-password
fi

# Account lockout after 3 failed attempts (faillock)
cat > /etc/security/faillock.conf <<'EOF'
deny        = 3
unlock_time = 0
fail_interval = 900
silent
audit
EOF

if ! grep -q 'pam_faillock.so' /etc/pam.d/common-auth; then
    sed -i '1i auth required pam_faillock.so preauth' /etc/pam.d/common-auth
    echo 'auth [default=die] pam_faillock.so authfail' >> /etc/pam.d/common-auth
    echo 'auth sufficient pam_faillock.so authsucc'    >> /etc/pam.d/common-auth
fi

# -----------------------------------------------------------------------------
# Section 3: SSH daemon hardening (if installed)
# -----------------------------------------------------------------------------
log "Hardening sshd_config"

if [ -f /etc/ssh/sshd_config ]; then
    # Disable root login
    sed -i 's/^#*PermitRootLogin.*/PermitRootLogin no/' /etc/ssh/sshd_config
    # No empty passwords
    sed -i 's/^#*PermitEmptyPasswords.*/PermitEmptyPasswords no/' /etc/ssh/sshd_config
    # Protocol 2 only (default in modern OpenSSH but STIG requires explicit)
    grep -q '^Protocol' /etc/ssh/sshd_config || echo 'Protocol 2' >> /etc/ssh/sshd_config
    # Strict modes
    sed -i 's/^#*StrictModes.*/StrictModes yes/' /etc/ssh/sshd_config
    # FIPS-aligned ciphers
    cat >> /etc/ssh/sshd_config <<'EOF'

# STIG: approved ciphers/MACs/kex only
Ciphers aes256-ctr,aes192-ctr,aes128-ctr
MACs hmac-sha2-512,hmac-sha2-256
KexAlgorithms ecdh-sha2-nistp521,ecdh-sha2-nistp384,ecdh-sha2-nistp256
HostKeyAlgorithms ssh-rsa,rsa-sha2-512,rsa-sha2-256
ClientAliveInterval 600
ClientAliveCountMax 0
LoginGraceTime 60
MaxAuthTries 3
MaxSessions 10
Banner /etc/issue.net
EOF
fi

# -----------------------------------------------------------------------------
# Section 4: Audit daemon configuration
# -----------------------------------------------------------------------------
log "Configuring auditd"

cat > /etc/audit/auditd.conf <<'EOF'
log_file = /var/log/audit/audit.log
log_format = ENRICHED
log_group = adm
priority_boost = 4
flush = INCREMENTAL_ASYNC
freq = 50
num_logs = 5
disp_qos = lossy
dispatcher = /sbin/audispd
name_format = NONE
max_log_file = 8
max_log_file_action = ROTATE
space_left = 75
space_left_action = SYSLOG
admin_space_left = 50
admin_space_left_action = SUSPEND
disk_full_action = SUSPEND
disk_error_action = SUSPEND
use_libwrap = yes
tcp_listen_queue = 5
tcp_max_per_addr = 1
tcp_client_max_idle = 0
enable_krb5 = no
EOF

# Audit rules — the STIG-mandated set
mkdir -p /etc/audit/rules.d
cat > /etc/audit/rules.d/stig.rules <<'EOF'
# Time-change events
-a always,exit -F arch=b64 -S adjtimex,settimeofday,clock_settime -k time-change
-a always,exit -F arch=b32 -S adjtimex,settimeofday,clock_settime -k time-change
-w /etc/localtime -p wa -k time-change

# User/group modification
-w /etc/group    -p wa -k identity
-w /etc/passwd   -p wa -k identity
-w /etc/gshadow  -p wa -k identity
-w /etc/shadow   -p wa -k identity
-w /etc/security/opasswd -p wa -k identity

# Network environment
-a always,exit -F arch=b64 -S sethostname,setdomainname -k system-locale
-w /etc/issue    -p wa -k system-locale
-w /etc/issue.net -p wa -k system-locale
-w /etc/hosts    -p wa -k system-locale
-w /etc/network  -p wa -k system-locale

# MAC policy
-w /etc/selinux/    -p wa -k MAC-policy
-w /etc/apparmor/   -p wa -k MAC-policy
-w /etc/apparmor.d/ -p wa -k MAC-policy

# Login/logout events
-w /var/log/lastlog  -p wa -k logins
-w /var/run/faillock -p wa -k logins

# Session initiation
-w /var/run/utmp  -p wa -k session
-w /var/log/wtmp  -p wa -k session
-w /var/log/btmp  -p wa -k session

# Permission modifications
-a always,exit -F arch=b64 -S chmod,fchmod,fchmodat   -F auid>=1000 -F auid!=4294967295 -k perm_mod
-a always,exit -F arch=b64 -S chown,fchown,fchownat,lchown -F auid>=1000 -F auid!=4294967295 -k perm_mod
-a always,exit -F arch=b64 -S setxattr,lsetxattr,fsetxattr,removexattr,lremovexattr,fremovexattr -F auid>=1000 -F auid!=4294967295 -k perm_mod

# Unauthorized access attempts
-a always,exit -F arch=b64 -S creat,open,openat,truncate,ftruncate -F exit=-EACCES -F auid>=1000 -F auid!=4294967295 -k access
-a always,exit -F arch=b64 -S creat,open,openat,truncate,ftruncate -F exit=-EPERM  -F auid>=1000 -F auid!=4294967295 -k access

# Privileged commands (truncated for brevity — real STIG list is ~40 entries)
-a always,exit -F path=/usr/bin/sudo      -F perm=x -F auid>=1000 -F auid!=4294967295 -k privileged
-a always,exit -F path=/usr/bin/su        -F perm=x -F auid>=1000 -F auid!=4294967295 -k privileged
-a always,exit -F path=/usr/bin/passwd    -F perm=x -F auid>=1000 -F auid!=4294967295 -k privileged
-a always,exit -F path=/usr/bin/chage     -F perm=x -F auid>=1000 -F auid!=4294967295 -k privileged
-a always,exit -F path=/usr/bin/gpasswd   -F perm=x -F auid>=1000 -F auid!=4294967295 -k privileged
-a always,exit -F path=/usr/bin/newgrp    -F perm=x -F auid>=1000 -F auid!=4294967295 -k privileged

# Mount events
-a always,exit -F arch=b64 -S mount -F auid>=1000 -F auid!=4294967295 -k mounts

# Deletion events
-a always,exit -F arch=b64 -S unlink,unlinkat,rename,renameat -F auid>=1000 -F auid!=4294967295 -k delete

# Sudoers changes
-w /etc/sudoers   -p wa -k scope
-w /etc/sudoers.d -p wa -k scope

# Kernel module loading
-w /sbin/insmod    -p x -k modules
-w /sbin/rmmod     -p x -k modules
-w /sbin/modprobe  -p x -k modules
-a always,exit -F arch=b64 -S init_module,delete_module -k modules

# Make config immutable (must be last)
-e 2
EOF

chmod 0640 /etc/audit/auditd.conf
chmod 0640 /etc/audit/rules.d/stig.rules

# -----------------------------------------------------------------------------
# Section 5: Kernel parameters via sysctl
# -----------------------------------------------------------------------------
log "Writing sysctl hardening"

cat > /etc/sysctl.d/99-stig.conf <<'EOF'
# Network
net.ipv4.ip_forward                       = 0
net.ipv4.conf.all.send_redirects          = 0
net.ipv4.conf.default.send_redirects      = 0
net.ipv4.conf.all.accept_source_route     = 0
net.ipv4.conf.default.accept_source_route = 0
net.ipv4.conf.all.accept_redirects        = 0
net.ipv4.conf.default.accept_redirects    = 0
net.ipv4.conf.all.secure_redirects        = 0
net.ipv4.conf.default.secure_redirects    = 0
net.ipv4.conf.all.log_martians            = 1
net.ipv4.conf.default.log_martians        = 1
net.ipv4.icmp_echo_ignore_broadcasts      = 1
net.ipv4.icmp_ignore_bogus_error_responses = 1
net.ipv4.conf.all.rp_filter               = 1
net.ipv4.conf.default.rp_filter           = 1
net.ipv4.tcp_syncookies                   = 1
net.ipv6.conf.all.accept_redirects        = 0
net.ipv6.conf.default.accept_redirects    = 0
net.ipv6.conf.all.accept_source_route     = 0
net.ipv6.conf.default.accept_source_route = 0

# Kernel hardening
kernel.randomize_va_space    = 2
kernel.kptr_restrict         = 2
kernel.dmesg_restrict        = 1
kernel.yama.ptrace_scope     = 1
kernel.unprivileged_bpf_disabled = 1
net.core.bpf_jit_harden      = 2

# Core dump restrictions
fs.suid_dumpable             = 0
kernel.core_uses_pid         = 1
EOF

chmod 0644 /etc/sysctl.d/99-stig.conf

# -----------------------------------------------------------------------------
# Section 6: Disable unused filesystems and modules
# -----------------------------------------------------------------------------
log "Blacklisting unused kernel modules"

mkdir -p /etc/modprobe.d
cat > /etc/modprobe.d/stig-blacklist.conf <<'EOF'
# Unnecessary filesystems
install cramfs   /bin/true
install freevxfs /bin/true
install jffs2    /bin/true
install hfs      /bin/true
install hfsplus  /bin/true
install squashfs /bin/true
install udf      /bin/true
install vfat     /bin/true

# Unnecessary network protocols
install dccp /bin/true
install sctp /bin/true
install rds  /bin/true
install tipc /bin/true

# USB storage (STIG requires it disabled by default)
install usb-storage /bin/true

# Bluetooth
install bluetooth /bin/true
EOF

# -----------------------------------------------------------------------------
# Section 7: File permissions on system files
# -----------------------------------------------------------------------------
log "Setting file permissions"

chmod 0644 /etc/passwd
chmod 0644 /etc/group
chmod 0600 /etc/shadow
chmod 0600 /etc/gshadow
chmod 0600 /etc/security/opasswd 2>/dev/null || true
chmod 0644 /etc/hosts
chmod 0700 /root

chown root:root /etc/passwd /etc/group /etc/hosts
chown root:shadow /etc/shadow /etc/gshadow 2>/dev/null || \
    chown root:root /etc/shadow /etc/gshadow

# -----------------------------------------------------------------------------
# Section 8: Banner files
# -----------------------------------------------------------------------------
log "Installing DoD warning banner"

cat > /etc/issue <<'EOF'
You are accessing a U.S. Government (USG) Information System (IS) that is
provided for USG-authorized use only. By using this IS (which includes any
device attached to this IS), you consent to the following conditions: -The
USG routinely intercepts and monitors communications on this IS for purposes
including, but not limited to, penetration testing, COMSEC monitoring, network
operations and defense, personnel misconduct (PM), law enforcement (LE), and
counterintelligence (CI) investigations.
EOF

cp /etc/issue /etc/issue.net
chmod 0644 /etc/issue /etc/issue.net

# -----------------------------------------------------------------------------
# Section 9: AIDE — file integrity baseline
# -----------------------------------------------------------------------------
log "Initializing AIDE database"

if command -v aideinit >/dev/null 2>&1; then
    aideinit -y -f >/dev/null 2>&1 || true
    if [ -f /var/lib/aide/aide.db.new ]; then
        mv /var/lib/aide/aide.db.new /var/lib/aide/aide.db
    fi
fi

# -----------------------------------------------------------------------------
# Section 10: cron permissions
# -----------------------------------------------------------------------------
log "Locking down cron"

for f in /etc/crontab /etc/cron.d /etc/cron.daily /etc/cron.hourly \
         /etc/cron.weekly /etc/cron.monthly; do
    [ -e "$f" ] && chmod -R go-rwx "$f"
done

# Restrict cron and at to root
touch /etc/cron.allow /etc/at.allow
chmod 0600 /etc/cron.allow /etc/at.allow
chown root:root /etc/cron.allow /etc/at.allow
rm -f /etc/cron.deny /etc/at.deny

# -----------------------------------------------------------------------------
# Done
# -----------------------------------------------------------------------------
log "Retrofit remediation complete."
log "Lines of config rewritten: ~340"
log "Remaining unfixable findings: package-selection rules (wget, tar,"
log "dpkg, /bin/bash present). Cannot be remediated without breaking the image."
