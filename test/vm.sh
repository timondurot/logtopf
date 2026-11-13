#!/bin/sh
# Boot and drive a throwaway FreeBSD VM (QEMU/KVM) with pf + pflog0 for testing logtopf.
#
#   test/vm.sh up        boot (first run: download image, seed cloud-init, provision)
#   test/vm.sh sync      copy sources into the VM and build them
#   test/vm.sh ssh CMD   run a command as root in the VM
#   test/vm.sh down      power off
#   test/vm.sh reset     power off and delete the VM disk (keeps the downloaded image)
#
# Everything lives in test/vm/ (gitignored). LOGTOPF_REL=15.1 uses another release,
# kept in test/vm-15.1/; give it its own LOGTOPF_VM_PORT to run both at once.
# LOGTOPF_SMP / LOGTOPF_MEM set the VM's CPUs and memory in MiB (default 4 / 2048). Needs qemu with KVM, xz, curl, and
# python3 with pycdlib (to write the cloud-init ISO); set LOGTOPF_PY to pick the python.
set -eu

HERE=$(cd "$(dirname "$0")" && pwd)
ROOT=$(cd "$HERE/.." && pwd)
REL=${LOGTOPF_REL:-14.5}
VM=$HERE/vm${LOGTOPF_REL:+-$REL}
IMG=FreeBSD-$REL-RELEASE-amd64-BASIC-CLOUDINIT-ufs.qcow2
PORT=${LOGTOPF_VM_PORT:-2222}
KEY=$VM/id_ed25519
SSH="ssh -q -i $KEY -p $PORT -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o ConnectTimeout=3 -o BatchMode=yes root@127.0.0.1"
PY=${LOGTOPF_PY:-python3}

vssh() { $SSH "$@"; }

running() { [ -f "$VM/qemu.pid" ] && kill -0 "$(cat "$VM/qemu.pid")" 2>/dev/null; }

seed_iso() {
    [ -f "$KEY" ] || ssh-keygen -q -t ed25519 -N '' -f "$KEY"
    pub=$(cat "$KEY.pub")
    mkdir -p "$VM/seed"
    printf 'instance-id: logtopf-test\nlocal-hostname: logtopf-test\n' >"$VM/seed/meta-data"
    cat >"$VM/seed/user-data" <<EOF
#cloud-config
ssh_authorized_keys:
  - $pub
runcmd:
  - mkdir -p /root/.ssh && chmod 700 /root/.ssh
  - echo '$pub' > /root/.ssh/authorized_keys && chmod 600 /root/.ssh/authorized_keys
  - echo 'PermitRootLogin prohibit-password' >> /etc/ssh/sshd_config
  - sysrc sshd_enable=YES
  - service sshd restart
EOF
    "$PY" - "$VM/seed" "$VM/seed.iso" <<'EOF'
import sys, io, os, pycdlib
src, out = sys.argv[1], sys.argv[2]
iso = pycdlib.PyCdlib()
iso.new(interchange_level=3, joliet=3, rock_ridge='1.09', vol_ident='cidata')
for name in ('meta-data', 'user-data'):
    data = open(os.path.join(src, name), 'rb').read()
    iso.add_fp(io.BytesIO(data), len(data), '/' + name.upper().replace('-', '_') + '.;1',
               rr_name=name, joliet_path='/' + name)
iso.write(out)
iso.close()
EOF
}

wait_ssh() {
    i=0
    until vssh true 2>/dev/null; do
        i=$((i + 1))
        [ $i -gt 120 ] && { echo "ssh never came up; see $VM/serial.log" >&2; exit 1; }
        sleep 2
    done
}

provision() {
    vssh sh -s <<'EOF'
set -e
env ASSUME_ALWAYS_YES=yes pkg bootstrap -f >/dev/null
env ASSUME_ALWAYS_YES=yes pkg install -q tmux >/dev/null
sysrc -q pf_enable=YES pflog_enable=YES >/dev/null
touch /root/.provisioned
EOF
}

case "${1:-}" in
up)
    mkdir -p "$VM"
    if ! running; then
    if [ ! -f "$VM/disk.qcow2" ]; then
        if [ ! -f "$VM/$IMG" ]; then
            url=https://download.freebsd.org/releases/VM-IMAGES/$REL-RELEASE/amd64/Latest
            [ -f "$VM/$IMG.xz" ] || curl -fL -o "$VM/$IMG.xz" "$url/$IMG.xz"
            want=$(curl -fsS "$url/CHECKSUM.SHA256" | sed -n "s/^SHA256 ($IMG.xz) = //p")
            got=$(sha256sum "$VM/$IMG.xz" | cut -d' ' -f1)
            [ -n "$want" ] && [ "$want" = "$got" ] || { echo "checksum mismatch for $IMG.xz" >&2; exit 1; }
            xz -dk "$VM/$IMG.xz"
        fi
        qemu-img create -q -f qcow2 -F qcow2 -b "$VM/$IMG" "$VM/disk.qcow2" 8G
        seed_iso
    fi
    qemu-system-x86_64 -enable-kvm -cpu host -smp "${LOGTOPF_SMP:-4}" -m "${LOGTOPF_MEM:-2048}" \
        -drive file="$VM/disk.qcow2",if=virtio \
        -drive file="$VM/seed.iso",media=cdrom,readonly=on \
        -netdev user,id=n0,hostfwd=tcp:127.0.0.1:$PORT-:22 -device virtio-net,netdev=n0 \
        -display none -serial file:"$VM/serial.log" \
        -daemonize -pidfile "$VM/qemu.pid"
    fi
    wait_ssh
    vssh test -f /root/.provisioned 2>/dev/null || provision
    vssh 'kldstat -q -m pf || service pf start >/dev/null 2>&1; service pflog start >/dev/null 2>&1; true'
    echo "up: $(vssh uname -sr)"
    ;;
sync)
    tar -C "$ROOT" -cf - --exclude='./test/vm*' --exclude='*/__pycache__' --exclude=./.git --exclude=./logtopf --exclude='*.o' . |
        vssh 'rm -rf /root/src && mkdir -p /root/src && tar -C /root/src -xf -'
    vssh 'cd /root/src && sh ./build.sh 2>&1 && cc -O2 -Wall -Wextra -o /root/pktgen test/pktgen.c 2>&1'
    ;;
ssh)
    shift
    vssh "$@"
    ;;
down)
    running && { vssh 'shutdown -p now' 2>/dev/null || kill "$(cat "$VM/qemu.pid")"; }
    i=0
    while running && [ $i -lt 30 ]; do sleep 1; i=$((i + 1)); done
    running && kill -9 "$(cat "$VM/qemu.pid")"
    rm -f "$VM/qemu.pid"
    ;;
reset)
    "$0" down
    rm -f "$VM/disk.qcow2" "$VM/seed.iso"
    ;;
*)
    sed -n '2,10p' "$0"
    exit 1
    ;;
esac
