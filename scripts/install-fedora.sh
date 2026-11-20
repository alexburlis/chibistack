#!/bin/bash
set -euo pipefail
umask 077
trap 'printf "Fedora installation stopped at line %s.\n" "$LINENO" >&2' ERR
fail() { printf '%s\n' "$*" >&2; exit 1; }
test "$(id -u)" = 0 || fail 'Run on the fresh Fedora host as root.'
# Never source the stage or a candidate application.
# shellcheck source=/dev/null
source /etc/os-release
[[ "$ID" = fedora && "$VERSION_ID" = 44 ]] || fail 'Fedora 44 is required.'
test "$(getenforce)" = Enforcing
test "$(stat -fc %T /sys/fs/cgroup)" = cgroup2fs
stage=${1:?absolute reviewed stage required}
bundle=${2:?absolute reviewed utility tar required}
hash=${3:?trusted utility tar SHA512 required}
[[ "$stage" = /* && "$bundle" = /* && "$hash" =~ ^[a-f0-9]{128}$ ]]

safe_path() {
  local path=$1
  [[ "$path" = /* && "$path" != *'/../'* && "$path" != *'/./'* && "$path" != *'//'* ]]
  while [[ "$path" != / ]]; do
    test ! -L "$path" || fail "Symlink target: $path"
    path=${path%/*}; path=${path:-/}
  done
}
trusted() {
  safe_path "$1"
  test "$(stat -c %u "$1")" = 0
  test $(( 8#$(stat -c %a "$1") & 0022 )) = 0
}
trusted_input() {
  local parent=${1%/*} mode
  parent=${parent:-/}
  safe_path "$1"
  while :; do
    mode=$(stat -c %a "$parent")
    if [[ "$(stat -c %u "$parent")" != 0 ]] ||
      (( (8#$mode & 0022) != 0 && (8#$mode & 01000) == 0 )); then
      fail "Untrusted input ancestor: $parent"
    fi
    [[ "$parent" != / ]] || break
    parent=${parent%/*}; parent=${parent:-/}
  done
  trusted "$1"
}
trusted_input "$stage"
trusted_input "$bundle"
test -d "$stage/root"
# Reject writable/symlinked inputs before any package or identity change.
while IFS= read -r -d '' path; do trusted "$path"; done < <(find "$stage" -print0)
test -f "$bundle"
printf '%s  %s\n' "$hash" "$bundle" | sha512sum --check --status
expected=$(printf '%s\n' hostctl hostmcp restic tailscale tailscaled | sort)
test "$(tar -tf "$bundle" | sort)" = "$expected" || fail 'Exactly five plain utility names required.'
test "$(tar -tvf "$bundle" | cut -c1 | sort -u)" = '-' || fail 'Utility links/directories are forbidden.'
for name in hostctl hostmcp restic tailscale tailscaled; do
  bytes=$(tar -xOf "$bundle" "$name" | wc -c)
  test "$bytes" -gt 0 && test "$bytes" -le 134217728
done
for metadata in accounts.tsv dirs.tsv files.tsv subids enabled.txt; do test -f "$stage/$metadata"; done

safe_path /run/minimal-host/lifecycle.lock
if [[ -e /run/minimal-host ]]; then trusted /run/minimal-host; fi
install -d -m 0755 /run/minimal-host
exec 9>/run/minimal-host/lifecycle.lock
flock -n 9 || fail 'Host lifecycle is busy; no installation started.'

for unit in minimal-host-mcp.service minimal-host-reconcile.service minimal-host-poll.timer minimal-host-health.timer dnf5-automatic.timer tailscaled.service; do
  if systemctl is-active --quiet "$unit"; then fail "Active installation: $unit"; fi
done
for socket in podman.socket docker.socket; do
  if systemctl is-enabled --quiet "$socket" || systemctl is-active --quiet "$socket"; then fail "Manager API enabled: $socket"; fi
done

while IFS=$'\t' read -r uid name extra; do
  [[ -z "$extra" && "$uid" =~ ^[12][0-9]{3}$ && "$name" =~ ^(host-proxy|host-mcp|app-[a-z][a-z0-9-]{0,31})$ ]]
  [[ "$name" = host-proxy && "$uid" = 1998 || "$name" = host-mcp && "$uid" = 1999 || "$name" = app-* && "$uid" -ge 2000 && "$uid" -le 2999 ]]
  entry=$(getent passwd "$name" || true)
  if [[ -n "$entry" ]]; then
    IFS=: read -r account _ actual_uid actual_gid _ home shell <<< "$entry"
    [[ "$account" = "$name" && "$actual_uid" = "$uid" && "$actual_gid" = "$uid" && "$home" = "/var/home/$name" && "$shell" = /usr/sbin/nologin ]]
  else
    ! getent passwd "$uid" >/dev/null || fail "Occupied UID: $uid"
  fi
  if getent passwd "$uid" >/dev/null; then test "$(getent passwd "$uid" | cut -d: -f1)" = "$name"; fi
  entry=$(getent group "$name" || true)
  if [[ -n "$entry" ]]; then
    IFS=: read -r account _ actual_gid members <<< "$entry"
    [[ "$account" = "$name" && "$actual_gid" = "$uid" && -z "$members" ]]
  else
    ! getent group "$uid" >/dev/null || fail "Occupied GID: $uid"
  fi
  if systemctl is-active --quiet "user@$uid.service"; then fail "Active managed user: $name"; fi
done < "$stage/accounts.tsv"
for database in /etc/subuid /etc/subgid; do
  safe_path "$database"
  while IFS=: read -r name start count; do
    [[ "$name" =~ ^(host-proxy|app-[a-z][a-z0-9-]{0,31})$ && "$start" =~ ^[0-9]+$ && "$count" = 65536 ]]
    uid=$(awk -F '\t' -v name="$name" '$2 == name {print $1}' "$stage/accounts.tsv")
    test "$start" = "$((2000000+(uid-1998)*65536))"
    if [[ -f "$database" ]]; then
      awk -F: -v name="$name" -v start="$start" -v count="$count" '
        NF != 3 || $2 !~ /^[0-9]+$/ || $3 !~ /^[0-9]+$/ {exit 1}
        $1 == name {if ($2 != start || $3 != count || seen++) exit 1; next}
        $2 < start+count && $2+$3 > start {exit 1}
      ' "$database" || fail "Subordinate ID conflict: $database $name"
    fi
  done < "$stage/subids"
done
while IFS=$'\t' read -r mode uid gid path extra; do
  [[ -z "$extra" && "$mode" =~ ^[0-7]{3,4}$ && "$uid" =~ ^[0-9]+$ && "$gid" =~ ^[0-9]+$ ]]
  safe_path "$path"
  if [[ -e "$path" ]]; then
    test -d "$path"
    test "$(stat -c %u:%g "$path")" = "$uid:$gid"
  fi
done < "$stage/dirs.tsv"
while IFS=$'\t' read -r mode path extra; do
  [[ -z "$extra" && "$mode" =~ ^[0-7]{3,4}$ ]]
  safe_path "$path"
  test -f "$stage/root$path"
  if [[ -e "$path" ]]; then
    test -f "$path" && test "$(stat -c %u:%g "$path")" = 0:0
    # The stock DNF configuration is the one deliberate fresh-host replacement.
    if [[ "$path" != /etc/dnf/automatic.conf || -e /etc/minimal-host/utilities.sha512 ]]; then
      cmp -s "$stage/root$path" "$path" || fail "Changed installation: $path"
    fi
  fi
done < "$stage/files.tsv"
safe_path /var/lib/minimal-host/utilities.tar
safe_path /etc/minimal-host/utilities.sha512
if [[ -e /var/lib/minimal-host/utilities.tar ]]; then cmp -s "$bundle" /var/lib/minimal-host/utilities.tar; fi
if [[ -e /etc/minimal-host/utilities.sha512 ]]; then
  test "$(cat /etc/minimal-host/utilities.sha512)" = "$hash  /var/lib/minimal-host/utilities.tar"
fi
for name in hostctl hostmcp restic tailscale tailscaled; do
  safe_path "/usr/local/bin/$name"
  if [[ -e "/usr/local/bin/$name" ]]; then
    test "$(stat -c %u:%g "/usr/local/bin/$name")" = 0:0
    tar -xOf "$bundle" "$name" | cmp -s - "/usr/local/bin/$name" || fail "Unrelated utility: $name"
  fi
done

# Only official signed Fedora repositories may resolve the host packages.
for repo in /etc/yum.repos.d/*.repo; do
  case "${repo##*/}" in fedora.repo|fedora-updates.repo|fedora-updates-testing.repo|fedora-cisco-openh264.repo|fedora-updates-archive.repo) ;; *) fail "Review non-Fedora repository: $repo";; esac
done
packages=(podman crun passt slirp4netns netavark aardvark-dns container-selinux shadow-utils shadow-utils-subid nftables dnf5-plugin-automatic policycoreutils policycoreutils-python-utils util-linux tar coreutils)
dnf5 --assumeyes --setopt=gpgcheck=1 --setopt=localpkg_gpgcheck=1 install "${packages[@]}"
for binary in podman crun pasta newuidmap newgidmap nft dnf5 flock restorecon semanage; do
  command -v "$binary" >/dev/null
  rpm -qf "$(command -v "$binary")"
done
test -x /usr/lib/systemd/system-generators/podman-system-generator
podman info --format '{{.Host.OCIRuntime.Name}}' | grep -Fx crun
systemctl cat dnf5-automatic.service dnf5-automatic.timer >/dev/null
install -d -m 0755 /var/lib/minimal-host
rpm -qa --qf '%{NAME}-%{VERSION}-%{RELEASE}.%{ARCH}\n' | sort > /var/lib/minimal-host/fedora-packages.txt

while IFS=$'\t' read -r uid name; do
  if ! getent group "$name" >/dev/null; then groupadd -g "$uid" "$name"; fi
  if ! getent passwd "$name" >/dev/null; then useradd -u "$uid" -g "$name" -d "/var/home/$name" -M -s /usr/sbin/nologin -K SUB_UID_COUNT=0 -K SUB_GID_COUNT=0 "$name"; fi
done < "$stage/accounts.tsv"
for database in /etc/subuid /etc/subgid; do
  while IFS= read -r entry; do
    if ! grep -Fxq "$entry" "$database"; then printf '%s\n' "$entry" >> "$database"; fi
  done < "$stage/subids"
done
while IFS=$'\t' read -r mode uid gid path; do
  install -d -m "$mode" -o "$uid" -g "$gid" -- "$path"
done < "$stage/dirs.tsv"
atomic_install() {
  local input=$1 path=$2 mode=$3 temporary
  temporary=$(mktemp "${path}.XXXXXX")
  install -m "$mode" -o root -g root -- "$input" "$temporary"
  mv -fT -- "$temporary" "$path"
}
while IFS=$'\t' read -r mode path; do
  install -d -m 0755 "${path%/*}"
  atomic_install "$stage/root$path" "$path" "$mode"
done < "$stage/files.tsv"
atomic_install "$bundle" /var/lib/minimal-host/utilities.tar 0600
temporary=$(mktemp /etc/minimal-host/.utilities.sha512.XXXXXX)
printf '%s  /var/lib/minimal-host/utilities.tar\n' "$hash" > "$temporary"
mv -fT -- "$temporary" /etc/minimal-host/utilities.sha512
/usr/local/libexec/minimal-host-binaries
# Retain stable /var/home paths with Fedora's ordinary home policy.
if ! semanage fcontext -l | grep -Eq '^/var/home[[:space:]]+=[[:space:]]+/home$'; then semanage fcontext -a -e /home /var/home; fi
restorecon -RF /var/home /etc/minimal-host /etc/containers/systemd/users /usr/local/libexec /var/lib/minimal-host
chcon -R -t container_file_t /etc/minimal-host/proxy /etc/minimal-host/app-secrets
systemd-tmpfiles --create /etc/tmpfiles.d/minimal-host.conf
systemctl daemon-reload
while read -r unit; do systemctl enable "$unit"; done < "$stage/enabled.txt"
printf 'Installed reviewed Fedora configuration. Optional timers, host firewall and enrollment remain disabled; no service was started.\n'
