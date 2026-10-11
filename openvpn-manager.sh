#!/usr/bin/env bash
set -Eeuo pipefail

# OpenVPN installer and client manager for Ubuntu 22.04/24.04.
# Commands: install | add [name] [days|-] [quota_GB|-] | revoke NAME | list | status | menu

APP="openvpn-manager"
OVPN_DIR=/etc/openvpn/server
PKI_DIR=/etc/openvpn/easy-rsa
CLIENT_DIR=/etc/openvpn/clients
DATA_DIR=/var/lib/openvpn-manager
CCD_DIR="$OVPN_DIR/ccd"
SERVER_CONF="$OVPN_DIR/server.conf"
PORT=21443
PROTO=tcp
VPN_NET=10.8.0.0/24
VPN_IF=tun0
WAN_IF="$(ip -4 route show default 2>/dev/null | awk 'NR==1 {print $5}')"
PUBLIC_IP="$(curl -4 -fsS --max-time 3 https://api.ipify.org 2>/dev/null || true)"

fail(){ echo "خطا: $*" >&2; exit 1; }
need_root(){ [[ ${EUID:-$(id -u)} -eq 0 ]] || fail "این دستور را با sudo اجرا کن."; }
valid_name(){ [[ "$1" =~ ^[A-Za-z0-9_-]{1,32}$ ]]; }

install_manager_helpers(){
  install -d -m 755 "$DATA_DIR"; chmod 755 "$DATA_DIR"; install -d -m 700 "$CLIENT_DIR" "$CCD_DIR"
  cat > /usr/local/sbin/openvpn-client-connect <<'PY'
#!/usr/bin/env python3
import json, os, sys, time
name=os.environ.get('common_name','')
if not name or not name.replace('_','').replace('-','').isalnum(): sys.exit(1)
p='/var/lib/openvpn-manager/'+name+'.json'
# Existing clients not managed by this script remain allowed during adoption.
if not os.path.exists(p): sys.exit(0)
try:
 d=json.load(open(p))
 if d.get('revoked') or d.get('blocked') or (d.get('expires_at') and time.time() >= d['expires_at']): sys.exit(1)
except Exception: sys.exit(1)
sys.exit(0)
PY
  chmod 755 /usr/local/sbin/openvpn-client-connect

  cat > /usr/local/sbin/openvpn-quota-check <<'PY'
#!/usr/bin/env python3
import csv, glob, json, os, subprocess, time
D='/var/lib/openvpn-manager'; STATUS='/var/log/openvpn/status.log'
def fw(args): subprocess.run(['/usr/sbin/iptables']+args, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
def rule(args): return subprocess.run(['/usr/sbin/iptables','-C']+args, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL).returncode==0
# Remove prior quota blocks first only when the corresponding account is not blocked.
rows={}
try:
 with open(STATUS, newline='') as f:
  for row in csv.reader(f):
   if len(row)>6 and row[0]=='CLIENT_LIST':
    try: rows[row[1]]=(int(row[5]),int(row[6]))
    except ValueError: pass
except OSError: pass
for path in glob.glob(D+'/*.json'):
 try:
  d=json.load(open(path)); name=os.path.basename(path)[:-5]; ip=d.get('ip'); old=int(d.get('used_bytes',0)); prev=d.get('last_counters');
  if name in rows:
   rx,tx=rows[name]
   if isinstance(prev,list) and len(prev)==2 and rx>=prev[0] and tx>=prev[1]: old += (rx-prev[0])+(tx-prev[1])
   else: old += rx+tx
   d['last_counters']=[rx,tx]; d['last_seen']=int(time.time())
  d['used_bytes']=old
  expired=bool(d.get('expires_at') and time.time()>=d['expires_at'])
  quota=int(d.get('quota_bytes',0) or 0)
  if expired or (quota and old>=quota): d['blocked']=True
  if ip:
   for direction,addr in [(' -s'.strip(),ip),(' -d'.strip(),ip)]:
    args=['FORWARD',direction,addr,'-j','DROP']
    if d.get('blocked') and not rule(args): fw(['-I']+args)
    elif not d.get('blocked') and rule(args): fw(['-D']+args)
  tmp=path+'.tmp'; json.dump(d,open(tmp,'w')); os.chmod(tmp,0o644); os.replace(tmp,path)
 except Exception: pass
PY
  chmod 750 /usr/local/sbin/openvpn-quota-check
  cat > /etc/systemd/system/openvpn-quota-check.service <<'UNIT'
[Unit]
Description=OpenVPN per-client quota and expiry checker
After=network-online.target openvpn-server@server.service
[Service]
Type=oneshot
ExecStart=/usr/local/sbin/openvpn-quota-check
UNIT
  cat > /etc/systemd/system/openvpn-quota-check.timer <<'UNIT'
[Unit]
Description=Check OpenVPN client quotas every minute
[Timer]
OnBootSec=1min
OnUnitActiveSec=1min
Persistent=true
[Install]
WantedBy=timers.target
UNIT
  systemctl daemon-reload
  systemctl enable --now openvpn-quota-check.timer
}

install_openvpn(){
  need_root
  [[ -r /etc/os-release ]] || fail 'سیستم‌عامل شناسایی نشد.'
  . /etc/os-release
  [[ "$ID" == ubuntu ]] || fail 'این اسکریپت برای Ubuntu طراحی شده است.'
  if [[ -e "$SERVER_CONF" ]]; then
    echo "یک پیکربندی OpenVPN از قبل وجود دارد: $SERVER_CONF"
    echo 'برای جلوگیری از قطع اتصال فعلی، نصب خودکار آن را بازنویسی نمی‌کند.'
    echo 'اگر این سرور تازه نیست، ابتدا از فایل‌های موجود پشتیبان بگیر و مهاجرت را دستی بررسی کن.'
    exit 2
  fi
  [[ -n "$WAN_IF" ]] || fail 'رابط اینترنت (default route) پیدا نشد.'
  export DEBIAN_FRONTEND=noninteractive
  apt-get update
  apt-get install -y openvpn easy-rsa ufw iptables curl python3
  PUBLIC_IP="$(curl -4 -fsS --max-time 5 https://api.ipify.org 2>/dev/null || true)"
  [[ -n "$PUBLIC_IP" ]] || PUBLIC_IP="$(ip -4 -o addr show dev "$WAN_IF" | awk '{split($4,a,"/"); print a[1]; exit}')"
  install -d -m 700 "$OVPN_DIR" "$PKI_DIR" "$CLIENT_DIR" "$CCD_DIR" "$DATA_DIR" /var/log/openvpn
  cp -r /usr/share/easy-rsa/* "$PKI_DIR/"
  cd "$PKI_DIR"
  export EASYRSA_BATCH=1 EASYRSA_PKI="$PKI_DIR/pki" EASYRSA_CA_EXPIRE=3650 EASYRSA_CERT_EXPIRE=3650 EASYRSA_CRL_DAYS=3650
  ./easyrsa init-pki
  ./easyrsa build-ca nopass
  ./easyrsa gen-dh
  ./easyrsa build-server-full server nopass
  ./easyrsa gen-crl
  install -m 644 pki/ca.crt "$OVPN_DIR/ca.crt"
  install -m 644 pki/issued/server.crt "$OVPN_DIR/server.crt"
  install -m 600 pki/private/server.key "$OVPN_DIR/server.key"
  install -m 644 pki/dh.pem "$OVPN_DIR/dh.pem"
  install -m 644 pki/crl.pem "$OVPN_DIR/crl.pem"
  openvpn --genkey secret "$OVPN_DIR/ta.key"
  chmod 600 "$OVPN_DIR/ta.key"
  cat > "$SERVER_CONF" <<EOF2
port $PORT
proto $PROTO
dev tun
user nobody
group nogroup
persist-key
persist-tun
topology subnet
server 10.8.0.0 255.255.255.0
ifconfig-pool 10.8.0.2 10.8.0.9 255.255.255.0
client-config-dir $CCD_DIR
script-security 2
client-connect /usr/local/sbin/openvpn-client-connect
ca $OVPN_DIR/ca.crt
cert $OVPN_DIR/server.crt
key $OVPN_DIR/server.key
dh $OVPN_DIR/dh.pem
crl-verify $OVPN_DIR/crl.pem
tls-auth $OVPN_DIR/ta.key 0
tls-version-min 1.2
remote-cert-tls client
auth SHA256
data-ciphers AES-256-GCM:AES-128-GCM:CHACHA20-POLY1305
keepalive 10 120
push "redirect-gateway def1"
push "dhcp-option DNS 1.1.1.1"
push "dhcp-option DNS 1.0.0.1"
status /var/log/openvpn/status.log 10
status-version 2
verb 3
EOF2
  install_manager_helpers
  echo 'net.ipv4.ip_forward=1' > /etc/sysctl.d/99-openvpn-forward.conf
  sysctl --system >/dev/null
  # Preserve existing UFW files; add only this VPN's NAT rule.
  if ! grep -q '10\.8\.0\.0/24.*MASQUERADE' /etc/ufw/before.rules; then
    cp -a /etc/ufw/before.rules /etc/ufw/before.rules.openvpn-backup
    sed -i "/^\*filter/i *nat\n:POSTROUTING ACCEPT [0:0]\n-A POSTROUTING -s 10.8.0.0/24 -o $WAN_IF -j MASQUERADE\nCOMMIT\n" /etc/ufw/before.rules
  fi
  # Allow the currently configured SSH port before enabling UFW, to avoid lockout.
  local ssh_port
  ssh_port=$(sshd -T 2>/dev/null | awk '$1=="port" {print $2; exit}')
  [[ "$ssh_port" =~ ^[0-9]+$ ]] || ssh_port=22
  ufw allow "$ssh_port/tcp"
  ufw allow "$PORT/tcp"
  ufw route allow in on tun0 out on "$WAN_IF" from 10.8.0.0/24 to any
  if ! ufw status | grep -q '^Status: active'; then ufw --force enable; else ufw reload; fi
  systemctl enable --now openvpn-server@server
  systemctl restart openvpn-server@server
  echo
  echo "نصب انجام شد. پورت: $PORT/tcp، رابط اینترنت: $WAN_IF"
  [[ -n "$PUBLIC_IP" ]] && echo "IP عمومی تشخیص‌داده‌شده: $PUBLIC_IP"
  echo 'اکنون با دستور زیر اولین کاربر را بساز: sudo openvpn-manager add iphone 365 50'
}


adopt_existing(){
  need_root
  [[ -f "$SERVER_CONF" ]] || fail "فایل تنظیمات فعلی پیدا نشد: $SERVER_CONF"
  [[ -n "$WAN_IF" ]] || fail 'رابط اینترنت (default route) پیدا نشد.'
  command -v openvpn >/dev/null || fail 'OpenVPN نصب نیست.'
  grep -Eq '^[[:space:]]*dev[[:space:]]+tun([[:space:]]|$)' "$SERVER_CONF" || fail 'این اسکریپت فقط برای سرور دارای dev tun طراحی شده است.'
  grep -Eq '^[[:space:]]*server[[:space:]]+10\.8\.0\.0[[:space:]]+255\.255\.255\.0' "$SERVER_CONF" || fail 'شبکه سرور با 10.8.0.0/24 مطابقت ندارد؛ برای جلوگیری از تداخل، مهاجرت متوقف شد.'
  local old_ca
  old_ca=$(awk '$1=="ca" {print $2; exit}' "$SERVER_CONF")
  [[ -n "$old_ca" && -r "$old_ca" ]] || fail 'مسیر CA فعلی در server.conf پیدا نشد یا قابل خواندن نیست.'
  [[ ! -e "$PKI_DIR/pki" ]] || fail 'ساختار PKI مدیریتی از قبل وجود دارد؛ از adopt دوباره استفاده نکن.'
  echo 'این عملیات تنظیمات فعلی را پشتیبان می‌گیرد و به CA مدیریتی جداگانه برای کاربران جدید مهاجرت می‌کند.'
  echo 'OpenVPN در پایان یک بار restart می‌شود؛ اتصال VPN ممکن است چند ثانیه قطع شود، ولی مجوز SSH تغییر نمی‌کند.'
  read -rp 'برای ادامه دقیقاً YES بنویس: ' confirm
  [[ "$confirm" == YES ]] || { echo 'لغو شد.'; return 0; }
  export DEBIAN_FRONTEND=noninteractive
  apt-get update
  apt-get install -y easy-rsa ufw iptables python3
  install -d -m 700 "$PKI_DIR" "$CLIENT_DIR" "$CCD_DIR" "$DATA_DIR" /var/log/openvpn
  cp -a "$SERVER_CONF" "$SERVER_CONF.before-openvpn-manager.$(date +%Y%m%d%H%M%S)"
  cp -a "$old_ca" "$OVPN_DIR/ca-before-manager.crt"
  cp -r /usr/share/easy-rsa/* "$PKI_DIR/"
  cd "$PKI_DIR"
  export EASYRSA_BATCH=1 EASYRSA_PKI="$PKI_DIR/pki" EASYRSA_CA_EXPIRE=3650 EASYRSA_CERT_EXPIRE=3650 EASYRSA_CRL_DAYS=3650
  ./easyrsa init-pki
  ./easyrsa build-ca nopass
  ./easyrsa gen-crl
  install -m 644 pki/crl.pem "$OVPN_DIR/manager-crl.pem"
  # Keep the old trust certificate and append the manager CA for newly issued clients.
  cat "$OVPN_DIR/ca-before-manager.crt" "$PKI_DIR/pki/ca.crt" > "$OVPN_DIR/ca-manager-bundle.crt"
  chmod 644 "$OVPN_DIR/ca-manager-bundle.crt"
  install_manager_helpers
  # Change only known directives; preserve all unrelated server settings.
  sed -i -E "s|^[[:space:]]*ca[[:space:]]+.*|ca $OVPN_DIR/ca-manager-bundle.crt|" "$SERVER_CONF"
  grep -Eq '^[[:space:]]*crl-verify[[:space:]]' "$SERVER_CONF" || echo "crl-verify $OVPN_DIR/manager-crl.pem" >> "$SERVER_CONF"
  grep -Eq '^[[:space:]]*client-config-dir[[:space:]]' "$SERVER_CONF" || echo "client-config-dir $CCD_DIR" >> "$SERVER_CONF"
  if grep -Eq '^[[:space:]]*ifconfig-pool[[:space:]]' "$SERVER_CONF"; then sed -i -E 's|^[[:space:]]*ifconfig-pool[[:space:]].*|ifconfig-pool 10.8.0.2 10.8.0.9 255.255.255.0|' "$SERVER_CONF"; else echo 'ifconfig-pool 10.8.0.2 10.8.0.9 255.255.255.0' >> "$SERVER_CONF"; fi
  grep -Eq '^[[:space:]]*client-connect[[:space:]]' "$SERVER_CONF" || echo 'client-connect /usr/local/sbin/openvpn-client-connect' >> "$SERVER_CONF"
  grep -Eq '^[[:space:]]*script-security[[:space:]]' "$SERVER_CONF" || echo 'script-security 2' >> "$SERVER_CONF"
  grep -Eq '^[[:space:]]*status[[:space:]]' "$SERVER_CONF" || echo 'status /var/log/openvpn/status.log 10' >> "$SERVER_CONF"
  grep -Eq '^[[:space:]]*status-version[[:space:]]' "$SERVER_CONF" || echo 'status-version 2' >> "$SERVER_CONF"
  echo 'net.ipv4.ip_forward=1' > /etc/sysctl.d/99-openvpn-forward.conf
  sysctl --system >/dev/null
  # Add persistent NAT without removing the existing WireGuard NAT rules.
  if ! grep -q '10\.8\.0\.0/24.*MASQUERADE' /etc/ufw/before.rules; then
    cp -a /etc/ufw/before.rules "/etc/ufw/before.rules.before-openvpn-manager.$(date +%Y%m%d%H%M%S)"
    if grep -q '^\*nat$' /etc/ufw/before.rules; then
      grep -q '10\.8\.0\.0/24.*MASQUERADE' /etc/ufw/before.rules || sed -i '/^-A POSTROUTING/i -A POSTROUTING -s 10.8.0.0/24 -o '"$WAN_IF"' -j MASQUERADE' /etc/ufw/before.rules
    else
      sed -i "/^\*filter/i *nat\n:POSTROUTING ACCEPT [0:0]\n-A POSTROUTING -s 10.8.0.0/24 -o $WAN_IF -j MASQUERADE\nCOMMIT\n" /etc/ufw/before.rules
    fi
  fi
  ufw route allow in on tun0 out on "$WAN_IF" from 10.8.0.0/24 to any
  ufw reload
  systemctl daemon-reload
  systemctl enable --now openvpn-quota-check.timer
  if ! openvpn --config "$SERVER_CONF" --test-crypto >/dev/null 2>&1; then
    echo 'هشدار: بررسی عمومی config با --test-crypto موفق نشد؛ قبل از restart لاگ را بررسی کن.'
  fi
  systemctl restart openvpn-server@server
  systemctl is-active --quiet openvpn-server@server || fail 'سرویس پس از مهاجرت فعال نشد. پشتیبان server.conf و CA در مسیرهای قبلی موجود است؛ وضعیت را بررسی کن.'
  echo 'مدیریت به سرور فعلی اضافه شد. تنظیمات قبلی پشتیبان‌گیری شدند.'
  echo 'اکنون کاربر جدید بساز: sudo openvpn-manager add friend1 30 10'
}

add_client(){
  need_root
  [[ -d "$PKI_DIR/pki" && -f "$SERVER_CONF" ]] || fail 'OpenVPN با همین اسکریپت نصب نشده یا PKI در دسترس نیست.'
  local name="${1:-}" days="${2:-365}" quota="${3:-0}" ip last
  if [[ -z "$name" ]]; then read -rp 'نام کاربر (حروف انگلیسی/عدد/_/-): ' name; fi
  valid_name "$name" || fail 'نام نامعتبر است؛ فقط حروف انگلیسی، عدد، _ و - (حداکثر 32 کاراکتر).'
  [[ ! -e "$PKI_DIR/pki/issued/$name.crt" ]] || fail 'این نام قبلاً استفاده شده است.'
  [[ "$days" == '-' ]] && days=365
  [[ "$quota" == '-' ]] && quota=0
  [[ "$days" =~ ^[0-9]+$ ]] && ((days>=1 && days<=3650)) || fail 'روز باید بین 1 تا 3650 باشد.'
  [[ "$quota" =~ ^[0-9]+([.][0-9]+)?$ ]] || fail 'حجم باید به GB باشد؛ صفر یعنی نامحدود.'
  last=$(find "$DATA_DIR" -maxdepth 1 -name '*.json' -printf '%f\n' 2>/dev/null | wc -l)
  ((last<240)) || fail 'ظرفیت IPهای اختصاصی پر شده است.'
  ip="10.8.0.$((last+10))"
  [[ -e "$DATA_DIR/$name.json" ]] && fail 'پرونده مدیریتی این نام موجود است.'
  cd "$PKI_DIR"
  export EASYRSA_BATCH=1 EASYRSA_PKI="$PKI_DIR/pki" EASYRSA_CERT_EXPIRE="$days"
  ./easyrsa build-client-full "$name" nopass
  printf 'ifconfig-push %s 255.255.255.0\n' "$ip" > "$CCD_DIR/$name"
  chmod 600 "$CCD_DIR/$name"
  local expiry=0 quota_bytes=0
  expiry=$(( $(date +%s) + days*86400 ))
  if [[ "$quota" != 0 ]]; then quota_bytes=$(awk -v q="$quota" 'BEGIN{printf "%.0f",q*1073741824}'); fi
  python3 - "$DATA_DIR/$name.json" "$name" "$ip" "$expiry" "$quota_bytes" <<'PY'
import json,sys,os
p,n,ip,exp,q=sys.argv[1:]; d={'name':n,'ip':ip,'expires_at':int(exp),'quota_bytes':int(q),'used_bytes':0,'last_counters':None,'last_seen':0,'blocked':False,'revoked':False}
with open(p,'w') as f: json.dump(d,f)
os.chmod(p,0o644)
PY
  local out="$CLIENT_DIR/$name.ovpn"
  { printf 'client\ndev tun\nproto tcp-client\nremote %s %s\nresolv-retry infinite\nnobind\npersist-key\npersist-tun\nremote-cert-tls server\nauth SHA256\nverb 3\nkey-direction 1\n<ca>\n' "${PUBLIC_IP:-YOUR_SERVER_IP}" "$PORT"; if [[ -r "$OVPN_DIR/ca-before-manager.crt" ]]; then cat "$OVPN_DIR/ca-before-manager.crt"; else cat "$PKI_DIR/pki/ca.crt"; fi; printf '</ca>\n<cert>\n'; awk '/BEGIN CERTIFICATE/,/END CERTIFICATE/' "$PKI_DIR/pki/issued/$name.crt"; printf '</cert>\n<key>\n'; cat "$PKI_DIR/pki/private/$name.key"; printf '</key>\n<tls-auth>\n'; cat "$OVPN_DIR/ta.key"; printf '</tls-auth>\n'; } > "$out"
  chmod 600 "$out"
  systemctl reload openvpn-server@server 2>/dev/null || systemctl restart openvpn-server@server
  echo "کانفیگ ساخته شد: $out"
  echo "IP اختصاصی: $ip | اعتبار: $days روز | سقف حجم: ${quota} GB (صفر=نامحدود)"
  echo 'فایل .ovpn را امن منتقل کن؛ هرکس آن را داشته باشد می‌تواند از حساب استفاده کند.'
}

revoke_client(){
  need_root; local name="${1:-}"; valid_name "$name" || fail 'نام کاربر را درست وارد کن.'
  [[ -d "$PKI_DIR/pki" && -f "$PKI_DIR/pki/issued/$name.crt" ]] || fail 'گواهی این کاربر پیدا نشد.'
  cd "$PKI_DIR"; export EASYRSA_BATCH=1 EASYRSA_PKI="$PKI_DIR/pki" EASYRSA_CRL_DAYS=3650
  ./easyrsa revoke "$name"
  ./easyrsa gen-crl
  install -m 644 pki/crl.pem "$OVPN_DIR/crl.pem"
  python3 - "$DATA_DIR/$name.json" <<'PY'
import json,sys,os
p=sys.argv[1]
try:
 d=json.load(open(p)); d['revoked']=True; d['blocked']=True; json.dump(d,open(p,'w')); os.chmod(p,0o644)
except FileNotFoundError: pass
PY
  if [[ -f "$DATA_DIR/$name.json" ]]; then ip=$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1])).get("ip",""))' "$DATA_DIR/$name.json");
    for spec in "-s $ip" "-d $ip"; do read -r flag addr <<< "$spec"; iptables -C FORWARD "$flag" "$addr" -j DROP 2>/dev/null || iptables -I FORWARD "$flag" "$addr" -j DROP; done
  fi
  rm -f "$CCD_DIR/$name"
  systemctl reload openvpn-server@server 2>/dev/null || systemctl restart openvpn-server@server
  echo "گواهی $name باطل شد؛ اتصال مجدد با آن باید رد شود. فایل کانفیگ را هم از دستگاه کاربر حذف کن."
}

list_clients(){
  need_root; echo 'نام | IP | اعتبار تا | مصرف | سقف | وضعیت'
  shopt -s nullglob
  for f in "$DATA_DIR"/*.json; do python3 - "$f" <<'PY'
import json,sys,datetime
try:
 d=json.load(open(sys.argv[1])); exp=datetime.datetime.fromtimestamp(d['expires_at']).strftime('%Y-%m-%d') if d.get('expires_at') else 'بدون انقضا'; used=d.get('used_bytes',0)/1073741824; q=d.get('quota_bytes',0)/1073741824; state='مسدود' if d.get('blocked') or d.get('revoked') else 'فعال'
 print(f"{d.get('name','?')} | {d.get('ip','?')} | {exp} | {used:.2f} GB | {q:.2f} GB" if q else f"{d.get('name','?')} | {d.get('ip','?')} | {exp} | {used:.2f} GB | نامحدود", '|',state)
except Exception: pass
PY
  done
}

status(){
  echo '--- سرویس ---'; systemctl --no-pager --full status openvpn-server@server 2>/dev/null | head -n 12 || true
  echo '--- پورت ---'; ss -lntp | grep -E ":${PORT:-21443}[[:space:]]" || true
  echo '--- کاربران متصل ---'; if [[ -r /var/log/openvpn/status.log ]]; then awk -F, '$1=="CLIENT_LIST" {print $2, $3, "RX=" $5, "TX=" $6}' /var/log/openvpn/status.log; else echo 'فایل وضعیت موجود نیست'; fi
  echo '--- زمان آخرین بررسی سهمیه ---'; systemctl --no-pager status openvpn-quota-check.timer 2>/dev/null | head -n 8 || true
}

menu(){
  while true; do
    echo; echo '===== OpenVPN Manager ====='; echo '1) نصب روی سرور تازه'; echo '2) ساخت کانفیگ کاربر'; echo '3) ابطال/حذف دسترسی کاربر'; echo '4) فهرست کاربران و مصرف'; echo '5) وضعیت سرویس و کاربران متصل'; echo '6) افزودن مدیریت به سرور موجود (با پشتیبان‌گیری)'; echo '0) خروج'
    read -rp 'انتخاب: ' n
    case "$n" in
      1) install_openvpn;;
      2) read -rp 'نام کاربر: ' a; read -rp 'اعتبار به روز (پیش‌فرض 365): ' b; b=${b:-365}; read -rp 'سقف حجم به GB (0=نامحدود): ' c; c=${c:-0}; add_client "$a" "$b" "$c";;
      3) read -rp 'نام کاربر برای ابطال: ' a; revoke_client "$a";;
      4) list_clients;; 5) status;; 6) adopt_existing;; 0) exit 0;; *) echo 'انتخاب نامعتبر';;
    esac
  done
}

case "${1:-menu}" in
  install) install_openvpn;;
  adopt|integrate) adopt_existing;;
  add) shift; add_client "${1:-}" "${2:-365}" "${3:-0}";;
  revoke|delete) shift; revoke_client "${1:-}";;
  list|clients) list_clients;;
  status) status;;
  menu) menu;;
  *) echo "استفاده: $0 {install|adopt|add NAME [DAYS] [QUOTA_GB]|revoke NAME|list|status|menu}"; exit 1;;
esac
