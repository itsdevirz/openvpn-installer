# OpenVPN Manager for Ubuntu

The script supports two paths:

- `install`: install on a fresh Ubuntu server with no `/etc/openvpn/server/server.conf`.
- `adopt`: add client-management support to the existing server at `/etc/openvpn/server/server.conf`, with backups and an explicit confirmation prompt.

## Current server: adopt carefully

Upload both files to the current server. First make a separate backup of `/etc/openvpn` and `/etc/ufw` if possible. Then run:

```bash
chmod +x openvpn-manager.sh
sudo ./openvpn-manager.sh adopt
```

Read the prompt carefully and type `YES` only if you accept a brief VPN interruption while OpenVPN restarts. The script does not change the SSH port/rules. It backs up `server.conf` and the original CA certificate before changing the server's client-trust configuration. Existing unmanaged client names are allowed by the connect hook, while accounts created by this manager are subject to manager expiry/blocking.

The adoption path is intentionally restricted to the expected `10.8.0.0/24` server subnet and a readable `ca` file in the current config. If those checks fail, it stops instead of guessing. Because custom OpenVPN setups vary, review the output and test a new profile before relying on this for all users.

## Fresh Ubuntu server

```bash
chmod +x openvpn-manager.sh
sudo ./openvpn-manager.sh install
```

The installer detects the default internet interface, creates an Easy-RSA CA, configures TCP port `21443`, enables forwarding, configures UFW/NAT and enables the quota-check timer. It refuses to overwrite an existing server config.

## Commands

```bash
sudo ./openvpn-manager.sh menu
sudo ./openvpn-manager.sh add friend1 30 10
sudo ./openvpn-manager.sh add friend2 90 0
sudo ./openvpn-manager.sh list
sudo ./openvpn-manager.sh status
sudo ./openvpn-manager.sh revoke friend1
```

`add NAME DAYS QUOTA_GB`: `0` means unlimited volume. Profiles are saved under `/etc/openvpn/clients/`. Each generated profile contains private key material; transfer it securely. Anyone who obtains it can use that account until expiry, blocking or certificate revocation.

## Limits and cautions

- Per-client usage is sampled once per minute from OpenVPN's status log. A volume limit is approximate and can be exceeded slightly before the next check.
- The account list and counters are stored under `/var/lib/openvpn-manager/`.
- The manager assigns dedicated addresses starting at `10.8.0.10`; the server's dynamic pool is narrowed to `10.8.0.2–10.8.0.9` to avoid collisions. Existing clients should reconnect and be tested after adoption.
- Test a new profile on a second device. Keep your SSH session open throughout adoption and confirm port `9011` remains allowed.
