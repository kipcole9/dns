# I want to block ads on my LAN

The pi-hole-shaped path. Five minutes from a fresh
Raspberry Pi to ad-blocking on every device on your
network.

## What you'll have when you're done

* DNS server running on your Pi (or other always-on box).
* Subscribed to a maintained adlist.
* Every device on your LAN that points its DNS at the Pi
  gets ads blocked at the network level.
* A web dashboard at `http://<pi>:4000` showing how
  much was blocked and a "pause" button for when ads
  are inexplicably the right answer.

## Steps

### 1. Install (60 seconds)

On the Pi:

```bash
curl -fsSL https://raw.githubusercontent.com/kipcole9/dns/main/contrib/install/install.sh | sudo bash
```

The installer prints the URL of the setup wizard plus a
one-time bootstrap code.

### 2. Open the wizard

Open the URL on your laptop. Paste the bootstrap code,
create an admin email + password, pick **Block ads on
my LAN**, click "Finish setup".

The wizard auto-detects your LAN, subscribes the
[Steven Black unified hosts list](https://github.com/StevenBlack/hosts)
and binds it to your LAN's CIDR. By the time you land on
the dashboard, ad-blocking is on.

### 3. Point your devices at the Pi

Two ways:

* **Easy**: in your router's admin UI, set the LAN
  DNS server to the Pi's IP. Every device that uses
  DHCP picks it up.

* **Per-device**: on a phone or laptop, set the Wi-Fi
  network's DNS to the Pi's IP manually. Useful for
  testing one device before flipping the whole house.

### 4. Verify it's working

From any device on the LAN:

```bash
dig doubleclick.net
```

You should see `status: NXDOMAIN` (or whatever
[block response](../09-blackhole-filtering.md#block-response-choices)
you configured). Now try a normal site:

```bash
dig example.com
```

Should resolve normally.

### 5. Refine over time

* The dashboard shows the most-blocked and most-active
  clients. Notice anything weird? Investigate.
* Some sites you trust might use a tracker on a known
  blocklist. Add them to the **Allowlist** under the
  BlackHole tab.
* When ad-blocking breaks something and you need to
  bypass for a minute, hit **Pause plugins** on the
  dashboard.

## When it goes wrong

* **`exdns doctor`** from any terminal on the Pi
  surfaces config / zone / DNSSEC / cert issues with
  fix suggestions.
* **Pause plugins** for an hour and DNS reverts to
  pure pass-through. Useful while you debug.
* **`exdns status`** confirms the server is running
  and what it's serving.

## Where to go next

* [I want to host my own domain](host-a-domain.md) —
  the same install can also be authoritative for a
  domain you own.
* [BlackHole filtering](../09-blackhole-filtering.md) —
  full feature reference for the ad-block plugin.
* [Monitoring & observability](../10-monitoring-and-observability.md) —
  if you want to graph ad-blocking over time.
