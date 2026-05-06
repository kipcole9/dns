#!/usr/bin/env bash
###############################################################################
# install.sh — one-line installer for ExDns.
#
# Usage:
#
#     curl -fsSL https://raw.githubusercontent.com/kipcole9/dns/main/contrib/install/install.sh | sudo bash
#
# Or, pinned to a version:
#
#     curl -fsSL https://raw.githubusercontent.com/kipcole9/dns/main/contrib/install/install.sh \
#       | sudo bash -s -- --version v0.2.0
#
# What it does:
#
#   1. Detects OS + arch.
#   2. Downloads the matching precompiled tarball from the
#      GitHub Release.
#   3. Creates an `exdns` system user.
#   4. Unpacks the release at /opt/exdns.
#   5. Drops the minimal runtime.exs (auto-generated cookie + paths).
#   6. Generates the first-run bootstrap code.
#   7. Installs and starts the systemd unit.
#   8. Prints the URL + bootstrap code for the operator to paste into
#      the Web UI's setup wizard.
#
# Re-run safe: detects an existing install and offers to update or
# bail. Doesn't touch /var/lib/exdns state.
###############################################################################

set -euo pipefail

REPO="kipcole9/dns"
INSTALL_PREFIX="/opt/exdns"
STATE_DIR="/var/lib/exdns"
ETC_DIR="/etc/exdns"
SYSTEMD_UNIT="/etc/systemd/system/exdns.service"
USER_NAME="exdns"

VERSION="latest"
NON_INTERACTIVE="${EXDNS_NON_INTERACTIVE:-0}"

# ----- helpers --------------------------------------------------------

red()    { printf "\033[31m%s\033[0m\n" "$*"; }
green()  { printf "\033[32m%s\033[0m\n" "$*"; }
yellow() { printf "\033[33m%s\033[0m\n" "$*"; }
bold()   { printf "\033[1m%s\033[0m\n" "$*"; }

die() {
  red "error: $*" >&2
  exit 1
}

require_root() {
  if [[ $EUID -ne 0 ]]; then
    die "this installer needs root (try: sudo bash $0)"
  fi
}

# ----- args -----------------------------------------------------------

while [[ $# -gt 0 ]]; do
  case "$1" in
    --version)  VERSION="$2"; shift 2 ;;
    --yes|-y)   NON_INTERACTIVE=1; shift ;;
    --help|-h)
      grep '^#' "$0" | sed 's/^# \?//'
      exit 0
      ;;
    *) die "unknown argument: $1" ;;
  esac
done

require_root

# ----- detect platform -----------------------------------------------

detect_target() {
  local os arch
  os="$(uname -s | tr '[:upper:]' '[:lower:]')"
  arch="$(uname -m)"

  case "${os}-${arch}" in
    linux-x86_64)         echo "linux-x86_64" ;;
    linux-aarch64)        echo "linux-aarch64" ;;
    linux-arm64)          echo "linux-aarch64" ;;
    darwin-arm64)         echo "macos-arm64" ;;
    *) die "unsupported platform: ${os}-${arch}" ;;
  esac
}

TARGET="$(detect_target)"
green "detected platform: ${TARGET}"

# ----- resolve release version + URL ---------------------------------

if [[ "$VERSION" == "latest" ]]; then
  green "resolving latest release tag…"
  VERSION="$(curl -fsSL "https://api.github.com/repos/${REPO}/releases/latest" \
             | grep -E '"tag_name":' \
             | head -1 \
             | sed -E 's/.*"tag_name": "([^"]+)".*/\1/')"
  [[ -z "$VERSION" ]] && die "couldn't resolve latest release"
fi

green "installing ExDns ${VERSION} (${TARGET})"

VERSION_NO_V="${VERSION#v}"
TARBALL="ex_dns-${VERSION_NO_V}-${TARGET}.tar.gz"
URL="https://github.com/${REPO}/releases/download/${VERSION}/${TARBALL}"
SHA_URL="${URL}.sha256"

# ----- detect existing install ---------------------------------------

if [[ -d "${INSTALL_PREFIX}/bin" ]]; then
  if [[ "$NON_INTERACTIVE" -eq 0 ]]; then
    yellow "existing install found at ${INSTALL_PREFIX}"
    read -rp "overwrite? (yes/N) " ans
    [[ "$ans" =~ ^[Yy]es$ ]] || die "aborting"
  fi
fi

# ----- download + verify ---------------------------------------------

WORK_DIR="$(mktemp -d)"
trap 'rm -rf "${WORK_DIR}"' EXIT

green "downloading ${URL}…"
curl -fsSL --output "${WORK_DIR}/${TARBALL}" "${URL}"

green "verifying SHA-256…"
curl -fsSL --output "${WORK_DIR}/${TARBALL}.sha256" "${SHA_URL}" || true

if [[ -s "${WORK_DIR}/${TARBALL}.sha256" ]]; then
  expected="$(awk '{print $1}' "${WORK_DIR}/${TARBALL}.sha256")"
  actual="$(shasum -a 256 "${WORK_DIR}/${TARBALL}" | awk '{print $1}')"
  [[ "$expected" == "$actual" ]] || die "checksum mismatch (expected ${expected}, got ${actual})"
else
  yellow "no .sha256 file published; skipping checksum verification"
fi

# ----- create runtime user + dirs ------------------------------------

if ! id -u "${USER_NAME}" >/dev/null 2>&1; then
  green "creating system user ${USER_NAME}"
  if command -v useradd >/dev/null 2>&1; then
    useradd --system --home "${STATE_DIR}" --shell /usr/sbin/nologin "${USER_NAME}"
  else
    # macOS / non-useradd systems
    yellow "useradd not found — create the ${USER_NAME} user manually if running on macOS"
  fi
fi

install -d -o root          -g root          -m 0755 "${INSTALL_PREFIX}"
install -d -o "${USER_NAME}" -g "${USER_NAME}" -m 0750 "${STATE_DIR}"
install -d -o root           -g "${USER_NAME}" -m 0750 "${ETC_DIR}"
install -d -o root           -g "${USER_NAME}" -m 0750 "${ETC_DIR}/zones.d"

# ----- unpack --------------------------------------------------------

green "unpacking release into ${INSTALL_PREFIX}"
tar -xzf "${WORK_DIR}/${TARBALL}" -C "${INSTALL_PREFIX}"
chown -R root:root "${INSTALL_PREFIX}"

# Allow the BEAM to bind low ports (53, 853, 443) without root.
if command -v setcap >/dev/null 2>&1; then
  beam="$(find "${INSTALL_PREFIX}/erts-"*/bin -maxdepth 1 -name beam.smp | head -1)"
  if [[ -n "$beam" ]]; then
    setcap 'cap_net_bind_service=+ep' "$beam" || \
      yellow "setcap failed; you may need to run ExDns as root or set CAP_NET_BIND_SERVICE on the unit"
  fi
fi

# ----- runtime config ------------------------------------------------

if [[ ! -f "${ETC_DIR}/runtime.exs" ]]; then
  green "writing minimal runtime config to ${ETC_DIR}/runtime.exs"
  # The release tarball ships the minimal config under
  # `releases/<version>/runtime.exs`; copy it to /etc as
  # the operator's editable file.
  src="$(find "${INSTALL_PREFIX}/releases" -name runtime.exs | head -1)"
  if [[ -z "$src" ]]; then
    die "couldn't find runtime.exs in the release tarball"
  fi
  install -m 0640 -o root -g "${USER_NAME}" "$src" "${ETC_DIR}/runtime.exs"
fi

# ----- release cookie ------------------------------------------------

if [[ ! -f "${STATE_DIR}/.cookie" ]]; then
  green "generating RELEASE_COOKIE"
  openssl rand -hex 32 > "${STATE_DIR}/.cookie"
  chown "${USER_NAME}:${USER_NAME}" "${STATE_DIR}/.cookie"
  chmod 0400 "${STATE_DIR}/.cookie"
fi

# ----- bootstrap code ------------------------------------------------

green "generating one-time bootstrap code"
BOOTSTRAP_CODE="$(openssl rand -base64 24 | tr -d '=+/' | cut -c1-32)"
echo "${BOOTSTRAP_CODE}" > "${STATE_DIR}/bootstrap.code"
chown "${USER_NAME}:${USER_NAME}" "${STATE_DIR}/bootstrap.code"
chmod 0600 "${STATE_DIR}/bootstrap.code"

# ----- systemd unit --------------------------------------------------

if command -v systemctl >/dev/null 2>&1; then
  if [[ ! -f "${SYSTEMD_UNIT}" ]]; then
    green "installing systemd unit"
    install -m 0644 \
      "${INSTALL_PREFIX}/contrib/systemd/exdns.service" \
      "${SYSTEMD_UNIT}" 2>/dev/null || \
      yellow "couldn't find contrib/systemd/exdns.service in the release; install the unit by hand"
  fi

  systemctl daemon-reload
  systemctl enable --now exdns || yellow "couldn't start exdns; check 'journalctl -u exdns'"
fi

# ----- exdns CLI on $PATH --------------------------------------------
# Symlink the operator CLI shell wrapper onto /usr/local/bin so operators
# can type `exdns status` after install. Wrapper talks to the running
# release via `bin/ex_dns rpc`.

for tool in exdns exdns-update; do
  src="${INSTALL_PREFIX}/contrib/install/bin/${tool}"
  if [[ -f "${src}" ]]; then
    install -m 0755 "${src}" "/usr/local/bin/${tool}"
    green "installed ${tool} → /usr/local/bin/${tool}"
  fi
done

# ----- finish --------------------------------------------------------

bold ""
bold "ExDns ${VERSION} installed."
bold ""
echo "Open the setup wizard:"
echo
echo "    http://$(hostname):4000/setup"
echo
echo "Bootstrap code (single-use; paste into the wizard):"
echo
echo "    ${BOOTSTRAP_CODE}"
echo
echo "After the wizard finishes, the bootstrap code is consumed and"
echo "${STATE_DIR}/bootstrap.code is deleted. To reissue it later:"
echo
echo "    sudo cd ${INSTALL_PREFIX} && ${INSTALL_PREFIX}/bin/ex_dns rpc 'ExDns.Bootstrap.generate!()'"
echo
green "done."
