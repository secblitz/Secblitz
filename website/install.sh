#!/usr/bin/env bash
# Installs Secblitz on Linux:  curl -fsSL https://secblitz.lol/install.sh | bash
#                         or:  wget -qO- https://secblitz.lol/install.sh | bash
# The version and the SHA-256 of each package are written in when the website is
# built, from the files the release published (scripts/finalize-site.py).
set -euo pipefail

SECBLITZ_VERSION="@SECBLITZ_VERSION@"
SHA256_X64_DEB="@SHA256_X64_DEB@"
SHA256_X64_RPM="@SHA256_X64_RPM@"
SHA256_ARM64_DEB="@SHA256_ARM64_DEB@"
SHA256_ARM64_RPM="@SHA256_ARM64_RPM@"
DOWNLOAD_BASE="https://secblitz.lol/downloads"
OS_RELEASE_FILE="/etc/os-release"

WORK=""
FANCY=0
RESET="" BOLD="" DIM="" GREEN="" RED="" CYAN=""
OK_MARK="ok" BAD_MARK="failed"
FRAMES=('|' '/' '-' '\')
KIND="" ARCH_TAG="" EXPECTED_SHA="" PACKAGE_NAME="" PACKAGE_FILE="" IS_ROOT=0

cleanup() {
  if [ "$FANCY" -eq 1 ]; then
    printf '\033[?25h'
  fi
  if [ -n "$WORK" ] && [ -d "$WORK" ]; then
    rm -rf -- "$WORK"
  fi
}

setup_output() {
  if [ -t 1 ] && [ -z "${NO_COLOR:-}" ] && [ "${TERM:-dumb}" != "dumb" ]; then
    FANCY=1
    local esc=$'\033'
    RESET="${esc}[0m" BOLD="${esc}[1m" DIM="${esc}[2m"
    GREEN="${esc}[32m" RED="${esc}[31m" CYAN="${esc}[36m"
    case "${LC_ALL:-${LC_CTYPE:-${LANG:-}}}" in
      *[Uu][Tt][Ff]-8* | *[Uu][Tt][Ff]8*)
        OK_MARK="✓" BAD_MARK="✗"
        FRAMES=('⠋' '⠙' '⠹' '⠸' '⠼' '⠴' '⠦' '⠧' '⠇' '⠏')
        ;;
      *)
        OK_MARK="+" BAD_MARK="x"
        ;;
    esac
    printf '\033[?25l'
  fi
}

header() {
  if [ "$FANCY" -eq 1 ]; then
    printf '\n  %s%sSecblitz%s %sinstaller for Linux%s\n\n' "$BOLD" "$CYAN" "$RESET" "$DIM" "$RESET"
  else
    printf 'Secblitz installer for Linux\n\n'
  fi
}

die() {
  printf '%s\n' "$*" >&2
  exit 1
}

# Runs one step. Output goes to a log, never to the screen. A step that fails
# can leave its own explanation in $WORK/why; otherwise the given text is used.
run_step() {
  local label=$1 failure=$2 detail=""
  shift 2
  local log="$WORK/step.log" rc=0 pid i=0 count=${#FRAMES[@]}
  rm -f -- "$WORK/why"
  if [ "$FANCY" -eq 1 ]; then
    "$@" >"$log" 2>&1 </dev/null &
    pid=$!
    while kill -0 "$pid" 2>/dev/null; do
      printf '\r\033[K  %s%s%s %s' "$CYAN" "${FRAMES[$((i % count))]}" "$RESET" "$label"
      i=$((i + 1))
      sleep 0.1
    done
    wait "$pid" || rc=$?
    printf '\r\033[K'
  else
    printf '%s... ' "$label"
    "$@" >"$log" 2>&1 </dev/null || rc=$?
  fi
  [ -f "$WORK/detail" ] && detail=$(cat "$WORK/detail") && rm -f -- "$WORK/detail"
  if [ "$rc" -eq 0 ]; then
    if [ "$FANCY" -eq 1 ]; then
      printf '  %s%s%s %s' "$GREEN" "$OK_MARK" "$RESET" "$label"
      [ -n "$detail" ] && printf '  %s%s%s' "$DIM" "$detail" "$RESET"
      printf '\n'
    else
      printf 'done%s\n' "${detail:+ ($detail)}"
    fi
    return 0
  fi
  if [ "$FANCY" -eq 1 ]; then
    printf '  %s%s%s %s\n' "$RED" "$BAD_MARK" "$RESET" "$label"
  else
    printf 'failed\n'
  fi
  [ -f "$WORK/why" ] && failure=$(cat "$WORK/why")
  printf '\n%s\n' "$failure" >&2
  exit 1
}

lowercase() {
  printf '%s' "$1" | tr '[:upper:]' '[:lower:]'
}

os_field() {
  local value
  value=$(sed -n "s/^$1=//p" "$OS_RELEASE_FILE" | tail -n 1) || true
  value=${value%\"}
  value=${value#\"}
  value=${value%\'}
  value=${value#\'}
  printf '%s' "$value"
}

package_kind() {
  local id like name
  id=$(lowercase "$(os_field ID)")
  like=$(lowercase "$(os_field ID_LIKE)")
  for name in $id $like; do
    case "$name" in
      debian | ubuntu | linuxmint | pop | raspbian)
        printf 'deb'
        return 0
        ;;
      fedora | rhel | centos)
        printf 'rpm'
        return 0
        ;;
    esac
  done
  return 1
}

detect_system() {
  local machine pretty cpu_text
  if [ ! -r "$OS_RELEASE_FILE" ] && [ "$OS_RELEASE_FILE" = "/etc/os-release" ]; then
    OS_RELEASE_FILE="/usr/lib/os-release"
  fi
  if ! KIND=$(package_kind); then
    printf 'Secblitz does not support this kind of Linux yet. It works on Ubuntu, Debian, Linux Mint and Fedora.\n' >"$WORK/why"
    return 1
  fi
  machine=$(uname -m)
  case "$machine" in
    x86_64 | amd64)
      ARCH_TAG="x64"
      cpu_text="64-bit Intel or AMD"
      ;;
    aarch64 | arm64)
      ARCH_TAG="arm64"
      cpu_text="64-bit ARM"
      ;;
    *)
      printf 'Secblitz does not support this kind of computer yet (%s). It needs a 64-bit Intel, AMD or ARM processor.\n' "$machine" >"$WORK/why"
      return 1
      ;;
  esac
  case "$KIND" in
    deb)
      if ! command -v apt-get >/dev/null 2>&1; then
        printf 'This computer looks like Ubuntu or Debian, but the tool that installs programs is missing.\n' >"$WORK/why"
        return 1
      fi
      ;;
    rpm)
      if ! command -v dnf >/dev/null 2>&1; then
        printf 'This computer looks like Fedora, but the tool that installs programs is missing.\n' >"$WORK/why"
        return 1
      fi
      ;;
  esac
  pretty=$(os_field PRETTY_NAME)
  printf '%s, %s' "${pretty:-Linux}" "$cpu_text" >"$WORK/detail"
  printf '%s %s\n' "$KIND" "$ARCH_TAG" >"$WORK/system"
}

# Ubuntu comes with wget but not curl; Fedora comes with curl.
download_package() {
  if command -v curl >/dev/null 2>&1; then
    curl --fail --silent --show-error --location --proto '=https' --tlsv1.2 \
      --connect-timeout 20 --retry 2 \
      --output "$PACKAGE_FILE" "$DOWNLOAD_BASE/$PACKAGE_NAME"
  else
    wget --quiet --https-only --timeout=20 --tries=3 \
      --output-document="$PACKAGE_FILE" "$DOWNLOAD_BASE/$PACKAGE_NAME"
  fi
}

check_download() {
  local actual
  actual=$(sha256sum "$PACKAGE_FILE" | cut -d' ' -f1) || return 1
  if [ "$actual" != "$EXPECTED_SHA" ]; then
    printf 'The downloaded file is not the one we published, so nothing was installed. Please try again in a few minutes. If it keeps happening, write to support@secblitz.lol.\n' >"$WORK/why"
    return 1
  fi
}

as_root() {
  if [ "$IS_ROOT" -eq 1 ]; then
    "$@"
  else
    sudo "$@"
  fi
}

install_package() {
  local safe rc=0 actual
  safe=$(as_root mktemp -d /var/tmp/secblitz-install.XXXXXX) || return 1
  as_root chmod 755 "$safe" || rc=1
  # The administrator installs a copy that only the administrator can change,
  # and checks it again, so nothing can swap the file after the first check.
  if [ "$rc" -eq 0 ]; then
    as_root install -m 644 "$PACKAGE_FILE" "$safe/$PACKAGE_NAME" || rc=1
  fi
  if [ "$rc" -eq 0 ]; then
    actual=$(as_root sha256sum "$safe/$PACKAGE_NAME" | cut -d' ' -f1) || actual=""
    if [ "$actual" != "$EXPECTED_SHA" ]; then
      printf 'The downloaded file changed while it was being installed, so nothing was installed. Please run the command again.\n' >"$WORK/why"
      rc=1
    fi
  fi
  if [ "$rc" -eq 0 ]; then
    cd "$safe" || rc=1
  fi
  if [ "$rc" -eq 0 ]; then
    case "$KIND" in
      deb) as_root env DEBIAN_FRONTEND=noninteractive apt-get install -y "./$PACKAGE_NAME" || rc=1 ;;
      rpm) as_root dnf install -y "./$PACKAGE_NAME" || rc=1 ;;
    esac
  fi
  cd "$WORK" || true
  as_root rm -rf -- "$safe" || true
  return "$rc"
}

main() {
  trap cleanup EXIT
  trap 'exit 130' INT TERM

  if [ "${BASH_VERSINFO[0]:-0}" -lt 4 ]; then
    die "This installer needs bash 4 or newer. Please run it with a newer bash."
  fi
  if [ "$(uname -s)" != "Linux" ]; then
    die "This installer is for Linux. Visit https://secblitz.lol to download Secblitz for Windows."
  fi
  if ! command -v sha256sum >/dev/null 2>&1; then
    die "This installer needs the tool \"sha256sum\", which is missing. Install it with your package manager and run the command again."
  fi
  if ! command -v curl >/dev/null 2>&1 && ! command -v wget >/dev/null 2>&1; then
    die "This installer needs \"curl\" or \"wget\" to download Secblitz, and neither is installed. Install one with your package manager and run the command again."
  fi
  case "$SECBLITZ_VERSION" in
    [0-9]*.[0-9]*.[0-9]*) ;;
    *) die "This copy of the installer is incomplete. Get a fresh one from https://secblitz.lol." ;;
  esac

  WORK=$(mktemp -d) || die "Could not make a temporary folder."
  chmod 755 "$WORK"
  setup_output
  header

  run_step "Detecting your system" "Could not tell what kind of computer this is." detect_system
  read -r KIND ARCH_TAG <"$WORK/system"

  case "$ARCH_TAG-$KIND" in
    x64-deb) EXPECTED_SHA=$SHA256_X64_DEB ;;
    x64-rpm) EXPECTED_SHA=$SHA256_X64_RPM ;;
    arm64-deb) EXPECTED_SHA=$SHA256_ARM64_DEB ;;
    arm64-rpm) EXPECTED_SHA=$SHA256_ARM64_RPM ;;
    *) die "Secblitz does not support this computer yet." ;;
  esac
  case "$EXPECTED_SHA" in
    *[!0-9a-f]* | "") die "This copy of the installer is incomplete. Get a fresh one from https://secblitz.lol." ;;
  esac
  if [ "${#EXPECTED_SHA}" -ne 64 ]; then
    die "This copy of the installer is incomplete. Get a fresh one from https://secblitz.lol."
  fi
  PACKAGE_NAME="secblitz-$SECBLITZ_VERSION-linux-$ARCH_TAG.$KIND"
  PACKAGE_FILE="$WORK/$PACKAGE_NAME"

  run_step "Downloading Secblitz $SECBLITZ_VERSION" \
    "The download did not work. Check your internet connection and run the command again." \
    download_package
  chmod 644 "$PACKAGE_FILE"

  run_step "Checking the download" "The downloaded file could not be checked." check_download

  if [ "$(id -u)" -eq 0 ]; then
    IS_ROOT=1
  else
    if ! command -v sudo >/dev/null 2>&1; then
      die "Installing needs administrator permission, and this computer cannot ask for it. Run the same command again while signed in as the administrator."
    fi
    printf '\nInstalling a program changes system files, so your computer needs your password.\n'
    printf 'It is only used to install Secblitz.\n\n'
    sudo -v </dev/null || die "Could not get permission to install. Run the command again and enter your password when asked."
  fi

  run_step "Installing Secblitz" \
    "The installation did not finish. Nothing else on your computer was changed by this installer. Run the command again, or write to support@secblitz.lol." \
    install_package

  if [ "$FANCY" -eq 1 ]; then
    printf '\n  %s%sSecblitz %s is ready.%s\n  Open Secblitz from your app menu to get started.\n\n' "$BOLD" "$GREEN" "$SECBLITZ_VERSION" "$RESET"
  else
    printf '\nSecblitz %s is ready.\nOpen Secblitz from your app menu to get started.\n' "$SECBLITZ_VERSION"
  fi
}

main "$@"
