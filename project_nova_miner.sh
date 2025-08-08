#!/data/data/com.termux/files/usr/bin/bash
# If running outside Termux, /usr/bin/env bash fallback:
if [ ! -x /data/data/com.termux/files/usr/bin/bash ] && command -v /usr/bin/env >/dev/null 2>&1; then
  exec /usr/bin/env bash "$0" "$@"
fi
#
# Project Nova - Monolithic All-in-One Auto Verus Miner for Termux/Ubuntu
# Complete single-file implementation (detection, installer, miner control,
# watchdog, notifier, storage, config, menu, auto-update, logging).
#
# Save as project_nova_miner.sh, chmod +x, then run:
# ./project_nova_miner.sh
#
set -euo pipefail
IFS=$'\n\t'

# -------------------------
# === Color & Globals ===
# -------------------------
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

# Paths & files
HOME_DIR="${HOME:-/root}"
CONFIG_DIR="$HOME_DIR/.nova_miner_data"
LOG_DIR="$CONFIG_DIR/logs"
MINER_BIN_DIR="$CONFIG_DIR/miner_bin"
MINER_BIN_NAME="verus-miner"
CONFIG_FILE="$CONFIG_DIR/config.conf"
RUN_INFO_FILE="$CONFIG_DIR/run.info"
MINER_LOG="$LOG_DIR/miner.log"
WATCHDOG_LOG="$LOG_DIR/watchdog.log"
ERROR_LOG="$LOG_DIR/errors.log"
MINER_PID_FILE="$CONFIG_DIR/miner.pid"
WATCHDOG_PID_FILE="$CONFIG_DIR/watchdog.pid"
SCRIPT_VERSION="1.2.0-nova"
GITHUB_REPO="MrNova420/verus-miner-termux"  # set your repo

# Defaults (overridden by config)
WALLET_ADDRESS="${WALLET_ADDRESS:-}"
POOL_URL="${POOL_URL:-}"
MINER_ARGS="${MINER_ARGS:-}"
THREADS="${THREADS:-0}"
MINER_MODE="${MINER_MODE:-balanced}"
CPU_ARCH="${CPU_ARCH:-unknown}"
ROOT_ACCESS=0
IS_TERMUX=0

# Ensure directories
mkdir -p "$CONFIG_DIR" "$LOG_DIR" "$MINER_BIN_DIR"

# -------------------------
# === Utility Functions ===
# -------------------------
color_echo() {
  local color="$1"; shift
  echo -e "${color}$*${NC}"
}

print_banner() {
  clear
  echo -e "${GREEN}==========================================="
  echo -e "    Project Nova - Auto Verus Miner"
  echo -e "    Version: $SCRIPT_VERSION"
  echo -e "===========================================${NC}"
}

pause() {
  read -rp "Press Enter to continue..."
}

log_error() {
  echo "$(date '+%Y-%m-%d %H:%M:%S') ERROR: $*" >> "$ERROR_LOG"
}

# -------------------------
# === Config Load/Save ===
# -------------------------
save_config() {
  cat > "$CONFIG_FILE" <<EOF
WALLET_ADDRESS="${WALLET_ADDRESS:-}"
POOL_URL="${POOL_URL:-}"
MINER_ARGS="${MINER_ARGS:-}"
THREADS=${THREADS:-0}
MINER_MODE="${MINER_MODE:-balanced}"
GITHUB_REPO="${GITHUB_REPO}"
MINER_BIN_NAME="${MINER_BIN_NAME}"
EOF
  color_echo $GREEN "[✓] Configuration saved to $CONFIG_FILE"
}

load_config() {
  if [ -f "$CONFIG_FILE" ]; then
    # shellcheck disable=SC1090
    source "$CONFIG_FILE"
  fi
}

write_run_info() {
  local status="${1:-unknown}"
  local errcode="${2:-0}"
  local runtime=0
  if [ -f "$MINER_PID_FILE" ]; then
    local pid
    pid=$(cat "$MINER_PID_FILE" 2>/dev/null || echo "")
    if [ -n "$pid" ]; then
      runtime=$(ps -o etimes= -p "$pid" 2>/dev/null || echo 0)
    fi
  fi
  local cpu_model mem_total mem_free
  cpu_model=$(awk -F: '/model name/ {print $2; exit}' /proc/cpuinfo 2>/dev/null || echo "unknown")
  mem_total=$(grep MemTotal /proc/meminfo 2>/dev/null | awk '{print $2}' || echo 0)
  mem_free=$(grep MemFree /proc/meminfo 2>/dev/null | awk '{print $2}' || echo 0)
  local hash_rate="N/A"
  if [ -f "$MINER_LOG" ]; then
    hash_rate=$(tail -n 50 "$MINER_LOG" | grep -oE '[0-9]+(\.[0-9]+)?[kM]?H/s' | tail -n1 || true)
    [ -z "$hash_rate" ] && hash_rate="N/A"
  fi
  cat > "$RUN_INFO_FILE" <<EOF
Last Run Timestamp: $(date +"%Y-%m-%d %H:%M:%S")
Status: $status
Error Code: $errcode
Runtime Seconds: $runtime
CPU Model: $cpu_model
Memory Total KB: $mem_total
Memory Free KB: $mem_free
Threads: $THREADS
Wallet: $WALLET_ADDRESS
Pool URL: $POOL_URL
Miner Mode: $MINER_MODE
Hash Rate (approx): $hash_rate
EOF
}

show_run_info() {
  print_banner
  echo -e "${CYAN}Last run details:${NC}"
  if [ -f "$RUN_INFO_FILE" ]; then
    cat "$RUN_INFO_FILE"
  else
    echo "No run.info found."
  fi
  pause
}

# -------------------------
# === Environment Detection ===
# -------------------------
detect_root() {
  if [ "$(id -u)" -eq 0 ] || command -v sudo >/dev/null 2>&1; then
    ROOT_ACCESS=1
  else
    ROOT_ACCESS=0
  fi
}

detect_cpu_arch() {
  local arch
  arch=$(uname -m 2>/dev/null || echo unknown)
  case "$arch" in
    aarch64|arm64) CPU_ARCH="arm64" ;;
    armv7l|armv7*) CPU_ARCH="armv7" ;;
    x86_64) CPU_ARCH="x86_64" ;;
    i686|i386) CPU_ARCH="x86" ;;
    *) CPU_ARCH="$arch" ;;
  esac
}

detect_os_and_termux() {
  if grep -qi "Android" /proc/version 2>/dev/null || [ -n "${ANDROID_ROOT:-}" ]; then
    OS_TYPE="android"
  elif [ -f /etc/os-release ]; then
    . /etc/os-release
    OS_TYPE="${NAME:-linux}"
  else
    OS_TYPE="$(uname -s)"
  fi
  # Termux detection
  if command -v termux-notification >/dev/null 2>&1 || [ -n "${PREFIX:-}" ] && echo "$PREFIX" | grep -q "com.termux"; then
    IS_TERMUX=1
  else
    IS_TERMUX=0
  fi
}

detect_environment() {
  detect_root
  detect_cpu_arch
  detect_os_and_termux
  color_echo $CYAN "[*] Detected: OS=$OS_TYPE ARCH=$CPU_ARCH TERMUX=$IS_TERMUX ROOT=$ROOT_ACCESS"
}

# -------------------------
# === Dependency & Installer ===
# -------------------------
check_dependencies() {
  local deps=(curl jq git bc)
  local miss=0
  for dep in "${deps[@]}"; do
    if ! command -v "$dep" >/dev/null 2>&1; then
      color_echo $YELLOW "[!] Missing dependency: $dep"
      miss=1
    fi
  done
  if [ $miss -eq 1 ]; then
    if [ "$IS_TERMUX" -eq 1 ]; then
      color_echo $CYAN "[*] Attempting to install missing packages with pkg..."
      pkg update -y || true
      pkg install -y "${deps[*]}" || color_echo $RED "[!] Auto-install partially failed; please install dependencies manually."
    else
      color_echo $CYAN "[*] Attempt to install missing packages with apt (requires sudo)..."
      if command -v sudo >/dev/null 2>&1; then
        sudo apt update -y || true
        sudo apt install -y "${deps[*]}" || color_echo $RED "[!] apt install failed; please install dependencies manually."
      else
        color_echo $YELLOW "[!] Missing sudo; please install dependencies manually."
      fi
    fi
  else
    color_echo $GREEN "[✓] Dependencies OK."
  fi
}

check_termux_api() {
  if [ "$IS_TERMUX" -eq 1 ] && ! command -v termux-notification >/dev/null 2>&1; then
    color_echo $YELLOW "[!] termux-api not installed. Some features will be limited."
    return 1
  fi
  return 0
}

termux_storage_setup() {
  if [ "$IS_TERMUX" -eq 1 ] && command -v termux-setup-storage >/dev/null 2>&1; then
    read -rp "Request Termux storage access now? (recommended) [Y/n]: " yn
    yn="${yn:-Y}"
    if [[ "$yn" =~ ^[Yy] ]]; then
      termux-setup-storage || color_echo $YELLOW "[i] termux-setup-storage returned non-zero; ensure you grant permission in Android."
      color_echo $GREEN "[✓] Storage access requested."
    fi
  fi
}

miner_download_url_for_arch() {
  local arch="$1"
  case "$arch" in
    arm64) echo "https://github.com/$GITHUB_REPO/releases/latest/download/verus-miner-arm64" ;;
    armv7) echo "https://github.com/$GITHUB_REPO/releases/latest/download/verus-miner-armv7" ;;
    x86) echo "https://github.com/$GITHUB_REPO/releases/latest/download/verus-miner-x86" ;;
    x86_64) echo "https://github.com/$GITHUB_REPO/releases/latest/download/verus-miner-x86_64" ;;
    *) echo "" ;;
  esac
}

download_miner_binary() {
  color_echo $CYAN "[*] Downloading miner binary for arch $CPU_ARCH..."
  local url
  url="$(miner_download_url_for_arch "$CPU_ARCH")"
  if [ -z "$url" ]; then
    color_echo $RED "[!] Unsupported arch or no URL available for $CPU_ARCH. Place binary manually in $MINER_BIN_DIR/$MINER_BIN_NAME"
    return 1
  fi
  local out="$MINER_BIN_DIR/$MINER_BIN_NAME"
  if curl -fSL --retry 3 -o "$out" "$url"; then
    chmod +x "$out"
    color_echo $GREEN "[✓] Miner binary downloaded to $out"
    return 0
  else
    color_echo $RED "[!] Failed to download miner from $url"
    log_error "Failed miner download: $url"
    return 1
  fi
}

check_miner_binary() {
  if [ -x "$MINER_BIN_DIR/$MINER_BIN_NAME" ]; then
    color_echo $GREEN "[✓] Miner binary present: $MINER_BIN_DIR/$MINER_BIN_NAME"
    return 0
  fi
  read -rp "Miner binary not found. Download now? [Y/n]: " yn
  yn="${yn:-Y}"
  if [[ "$yn" =~ ^[Yy] ]]; then
    download_miner_binary || return 1
  else
    color_echo $YELLOW "[i] Please provide miner binary at $MINER_BIN_DIR/$MINER_BIN_NAME"
    return 1
  fi
}

# -------------------------
# === Validation Helpers ===
# -------------------------
validate_wallet() {
  if [[ "${WALLET_ADDRESS:-}" =~ ^R[a-zA-Z0-9]{33,35}$ ]]; then
    return 0
  else
    return 1
  fi
}

validate_pool_url() {
  if [[ "${POOL_URL:-}" =~ ^[a-zA-Z0-9\.\-]+(:[0-9]{1,5})?$ ]]; then
    return 0
  else
    return 1
  fi
}

validate_threads() {
  local max
  max=$(nproc 2>/dev/null || echo 1)
  if [[ "$THREADS" =~ ^[0-9]+$ ]] && [ "$THREADS" -ge 1 ] && [ "$THREADS" -le "$max" ]; then
    return 0
  else
    return 1
  fi
}

# -------------------------
# === Miner Control ===
# -------------------------
_start_miner_background() {
  local cmd="$1"
  nohup bash -c "$cmd" > "$MINER_LOG" 2>&1 &
  local pid=$!
  echo "$pid" > "$MINER_PID_FILE"
  color_echo $GREEN "[✓] Miner started (PID $pid). Logs: $MINER_LOG"
  write_run_info "running" 0
}

start_miner() {
  if ! validate_wallet; then
    color_echo $RED "[!] Invalid or missing wallet. Configure wallet first."
    return 1
  fi
  if ! validate_pool_url; then
    color_echo $RED "[!] Invalid or missing pool URL. Configure pool first."
    return 1
  fi
  if [ -f "$MINER_PID_FILE" ]; then
    local pid
    pid=$(cat "$MINER_PID_FILE" 2>/dev/null || echo "")
    if [ -n "$pid" ] && kill -0 "$pid" 2>/dev/null; then
      color_echo $YELLOW "[*] Miner is already running (PID $pid)."
      return 0
    fi
  fi
  if ! check_miner_binary; then
    return 1
  fi
  if ! validate_threads; then
    if [ -z "${THREADS:-}" ] || [ "$THREADS" -le 0 ]; then
      THREADS=$(nproc 2>/dev/null || echo 1)
    else
      color_echo $RED "[!] Invalid thread count. Use configure to set a correct number."
      return 1
    fi
  fi
  local bin="$MINER_BIN_DIR/$MINER_BIN_NAME"
  local cmd="\"$bin\" --wallet \"$WALLET_ADDRESS\" --pool \"$POOL_URL\" --threads \"$THREADS\" $MINER_ARGS"
  _start_miner_background "$cmd"
}

stop_miner() {
  if [ -f "$MINER_PID_FILE" ]; then
    local pid
    pid=$(cat "$MINER_PID_FILE" 2>/dev/null || echo "")
    if [ -n "$pid" ] && kill -0 "$pid" 2>/dev/null; then
      color_echo $YELLOW "[*] Stopping miner (PID $pid)..."
      kill "$pid" || true
      sleep 2
      if kill -0 "$pid" 2>/dev/null; then
        color_echo $RED "[!] Miner did not stop; forcing kill..."
        kill -9 "$pid" || true
      fi
    fi
    rm -f "$MINER_PID_FILE"
    write_run_info "stopped" 0
    color_echo $GREEN "[✓] Miner stopped."
  else
    color_echo $YELLOW "[*] Miner not running."
  fi
}

miner_status() {
  print_banner
  if [ -f "$MINER_PID_FILE" ]; then
    local pid
    pid=$(cat "$MINER_PID_FILE" 2>/dev/null || echo "")
    if [ -n "$pid" ] && kill -0 "$pid" 2>/dev/null; then
      echo -e "${GREEN}Miner running (PID: $pid)${NC}"
      echo "Threads: $THREADS"
      echo "Wallet: $WALLET_ADDRESS"
      echo "Pool: $POOL_URL"
      echo "Mode: $MINER_MODE"
      echo "Log tail (last 10 lines):"
      tail -n 10 "$MINER_LOG" || true
    else
      color_echo $YELLOW "[*] PID present but process not running."
    fi
  else
    color_echo $RED "Miner is not running."
  fi
  pause
}

restart_miner() {
  stop_miner
  sleep 1
  start_miner
}

# -------------------------
# === Watchdog & Recovery ===
# -------------------------
log_watchdog() {
  local msg="$1"
  echo "$(date '+%Y-%m-%d %H:%M:%S') $msg" >> "$WATCHDOG_LOG"
}

notify_user() {
  local msg="$1"
  local title="${2:-Project Nova Alert}"
  if [ "$IS_TERMUX" -eq 1 ] && command -v termux-notification >/dev/null 2>&1; then
    termux-notification --title "$title" --content "$msg" --priority high || true
  else
    echo -e "${YELLOW}[NOTIFY]${NC} $title - $msg"
    if command -v notify-send >/dev/null 2>&1; then
      notify-send "$title" "$msg" || true
    fi
  fi
  log_watchdog "NOTIFY: $msg"
}

watchdog_loop() {
  local INTERVAL=60
  color_echo $CYAN "[*] Watchdog started (interval ${INTERVAL}s)."
  while true; do
    # Miner alive check
    if [ ! -f "$MINER_PID_FILE" ] || ! (pid=$(cat "$MINER_PID_FILE" 2>/dev/null) && kill -0 "$pid" 2>/dev/null); then
      color_echo $RED "[!] Miner process not found, attempting restart..."
      log_watchdog "[Miner missing - restart]"
      restart_miner && notify_user "Miner restarted by watchdog" || notify_user "Watchdog failed to restart miner"
      sleep 5
    fi

    # Termux checks: battery/temp when available
    if [ "$IS_TERMUX" -eq 1 ] && command -v termux-battery-status >/dev/null 2>&1; then
      battery_info="$(termux-battery-status 2>/dev/null || echo '{}')"
      battery_level=$(echo "$battery_info" | jq '.percentage' 2>/dev/null || echo 100)
      charging=$(echo "$battery_info" | jq '.plugged' 2>/dev/null || echo false)
      if [ -n "$battery_level" ] && [ "$battery_level" -lt 15 ] && [ "$charging" != "true" ]; then
        color_echo $YELLOW "[!] Low battery ($battery_level%). Pausing miner."
        log_watchdog "[Low battery $battery_level% - paused miner]"
        stop_miner
        notify_user "Miner paused: battery $battery_level%"
      fi
    fi

    # Temperature check (Termux sensor)
    if [ "$IS_TERMUX" -eq 1 ] && command -v termux-sensor >/dev/null 2>&1; then
      cpu_temp=$(termux-sensor | jq -r '.[] | select(.name=="cpu_temperature") | .value' 2>/dev/null || echo "")
      if [ -n "$cpu_temp" ]; then
        if awk "BEGIN {exit !($cpu_temp > 75)}"; then
          color_echo $YELLOW "[!] High CPU temp: ${cpu_temp}C. Pausing miner."
          log_watchdog "[High temp ${cpu_temp}C - paused miner]"
          stop_miner
          notify_user "Miner paused: high CPU temp ${cpu_temp}C"
        fi
      fi
    fi

    # Disk space
    avail=$(df -k "$CONFIG_DIR" 2>/dev/null | awk 'NR==2 {print $4}' || echo 0)
    if [ -n "$avail" ] && [ "$avail" -lt 10240 ]; then
      log_watchdog "[Low disk space: ${avail}KB]"
      notify_user "Low disk space: ${avail}KB in $CONFIG_DIR"
    fi

    sleep "$INTERVAL"
  done
}

watchdog_start() {
  if [ -f "$WATCHDOG_PID_FILE" ]; then
    local pid
    pid=$(cat "$WATCHDOG_PID_FILE" 2>/dev/null || echo "")
    if [ -n "$pid" ] && kill -0 "$pid" 2>/dev/null; then
      color_echo $YELLOW "[*] Watchdog already running (PID $pid)."
      return 0
    fi
  fi
  watchdog_loop & disown
  echo "$!" > "$WATCHDOG_PID_FILE"
  color_echo $GREEN "[✓] Watchdog started (PID $!)."
}

watchdog_stop() {
  if [ -f "$WATCHDOG_PID_FILE" ]; then
    local pid
    pid=$(cat "$WATCHDOG_PID_FILE" 2>/dev/null || echo "")
    if [ -n "$pid" ]; then
      kill "$pid" 2>/dev/null || true
      rm -f "$WATCHDOG_PID_FILE"
      color_echo $GREEN "[✓] Watchdog stopped."
    fi
  else
    color_echo $YELLOW "[*] Watchdog not running."
  fi
}

# -------------------------
# === Auto-update ===
# -------------------------
check_script_update() {
  color_echo $CYAN "[*] Checking for script updates..."
  local latest_version
  latest_version=$(curl -fsSL "https://raw.githubusercontent.com/$GITHUB_REPO/main/version.txt" 2>/dev/null || echo "")
  if [ -z "$latest_version" ]; then
    color_echo $YELLOW "[i] Could not fetch latest version info."
    return 1
  fi
  if [ "$latest_version" != "$SCRIPT_VERSION" ]; then
    color_echo $GREEN "[✓] New version available: $latest_version. Updating..."
    update_script
    return 0
  else
    color_echo $GREEN "[✓] Script is up to date."
    return 1
  fi
}

update_script() {
  local script_url="https://raw.githubusercontent.com/$GITHUB_REPO/main/project_nova_miner.sh"
  if curl -fsSL "$script_url" -o "$CONFIG_DIR/project_nova_miner.sh.tmp"; then
    mv "$CONFIG_DIR/project_nova_miner.sh.tmp" "$0"
    chmod +x "$0"
    color_echo $GREEN "[✓] Script updated successfully. Restarting..."
    exec "$0" "$@"
  else
    color_echo $RED "[!] Failed to download updated script."
    return 1
  fi
}

# -------------------------
# === Notification / Email ===
# -------------------------
send_email() {
  local to="$1"
  local subject="$2"
  local body="$3"
  if command -v sendmail >/dev/null 2>&1; then
    {
      printf "Subject: %s\n" "$subject"
      printf "To: %s\n" "$to"
      printf "\n"
      printf "%s\n" "$body"
    } | sendmail -t
    return $?
  elif command -v ssmtp >/dev/null 2>&1; then
    {
      printf "To: %s\n" "$to"
      printf "Subject: %s\n" "$subject"
      printf "\n"
      printf "%s\n" "$body"
    } | ssmtp "$to"
    return $?
  else
    color_echo $YELLOW "[!] No sendmail/ssmtp found; email disabled."
    return 1
  fi
}

# -------------------------
# === Interactive Prompts ===
# -------------------------
prompt_wallet() {
  while true; do
    read -rp "Enter your Verus wallet address (starts with R): " WALLET_ADDRESS
    if validate_wallet; then
      color_echo $GREEN "[✓] Wallet address valid."
      break
    else
      color_echo $RED "[!] Invalid wallet address format. Try again."
    fi
  done
}

prompt_pool() {
  while true; do
    read -rp "Enter mining pool URL (host:port): " POOL_URL
    if validate_pool_url; then
      color_echo $GREEN "[✓] Pool URL valid."
      break
    else
      color_echo $RED "[!] Invalid pool URL format. Try again."
    fi
  done
}

prompt_threads() {
  local max_threads
  max_threads=$(nproc 2>/dev/null || echo 1)
  while true; do
    read -rp "Enter number of mining threads (1-$max_threads): " THREADS
    if validate_threads; then
      color_echo $GREEN "[✓] Thread count valid."
      break
    else
      color_echo $RED "[!] Invalid thread count. Try again."
    fi
  done
}

configure_miner_mode() {
  echo "Choose mining mode:"
  echo "  1) Low Power (reduce CPU usage, save battery)"
  echo "  2) Balanced (default)"
  echo "  3) Boosted (max threads)"
  echo "  4) Custom (manual threads and flags)"
  read -rp "Select mode [1-4]: " mode_choice
  case $mode_choice in
    1)
      MINER_MODE="lowpower"
      THREADS=1
      MINER_ARGS="--lowpower"
      ;;
    2)
      MINER_MODE="balanced"
      THREADS=$(( (nproc || echo 1) / 2 ))
      MINER_ARGS=""
      ;;
    3)
      MINER_MODE="boosted"
      THREADS=$(nproc || echo 1)
      MINER_ARGS="--max-performance"
      ;;
    4)
      MINER_MODE="custom"
      prompt_threads
      read -rp "Enter additional miner arguments (or leave blank): " MINER_ARGS
      ;;
    *)
      color_echo $YELLOW "Invalid choice, using Balanced mode."
      MINER_MODE="balanced"
      THREADS=$(( (nproc || echo 1) / 2 ))
      MINER_ARGS=""
      ;;
  esac
  color_echo $GREEN "[✓] Mining mode set to $MINER_MODE with $THREADS threads."
  save_config
}

configure_settings() {
  prompt_wallet
  prompt_pool
  configure_miner_mode
  save_config
  pause
}

# -------------------------
# === Menu System ===
# -------------------------
show_main_menu() {
  while true; do
    print_banner
    echo -e "${CYAN}1) Configure Wallet & Pool"
    echo -e "2) Configure Mining Mode & Threads"
    echo -e "3) Start Miner"
    echo -e "4) Stop Miner"
    echo -e "5) Restart Miner"
    echo -e "6) Miner Status"
    echo -e "7) Show Last Run Info"
    echo -e "8) Start Watchdog"
    echo -e "9) Stop Watchdog"
    echo -e "10) Download/Check Miner Binary"
    echo -e "11) Check for Script Update"
    echo -e "12) Logs & Tail"
    echo -e "13) Export Config"
    echo -e "14) Import Config"
    echo -e "0) Exit${NC}"
    read -rp "Choose an option: " choice
    case $choice in
      1) configure_settings ;;
      2) configure_miner_mode ;;
      3) start_miner; notify_user "Miner started" "Project Nova" ;;
      4) stop_miner; notify_user "Miner stopped" "Project Nova" ;;
      5) restart_miner; notify_user "Miner restarted" "Project Nova" ;;
      6) miner_status ;;
      7) show_run_info ;;
      8) watchdog_start ;;
      9) watchdog_stop ;;
      10) check_miner_binary ;;
      11) check_script_update ;;
      12) logs_menu ;;
      13) export_config ;;
      14) import_config ;;
      0) stop_miner; watchdog_stop; color_echo $GREEN "Goodbye!"; exit 0 ;;
      *) color_echo $RED "Invalid option. Try again." ;;
    esac
    read -rp "Press Enter to return to menu..."
  done
}

logs_menu() {
  print_banner
  echo "1) Tail miner log"
  echo "2) Tail watchdog log"
  echo "3) Show logs folder"
  echo "4) Clear logs"
  echo "0) Back"
  read -rp "Choice: " lchoice
  case "$lchoice" in
    1) [ -f "$MINER_LOG" ] && tail -n 200 -f "$MINER_LOG" || color_echo $YELLOW "No miner log yet." ;;
    2) [ -f "$WATCHDOG_LOG" ] && tail -n 200 -f "$WATCHDOG_LOG" || color_echo $YELLOW "No watchdog log yet." ;;
    3) ls -lah "$LOG_DIR"; read -rp "Press Enter..." ;;
    4) rm -f "$LOG_DIR"/* && mkdir -p "$LOG_DIR" && color_echo $GREEN "[✓] Logs cleared." ;;
    0) return ;;
    *) color_echo $YELLOW "Invalid" ;;
  esac
}

export_config() {
  local out="$HOME_DIR/nova_config_export_$(date +%s).conf"
  cp -f "$CONFIG_FILE" "$out" && color_echo $GREEN "[✓] Config exported to $out"
}

import_config() {
  read -rp "Enter path to config file to import: " imp
  if [ -f "$imp" ]; then
    cp -f "$imp" "$CONFIG_FILE"
    load_config
    color_echo $GREEN "[✓] Config imported and loaded."
  else
    color_echo $RED "[!] File not found."
  fi
}

# -------------------------
# === Misc Helpers ===
# -------------------------
script_self_update() {
  if [ -z "$GITHUB_REPO" ]; then
    color_echo $RED "[!] GITHUB_REPO not configured."
    return 1
  fi
  local version_file_url="https://raw.githubusercontent.com/$GITHUB_REPO/main/version.txt"
  local latest
  latest=$(curl -fsSL "$version_file_url" 2>/dev/null || echo "")
  if [ -z "$latest" ]; then
    color_echo $YELLOW "[i] Unable to fetch version info."
    return 1
  fi
  if [ "$latest" != "$SCRIPT_VERSION" ]; then
    color_echo $CYAN "[*] New version $latest available. Updating script..."
    local script_url="https://raw.githubusercontent.com/$GITHUB_REPO/main/project_nova_miner.sh"
    if curl -fsSL "$script_url" -o "$CONFIG_DIR/project_nova_miner.sh.tmp"; then
      mv "$CONFIG_DIR/project_nova_miner.sh.tmp" "$0"
      chmod +x "$0"
      color_echo $GREEN "[✓] Updated main script. Please restart."
      exec "$0" "$@"
    else
      color_echo $RED "[!] Failed to download updated script."
      return 1
    fi
  else
    color_echo $GREEN "[✓] Script already up-to-date."
  fi
}

# -------------------------
# === Input Validation UI ===
# -------------------------
configure_quick() {
  read -rp "Quick set wallet? (y/N): " yn
  if [[ "$yn" =~ ^[Yy] ]]; then
    prompt_wallet
  fi
  read -rp "Quick set pool? (y/N): " yn
  if [[ "$yn" =~ ^[Yy] ]]; then
    prompt_pool
  fi
  save_config
}

# -------------------------
# === Initial Boot Flow ===
# -------------------------
initial_setup() {
  print_banner
  load_config
  detect_environment
  check_dependencies
  check_termux_api
  termux_storage_setup

  # Load previous PIDs (if present) and validate running state
  if [ -f "$MINER_PID_FILE" ]; then
    local pid
    pid=$(cat "$MINER_PID_FILE" 2>/dev/null || echo "")
    if [ -n "$pid" ] && kill -0 "$pid" 2>/dev/null; then
      color_echo $GREEN "[✓] Miner process detected (PID $pid)."
    else
      rm -f "$MINER_PID_FILE"
    fi
  fi
  if [ -f "$WATCHDOG_PID_FILE" ]; then
    local wpid
    wpid=$(cat "$WATCHDOG_PID_FILE" 2>/dev/null || echo "")
    if [ -n "$wpid" ] && kill -0 "$wpid" 2>/dev/null; then
      color_echo $GREEN "[✓] Watchdog running (PID $wpid)."
    else
      rm -f "$WATCHDOG_PID_FILE"
    fi
  fi
}

# -------------------------
# === Entry Point ===
# -------------------------
main() {
  initial_setup
  show_main_menu
}

# Run
main
