#!/usr/bin/env bash
set -euo pipefail

remove_releases=0
purge_credentials=0
confirm_purge=0
while [ "$#" -gt 0 ]; do
  case "$1" in
    --remove-releases) remove_releases=1; shift ;;
    --purge-credentials) purge_credentials=1; shift ;;
    --confirm-purge) confirm_purge=1; shift ;;
    -h|--help)
      echo "Usage: uninstall-macos.sh [--remove-releases] [--purge-credentials --confirm-purge]"
      exit 0
      ;;
    *) echo "unknown option: $1" >&2; exit 2 ;;
  esac
done

if [ "$(uname -s)" != "Darwin" ] || [ "$(id -u)" -eq 0 ]; then
  echo "run this user-level uninstaller on macOS without sudo" >&2
  exit 1
fi
if [ "$purge_credentials" -eq 1 ] && [ "$confirm_purge" -ne 1 ]; then
  echo "--confirm-purge is required to delete the independent device identity" >&2
  exit 2
fi

install_root=${EGO_BROWSER_INSTALL_ROOT:-$HOME/Library/Application Support/Agent Remote Ego Browser}
launch_agents=${EGO_BROWSER_LAUNCH_AGENTS_DIR:-$HOME/Library/LaunchAgents}
case "$install_root" in "$HOME"/*) ;; *) echo "invalid install root" >&2; exit 2 ;; esac
case "$launch_agents" in "$HOME"/*) ;; *) echo "invalid launch-agent directory" >&2; exit 2 ;; esac
bridge_plist="$launch_agents/dev.agentremote.ego-browser.bridge.plist"
device_plist="$launch_agents/dev.agentremote.ego-browser.device.plist"
domain="gui/$(id -u)"
for plist in "$bridge_plist" "$device_plist"; do
  launchctl bootout "$domain" "$plist" >/dev/null 2>&1 || true
  if [ -e "$plist" ]; then
    if [ -L "$plist" ] || [ ! -f "$plist" ]; then
      echo "refusing to remove unexpected launch-agent path: $plist" >&2
      exit 1
    fi
    rm -f -- "$plist"
  fi
done

if [ -L "$install_root/current" ]; then
  rm -f -- "$install_root/current"
elif [ -e "$install_root/current" ]; then
  echo "refusing to remove non-symlink current path" >&2
  exit 1
fi
if [ "$remove_releases" -eq 1 ] && [ -d "$install_root/releases" ] && [ ! -L "$install_root/releases" ]; then
  chmod -R u+rwX "$install_root/releases"
  rm -rf -- "$install_root/releases"
fi
if [ "$purge_credentials" -eq 1 ]; then
  credentials="$HOME/.config/agent-remote-ego-browser"
  if [ -d "$credentials" ] && [ ! -L "$credentials" ]; then
    rm -rf -- "$credentials"
  elif [ -e "$credentials" ]; then
    echo "refusing to purge unexpected credential path" >&2
    exit 1
  fi
fi

echo "ego-browser Bridge launch agents removed; ego lite was not changed"
