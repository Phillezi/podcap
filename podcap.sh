#!/bin/env sh

# Shell script to start a tcpdump of one or more pods in a Kubernetes cluster running with the containerd runtime.
#
# What does it do?
#   It lets you capture traffic of a specified pod/s using tcpdump. 
#   The captures are started in the background and are kept track of with a json file that stores the pids.
#   The capture dumps are saved in /tmp/<pod-name>_capture.pcap, or if output dir is specified, it is stored in the specified dir.
#
# Dependencies:
# - crictl
# - nsenter
# - tcpdump
# - jq
#

SCRIPT_NAME=$(basename "$0")                # The name of the script. Just for usage printing.
OUTPUT_DIR="/tmp"                           # Default output directory
PID_FILE="${OUTPUT_DIR}/capture_pids.json"  # File to store running capture PIDs

RED="\e[31m"
YELLOW="\e[33m"
GREEN="\e[32m"
RESET="\e[0m"

ERROR_LOG="${RED}[ERROR]${RESET}"
WARN_LOG="${YELLOW}[WARN]${RESET}"
INFO_LOG="${GREEN}[INFO]${RESET}"

POD_NAMES=()
STOP_PODS=()
STOP_ALL=false
LIST_ACTIVE=false
PRINT_USAGE=false

check_dependencies() {
  missing_deps=()
  for cmd in "$@"; do
    if ! command -v "$cmd" >/dev/null 2>&1; then
      missing_deps+=("$cmd")
    fi
  done

  if [ ${#missing_deps[@]} -ne 0 ]; then
    echo -e "$ERROR_LOG Missing dependencies: ${missing_deps[*]}"
    exit 1
  fi
}

parse_args() {
  while [[ $# -gt 0 ]]; do
    case "$1" in
      -o|--output)
        if [[ -z "$2" || "$2" == -* ]]; then
          echo -e "$ERROR_LOG Missing output directory after $1"
          exit 1
        fi
        OUTPUT_DIR="$2"
        PID_FILE="${OUTPUT_DIR}/capture_pids.json"
        shift 2
        ;;
      --stop)
        shift
        if [[ $# -eq 0 || "$1" == -* ]]; then
          echo -e "$ERROR_LOG Missing pod name(s) after --stop"
          exit 1
        fi
        while [[ $# -gt 0 && "$1" != -* ]]; do
          STOP_PODS+=("$1")
          shift
        done
        ;;
      --stop-all)
        STOP_ALL=true
        shift
        ;;
      --ps|--ls)
        LIST_ACTIVE=true
        shift
        ;;
      -h|--help)
        PRINT_USAGE=true
        shift
        ;;
      -*)
        echo -e "$ERROR_LOG Unknown option: $1"
        exit 1
        ;;
      *)
        POD_NAMES+=("$1")
        shift
        ;;
    esac
  done

  if [[ ${#POD_NAMES[@]} -eq 0 && $STOP_ALL == false && $LIST_ACTIVE == false && $PRINT_USAGE == false && ${#STOP_PODS[@]} -eq 0 ]]; then
    echo -e "$ERROR_LOG No valid arguments provided."
    PRINT_USAGE=true
    #exit 1
  fi
}

# start a tcpdump for a given pod
# Arguments:
#   1: the pods name
start_capture() {
  POD_NAME=$1
  i=1
  BASE_FILE="${OUTPUT_DIR}/${POD_NAME}_capture"
  OUTPUT_FILE="${BASE_FILE}.pcap"

  while [[ -f "$OUTPUT_FILE" ]]; do
    OUTPUT_FILE="${BASE_FILE}_${i}.pcap"
    ((i++))
  done

  CONTAINER_ID=$(crictl ps | grep "$POD_NAME" | awk '{print $1}')
  if [ -z "$CONTAINER_ID" ]; then
    echo -e "$ERROR_LOG No container found for pod $POD_NAME"
    return
  fi

  PID=$(crictl inspect "$CONTAINER_ID" | jq '.info.pid')
  if [ -z "$PID" ]; then
    echo -e "$ERROR_LOG Could not retrieve PID for container $CONTAINER_ID"
    return
  fi

  if [ -f "$PID_FILE" ]; then
    if jq -e --arg pod "$POD_NAME" '.[$pod] != null' "$PID_FILE" >/dev/null; then
      RUNNING_PID=$(jq -r --arg pod "$POD_NAME" '.[$pod]' "$PID_FILE")
      if kill -0 "$RUNNING_PID" 2>/dev/null; then
        echo -e "$WARN_LOG Capture is already running for $POD_NAME (PID: $RUNNING_PID)."
        echo "       Use './"$SCRIPT_NAME" --stop $POD_NAME' to stop it before starting a new capture."
        echo "       Skipping $POD_NAME..."
        return
      fi
    fi
  fi

  echo -e "$INFO_LOG Starting capture for $POD_NAME..."
  echo "       Container ID: $CONTAINER_ID"
  echo "       Process ID: $PID"
  echo "       Saving network traffic to $OUTPUT_FILE..."

  nsenter --net=/proc/$PID/ns/net tcpdump -i any -nn -s0 -w "$OUTPUT_FILE" &
  TCPDUMP_PID=$!

  if [ ! -f "$PID_FILE" ]; then
    echo "{}" > "$PID_FILE"
  fi

  jq --arg pod "$POD_NAME" --arg pid "$TCPDUMP_PID" '. + {($pod): $pid}' "$PID_FILE" > "${PID_FILE}.tmp" && mv "${PID_FILE}.tmp" "$PID_FILE"

  echo -e "$INFO_LOG tcpdump started for $POD_NAME (PID: $TCPDUMP_PID)"
}

# stop selected pod captures, reads the json file to get the pids
stop_selected_captures() {
  if [ ! -f "$PID_FILE" ]; then
    echo -e "$ERROR_LOG No captures are currently running."
    exit 1
  fi

  for POD in "${STOP_PODS[@]}"; do
    PID=$(jq -r --arg pod "$POD" '.[$pod] // empty' "$PID_FILE")

    if [ -n "$PID" ]; then
      echo -e "$INFO_LOG Stopping capture for $POD (PID: $PID)..."
      kill "$PID"
      jq --arg pod "$POD" 'del(.[$pod])' "$PID_FILE" > "${PID_FILE}.tmp" && mv "${PID_FILE}.tmp" "$PID_FILE"
    else
      echo -e "$ERROR_LOG No running capture found for $POD."
    fi
  done
}

# stop all running tcpdump processes, reads the json file to get all pids
stop_all_captures() {
  if [ ! -f "$PID_FILE" ]; then
    echo -e "$INFO_LOG No captures are currently running."
    exit 1
  fi

  echo -e "$INFO_LOG Stopping all captures..."
  
  PIDS=$(jq -r 'to_entries | map(.value) | .[]' "$PID_FILE")
  
  if [ -n "$PIDS" ]; then
    for PID in $PIDS; do
      (kill "$PID" && echo -e "$INFO_LOG Successfully stopped capture for PID: $PID") || echo -e "$ERROR_LOG Failed to kill capture with PID: $PID. Error: $?"
    done
  else
    echo -e "$INFO_LOG No active captures to stop."
  fi
  
  rm -f "$PID_FILE"
}

list() {
  if [ ! -f "$PID_FILE" ]; then
    echo -e "$INFO_LOG No captures are currently running."
    exit 0
  fi

  echo -e "$INFO_LOG Listing active captures..."

  ACTIVE_PODS=$(jq -r 'to_entries[] | select(.value != null) | .key' "$PID_FILE")

  if [ -z "$ACTIVE_PODS" ]; then
    echo -e "$INFO_LOG No active captures found."
    return
  fi

  for POD_NAME in $ACTIVE_PODS; do
    PID=$(jq -r --arg pod "$POD_NAME" '.[$pod]' "$PID_FILE")

    if ps -p "$PID" > /dev/null 2>&1; then
      echo -e "$INFO_LOG Capture for pod $POD_NAME is running (PID: $PID)."
    else
      echo -e "$WARN_LOG Capture for pod $POD_NAME is no longer running (PID: $PID)."
      jq --arg pod "$POD_NAME" 'del(.[$pod])' "$PID_FILE" > "${PID_FILE}.tmp" && mv "${PID_FILE}.tmp" "$PID_FILE"
    fi
  done
}

usage() {
  echo -e "$INFO_LOG Usage:"
  echo -e "  ./$SCRIPT_NAME pod1 pod2 pod3                  - Start capture for multiple pods"
  echo -e "  ./$SCRIPT_NAME pod1 pod2 -o /path/to/output    - Start capture for multiple pods with custom output directory (default: /tmp)"
  echo -e "  ./$SCRIPT_NAME --stop pod1 pod2                - Stop capture for specific pods"
  echo -e "  ./$SCRIPT_NAME --stop-all                      - Stop all running captures"
  echo -e "  ./$SCRIPT_NAME --ps                            - List all active capture sessions"
}

# Main execution ===========================================================================================================================
if [ "$(id -u)" -ne 0 ]; then
  echo -e "$ERROR_LOG This script must be run as root. Try using sudo or doas."
  exit 1
fi

check_dependencies crictl nsenter tcpdump jq
parse_args "$@"

if $PRINT_USAGE; then
  usage
  exit 0
fi

if $LIST_ACTIVE; then
  list
  exit 0
fi

if $STOP_ALL; then
  stop_all_captures
  exit 0
fi

if [ ${#STOP_PODS[@]} -gt 0 ]; then
  stop_selected_captures
  exit 0
fi

if [ ${#POD_NAMES[@]} -eq 0 ]; then
  echo -e "$ERROR_LOG No pod names provided."
  exit 1
fi

for POD in "${POD_NAMES[@]}"; do
  start_capture "$POD"
done
