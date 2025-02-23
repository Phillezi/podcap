#!/bin/env sh

# Shell script to start a tcpdump of one or more pods in a Kubernetes cluster running with the CRI compliant runtime.
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
BLUE="\e[34m"
RESET="\e[0m"

ERROR_LOG="${RED}[ERROR]${RESET}"
WARN_LOG="${YELLOW}[WARN]${RESET}"
INFO_LOG="${GREEN}[INFO]${RESET}"

POD_NAMES=()
STOP_PODS=()
STOP_ALL=false
LIST_ACTIVE=false
PRINT_USAGE=false
AGGREGATE_OUTPUT_FILES=false

check_dependencies() {
  missing_deps=()
  for cmd in "$@"; do
    if ! command -v "$cmd" >/dev/null 2>&1; then
      missing_deps+=("$cmd")
    fi
  done

  if [ ${#missing_deps[@]} -ne 0 ]; then
    echo -e "$ERROR_LOG Missing dependencies: ${missing_deps[*]}" >&2
    exit 1
  fi
}

parse_args() {
  while [[ $# -gt 0 ]]; do
    case "$1" in
      -o|--output)
        if [[ -z "$2" || "$2" == -* ]]; then
          echo -e "$ERROR_LOG Missing output directory after $1" >&2
          exit 1
        fi
        OUTPUT_DIR="$2"
        PID_FILE="${OUTPUT_DIR}/capture_pids.json"
        shift 2
        ;;
      --stop)
        shift
        if [[ $# -eq 0 || "$1" == -* ]]; then
          echo -e "$ERROR_LOG Missing pod name(s) after --stop" >&2
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
      -d|--duration)
        if ! [[ "$2" =~ ^[0-9]+$ ]]; then
          echo -e "$ERROR_LOG Duration must be a positive integer." >&2
          exit 1
        fi
        DURATION="$2"
        shift 2
        ;;
      --aggregate)
        AGGREGATE_OUTPUT_FILES=true
        shift
        ;;
      -h|--help)
        PRINT_USAGE=true
        shift
        ;;
      -*)
        echo -e "$ERROR_LOG Unknown option: $1" >&2
        exit 1
        ;;
      *)
        POD_NAMES+=("$1")
        shift
        ;;
    esac
  done

  if [[ ${#POD_NAMES[@]} -eq 0 && $STOP_ALL == false && $LIST_ACTIVE == false && $PRINT_USAGE == false && $AGGREGATE_OUTPUT_FILES == false && ${#STOP_PODS[@]} -eq 0 ]]; then
    echo -e "$ERROR_LOG No valid arguments provided." >&2
    PRINT_USAGE=true
    #exit 1
  fi
}

# start a tcpdump for a given containe
# Arguments:
#   1: the pods name
#   2: the containers name
#   3: the containers id
capture_container() {
  POD_NAME=$1
  CONTAINER_NAME=$2
  CONTAINER_ID=$3
  i=1
  BASE_FILE="${OUTPUT_DIR}/${POD_NAME}_${CONTAINER_NAME}_capture"
  OUTPUT_FILE="${BASE_FILE}.pcap"

  while [[ -f "$OUTPUT_FILE" ]]; do
    OUTPUT_FILE="${BASE_FILE}_${i}.pcap"
    ((i++))
  done

  PID=$(crictl inspect "$CONTAINER_ID" | jq '.info.pid')
  if [ -z "$PID" ]; then
    echo -e "$ERROR_LOG Could not retrieve PID for container $CONTAINER_NAME with id: $CONTAINER_ID" >&2
    return
  fi

  if [ -f "$PID_FILE" ]; then
    if jq -e --arg pod "$POD_NAME" --arg container "$CONTAINER_NAME" '.[$pod][$container] != null' "$PID_FILE" >/dev/null; then
      RUNNING_PID=$(jq -r --arg pod "$POD_NAME" --arg container "$CONTAINER_NAME" '.[$pod][$container]' "$PID_FILE")

      if [ -n "$RUNNING_PID" ] && kill -0 "$RUNNING_PID" 2>/dev/null; then
        echo -e "$WARN_LOG Capture is already running for $POD_NAME -> $CONTAINER_NAME (PID: $RUNNING_PID)." >&2
        echo "       Use './$SCRIPT_NAME --stop $POD_NAME' to stop it before starting a new capture." >&2
        echo "       Skipping $POD_NAME $CONTAINER_NAME..." >&2
        return
      fi
    fi
  fi

  echo -e "$INFO_LOG Starting capture for $POD_NAME $CONTAINER_NAME..." >&2
  echo "       Container NAME: $CONTAINER_NAME" >&2
  echo "       Container ID: $CONTAINER_ID" >&2
  echo "       Process ID: $PID" >&2
  echo "       Saving network traffic to $OUTPUT_FILE..." >&2

  nsenter --net=/proc/$PID/ns/net tcpdump -i any -nn -s0 -w "$OUTPUT_FILE" &
  TCPDUMP_PID=$!

  if [ ! -f "$PID_FILE" ]; then
    echo "{}" > "$PID_FILE"
  fi

  jq --arg pod "$POD_NAME" --arg container "$CONTAINER_NAME" --arg pid "$TCPDUMP_PID" '.[$pod] = (.[$pod] // {}) + {($container): $pid}' "$PID_FILE" > "${PID_FILE}.tmp" && mv "${PID_FILE}.tmp" "$PID_FILE"

  if [ -n "$DURATION" ]; then
    (sleep "$DURATION"; kill "$TCPDUMP_PID" && jq --arg pod "$POD_NAME" --arg container "$CONTAINER_NAME" 'del(.[$pod][$container])' "$PID_FILE" > "${PID_FILE}.tmp" && mv "${PID_FILE}.tmp" "$PID_FILE") &
  fi

  echo -e "$INFO_LOG tcpdump started for $POD_NAME -> $CONTAINER_NAME (PID: $TCPDUMP_PID)" >&2
  if [ -n "$DURATION" ]; then
    echo -e "$INFO_LOG tcpdump will be killed in $DURATION s" >&2
  fi
}

get_pod() {
  POD_NAME=$1
  POD_INFO=$(crictl pods --name "$POD_NAME" -o json | jq -r '.items[] | "\(.id) \(.metadata.name)"')

  IFS=$'\n' read -r -d '' -a POD_IDS <<< "$POD_INFO"

  if [ ${#POD_IDS[@]} -eq 0 ]; then
    echo -e "$ERROR_LOG No pod found for $POD_NAME." >&2
    return 1
  fi

  if [ ${#POD_IDS[@]} -gt 1 ]; then
    echo -e "$WARN_LOG Multiple pods found for $POD_NAME. Please select one:" >&2

    i=1
    POD_MAP=()
    for pod_info in "${POD_IDS[@]}"; do

      pod_id=$(echo "$pod_info" | awk '{print $1}')
      pod_name=$(echo "$pod_info" | awk '{print $2}')

      echo -e "${BLUE}[$i]${RESET} $pod_name ($pod_id)" >&2
      POD_MAP[$i]="$pod_id"
      i=$((i + 1))
    done

    while :; do
      printf "Enter the number of the pod to use: " >&2
      read -r selection

      if [ -n "${POD_MAP[$selection]}" ]; then
        POD_ID="${POD_MAP[$selection]}"
        break
      else
        echo -e "$ERROR_LOG Invalid selection. Try again." >&2
      fi
    done
  else
    POD_ID="${POD_IDS[0]%% *}"
  fi

  echo -e "$INFO_LOG Selected pod: $POD_ID" >&2
  echo "$POD_ID"
}

# start a tcpdump for all containers in a given pod
# Arguments:
#   1: the pods name
start_capture() {
  POD_NAME=$1
  POD_ID=$(get_pod $POD_NAME)

  if [ -z "$POD_ID" ]; then
    echo -e "$ERROR_LOG No pod found for $POD_NAME." >&2
    return 1
  fi

  POD_NAME=$(crictl pods --id "$POD_ID" -o json | jq -r '.items[0].metadata.name')

  IFS=$'\n' read -d '' -r -a CONTAINER_IDS <<< "$(crictl ps --pod "$POD_ID" -q)"

  if [ -z "$CONTAINER_IDS" ]; then
    echo -e "$ERROR_LOG No containers found for $POD_NAME." >&2
    return 1
  fi

  for CONTAINER_ID in $CONTAINER_IDS; do
    CONTAINER_NAME=$(crictl inspect "$CONTAINER_ID" | jq -r '.status.metadata.name')

    echo -e "$INFO_LOG $CONTAINER_NAME"

    if [ -z "$CONTAINER_NAME" ]; then
      echo -e "$ERROR_LOG Could not retrieve container name for ID: $CONTAINER_ID" >&2
      continue
    fi

    capture_container "$POD_NAME" "$CONTAINER_NAME" "$CONTAINER_ID"
  done
}

stop_selected_captures() {
  if [ ! -f "$PID_FILE" ]; then
    echo -e "$ERROR_LOG No captures are currently running." >&2
    exit 1
  fi

  for POD in "${STOP_PODS[@]}"; do
    CONTAINERS=$(jq -r --arg pod "$POD" '(.[$pod] // {}) | keys[]' "$PID_FILE")

    if [ -z "$CONTAINERS" ]; then
      echo -e "$ERROR_LOG No running capture found for $POD." >&2
      continue
    fi

    for CONTAINER in $CONTAINERS; do
      PID=$(jq -r --arg pod "$POD" --arg container "$CONTAINER" '.[$pod][$container]' "$PID_FILE")
      
      if [ -n "$PID" ]; then
        echo -e "$INFO_LOG Stopping capture for $POD -> $CONTAINER (PID: $PID)..." >&2
        kill "$PID"
        jq --arg pod "$POD" --arg container "$CONTAINER" 'del(.[$pod][$container])' "$PID_FILE" > "${PID_FILE}.tmp" && mv "${PID_FILE}.tmp" "$PID_FILE"
      else
        echo -e "$ERROR_LOG No running capture found for $POD -> $CONTAINER." >&2
      fi
    done

    if [ "$(jq -r --arg pod "$POD" '(.[$pod] // {}) | length' "$PID_FILE")" -eq 0 ]; then
      jq --arg pod "$POD" 'del(.[$pod])' "$PID_FILE" > "${PID_FILE}.tmp" && mv "${PID_FILE}.tmp" "$PID_FILE"
    fi
  done
}

stop_all_captures() {
  if [ ! -f "$PID_FILE" ]; then
    echo -e "$INFO_LOG No captures are currently running." >&2
    exit 1
  fi

  echo -e "$INFO_LOG Stopping all captures..." >&2
  
  PIDS=$(jq -r 'to_entries | map(.value | to_entries | map(.value)) | add | .[]' "$PID_FILE")
  
  if [ -n "$PIDS" ]; then
    for PID in $PIDS; do
      (kill "$PID" && echo -e "$INFO_LOG Successfully stopped capture for PID: $PID") >&2 || echo -e "$ERROR_LOG Failed to kill capture with PID: $PID. Error: $?" >&2
    done
  else
    echo -e "$INFO_LOG No active captures to stop." >&2
  fi

  rm -f "$PID_FILE"
}

list() {
  if [ ! -f "$PID_FILE" ]; then
    echo -e "$INFO_LOG No captures are currently running." >&2
    exit 0
  fi

  echo -e "$INFO_LOG Listing active captures..." >&2

  ACTIVE_PODS=$(jq -r 'keys[]' "$PID_FILE")

  if [ -z "$ACTIVE_PODS" ]; then
    echo -e "$INFO_LOG No active captures found." >&2
    return
  fi

  for POD_NAME in $ACTIVE_PODS; do
    CONTAINERS=$(jq -r --arg pod "$POD_NAME" '(.[$pod] // {}) | keys[]' "$PID_FILE")

    for CONTAINER_NAME in $CONTAINERS; do
      PID=$(jq -r --arg pod "$POD_NAME" --arg container "$CONTAINER_NAME" '.[$pod][$container]' "$PID_FILE")

      if ps -p "$PID" > /dev/null 2>&1; then
        echo -e "$INFO_LOG Capture for $POD_NAME -> $CONTAINER_NAME is running (PID: $PID)." >&2
      else
        echo -e "$WARN_LOG Capture for $POD_NAME -> $CONTAINER_NAME is no longer running (PID: $PID)." >&2
        jq --arg pod "$POD_NAME" --arg container "$CONTAINER_NAME" 'del(.[$pod][$container])' "$PID_FILE" > "${PID_FILE}.tmp" && mv "${PID_FILE}.tmp" "$PID_FILE"
      fi
    done

    if [ "$(jq -r --arg pod "$POD_NAME" '(.[$pod] // {}) | length' "$PID_FILE")" -eq 0 ]; then
      jq --arg pod "$POD_NAME" 'del(.[$pod])' "$PID_FILE" > "${PID_FILE}.tmp" && mv "${PID_FILE}.tmp" "$PID_FILE"
    fi
  done
}

aggregate_output_files() {
  local POD_NAME=$1
  local FINAL_PCAP="${OUTPUT_DIR}/${POD_NAME}_final.pcap"

  if [[ -z "$OUTPUT_DIR" || ! -d "$OUTPUT_DIR" ]]; then
    echo -e "$ERROR_LOG Output directory not found: $OUTPUT_DIR" >&2
    return 1
  fi

  shopt -s nullglob
  local PCAP_FILES=("$OUTPUT_DIR"/"${POD_NAME}"_*_capture*.pcap)
  shopt -u nullglob

  if [[ ${#PCAP_FILES[@]} -eq 0 ]]; then
    echo -e "$ERROR_LOG No capture files found for pod: $POD_NAME" >&2
    return 1
  fi

  if [[ ${#PCAP_FILES[@]} -eq 1 ]]; then
    echo -e "$INFO_LOG Only one capture file for: $POD_NAME, copying it to $FINAL_PCAP" >&2
    cp "${PCAP_FILES[0]}" "$FINAL_PCAP"
    return 0
  fi

  echo -e "$INFO_LOG Aggregating capture files for pod: $POD_NAME" >&2

  if command -v mergecap &>/dev/null; then
    printf "%s\n" "${PCAP_FILES[@]}" | xargs mergecap -w "$FINAL_PCAP"
    
    if [[ $? -eq 0 ]]; then
      echo -e "$INFO_LOG Aggregated pcap file created: $FINAL_PCAP" >&2
    else
      echo -e "$ERROR_LOG Failed to merge pcap files." >&2
      return 1
    fi

  elif command -v editcap &>/dev/null; then
    echo -e "$WARN_LOG mergecap not found, using sequential appending with editcap..." >&2

    cp "${PCAP_FILES[0]}" "$FINAL_PCAP"

    for FILE in "${PCAP_FILES[@]:1}"; do
      echo -e "$INFO_LOG Appending: $FILE" >&2
      editcap -F pcap "$FILE" "$FINAL_PCAP.tmp" && mv "$FINAL_PCAP.tmp" "$FINAL_PCAP"
    done

    echo -e "$INFO_LOG Aggregated pcap file created: $FINAL_PCAP" >&2
  else
    echo -e "$ERROR_LOG Neither mergecap or editcap was found but are required to merge / append the pcap files" >&2
  fi

}

usage() {
  echo -e "$INFO_LOG Usage:"
  echo -e "  ./$SCRIPT_NAME pod1 pod2 pod3                  - Start capture for multiple pods"
  echo -e "  ./$SCRIPT_NAME pod1 pod2 -o /path/to/output    - Start capture for multiple pods with custom output directory (default: /tmp)"
  echo -e "  ./$SCRIPT_NAME pod1 pod2 pod3 -d 5             - Start capture for multiple pods that will stop in 5 seconds"
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

if $AGGREGATE_OUTPUT_FILES; then
  for POD in "${POD_NAMES[@]}"; do
    aggregate_output_files "$POD"
  done
  exit 0
fi

for POD in "${POD_NAMES[@]}"; do
  start_capture "$POD"
done
