# podcap - a script for running tcpdump on pods

## Overview

**podcap** is a lightweight shell script that simplifies capturing network traffic from one or more Kubernetes pods running on a cluster using a CRI-compatible container runtime. 
It uses `crictl`, `nsenter`, and `tcpdump` to capture network traffic directly from the pod's network namespace.

Each capture is started in the background and the process id for the capture is stored in a `json` file `capture_pids.json` in the specified `--output` location or `/tmp` by default.

## Features

- Capture network traffic from all containers in multiple pods simultaneously.
- Store captured packets in `.pcap` format for analysis with [`Wireshark`](https://www.wireshark.org/) or `tcpdump`.
- Specify a custom output directory for the capture files.
- Stop individual or all running captures with a simple command.
- List currently active capture sessions.

## Dependencies

The following tools are required for running `podcap`:
- `crictl` (for interacting with containerd)
- `nsenter` (for entering container network namespaces)
- `tcpdump` (for packet capture)
- `jq` (for JSON processing)

## Installation

```sh
wget https://raw.githubusercontent.com/Phillezi/podcap/main/podcap.sh
chmod +x podcap.sh
```

If you want it to be accessible everywhere you can do (after downloading the script using the command above)

```sh
mv podcap.sh /usr/bin/podcap   # requires root, run as sudo / doas if you arnt root
# you can now use podcap ... from anywhere (assuming /usr/bin/ is on your PATH)
```

Or if you want to run it directly:

```sh
curl -fsSL https://raw.githubusercontent.com/Phillezi/podcap/main/podcap.sh | sh
```

## Usage

### Start capturing traffic from one or more pods

```sh
./podcap.sh pod1 pod2 pod3
```
By default, capture files are saved to `/tmp`.

### Specify a custom output directory

```sh
./podcap.sh pod1 pod2 -o /path/to/output
```

### List active capture sessions

```sh
./podcap.sh --ls
# or
# ./podcap.sh --ps
```

### Stop capture for specific pods

```sh
./podcap.sh --stop pod1 pod3
```

### Stop all running captures

```sh
./podcap.sh --stop-all
```

## Capture-file naming

The capture file will be stored in the `--output` directory or `/tmp` by default and will be named `<pod-name>_<container-name>_capture.pcap`.
If a capture file already exists, the script automatically appends `_i` where `i` increments until a unique filename is found.

## Notes

- The script must be run with root privileges (`sudo ./podcap.sh ...`).
- Ensure the pods exist and are running before starting a capture.
- Use [`Wireshark`](https://www.wireshark.org/) or `tcpdump -r <file>.pcap` to analyze the captured packets.

## License

This project is licensed under the MIT License. See `LICENSE`.

