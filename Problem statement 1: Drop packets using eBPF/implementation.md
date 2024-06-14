# eBPF TCP Packet Dropper

This project demonstrates how to use eBPF to drop TCP packets on a specified port. The port number can be configured from user space using a Go program.

## Prerequisites

1. **Install Clang and LLVM**:
    ```sh
    sudo apt-get install clang llvm
    ```

2. **Install Go**:
    Download and install Go from the [official Go website](https://golang.org/dl/).

3. **Install libbpf** (if not already available on your system):
    ```sh
    sudo apt-get install libbpf-dev
    ```

## Compilation and Setup

1. **Compile the eBPF Program**:
    ```sh
    clang -O2 -target bpf -c drop_tcp.c -o drop_tcp.o
    ```

2. **Install the `cilium/ebpf` library** for Go:
    ```sh
    go get github.com/cilium/ebpf
    ```
3. **Compile the Go program**:
    ```sh
    go build -o update_port main.go
    ```
4. **Run the Go program** to update the port number and attach the eBPF program:
    ```sh
    sudo ./update_port 4040
    ```
