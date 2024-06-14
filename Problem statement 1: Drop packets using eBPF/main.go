package main

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"log"
	"os"
	"os/exec"
	"strconv"
	"unsafe"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/rlimit"
)

const (
	interfaceName = "eth0"
)

func main() {
	if len(os.Args) != 2 {
		log.Fatalf("Usage: %s <port>\n", os.Args[0])
	}
	port, err := strconv.Atoi(os.Args[1])
	if err != nil {
		log.Fatalf("Invalid port number: %v", err)
	}
	port16 := uint16(port)

	// Allow the current process to lock memory for eBPF resources.
	if err := rlimit.RemoveMemlock(); err != nil {
		log.Fatalf("Failed to set memory rlimit: %v", err)
	}

	// Load the compiled eBPF program.
	spec, err := ebpf.LoadCollectionSpec("drop_tcp.o")
	if err != nil {
		log.Fatalf("Failed to load eBPF object: %v", err)
	}

	// Create a new collection and load into the kernel.
	coll, err := ebpf.NewCollection(spec)
	if err != nil {
		log.Fatalf("Failed to create eBPF collection: %v", err)
	}
	defer coll.Close()

	// Update the port map with the new port number.
	portMap := coll.Maps["port_map"]
	if portMap == nil {
		log.Fatalf("Failed to find port_map in eBPF object")
	}
	key := uint32(0)
	if err := portMap.Put(key, unsafe.Pointer(&port16)); err != nil {
		log.Fatalf("Failed to update port map: %v", err)
	}

	// Attach the eBPF program to the interface.
	xdp := coll.Programs["drop_tcp_on_port"]
	if xdp == nil {
		log.Fatalf("Failed to find XDP program in eBPF object")
	}
	link, err := link.AttachXDP(link.XDPOptions{
		Program:   xdp,
		Interface: interfaceName,
	})
	if err != nil {
		log.Fatalf("Failed to attach XDP program: %v", err)
	}
	defer link.Close()

	fmt.Printf("Dropping TCP packets on port %d\n", port)

	// Block forever to keep the program loaded.
	select {}
}
