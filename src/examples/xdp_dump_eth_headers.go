package examples

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"os"
	"os/signal"
	"flag"
	"github.com/dropbox/goebpf"
)

type macAddress struct {
	Octet1 uint8
	Octet2 uint8
	Octet3 uint8
	Octet4 uint8
	Octet5 uint8
	Octet6 uint8
}

type perfEventItem struct {
	Dest	macAddress
	Src	macAddress
	Proto	uint16
}

func DumpEthernet() {
	elf     := getELF("xdp_dump_eth_headers")
	xdpMap  := "matches"
	xdpProg := "xdp_dump"

	flag.Parse()
	if *iface == "" {
		fatalError("-i is required.")
	}

	// Create eBPF system
	bpf := goebpf.NewDefaultEbpfSystem()
	err := bpf.LoadElf(elf)
	if err != nil {
		fatalError("LoadElf() failed: %v", err)
	}
	printBpfInfo(bpf)

	matches := bpf.GetMapByName(xdpMap)
	if matches == nil {
		fatalError("eBPF map '%s' not found", xdpMap)
	}

	xdp := bpf.GetProgramByName(xdpProg)
	if xdp == nil {
		fatalError("Program '%s' not found", xdpProg)
	}

	// Load XDP prog to kernel
	err = xdp.Load()
	if err != nil {
		fatalError("xdp.Load(): %v", err)
	}

	// Attach to interface
	err = xdp.Attach(*iface)
	if err != nil {
		fatalError("xdp.Attach(): %v", err)
	}
	defer xdp.Detach()

	// Add Ctrl+C handler
	ctrlC := make(chan os.Signal, 1)
	signal.Notify(ctrlC, os.Interrupt)

	// Start listening to Perf Events
	perf, _ := goebpf.NewPerfEvents(matches)
	perfEvents, err := perf.StartForAllProcessesAndCPUs(4096)
	if err != nil {
		fatalError("perf.StartForAllProcessesAndCPUs(): %v", err)
	}

	fmt.Println("XDP Program successfully loaded and attached.")
	fmt.Println("Press CTRL+C to stop.")
	fmt.Println()

	go func() {
		var event perfEventItem
		for {
			if eventData, ok := <-perfEvents; ok {
				reader := bytes.NewReader(eventData)
				binary.Read(reader, binary.LittleEndian, &event)
				proto := int(event.Proto)
				fmt.Printf("Ethernet Header: ")
				fmt.Printf("%x:%x:%x:%x:%x:%x -> ", event.Src.Octet1, event.Src.Octet2, event.Src.Octet3,
								    event.Src.Octet4, event.Src.Octet5, event.Src.Octet6)
				fmt.Printf("%x:%x:%x:%x:%x:%x, ", event.Dest.Octet1, event.Dest.Octet2, event.Dest.Octet3,
								  event.Dest.Octet4, event.Dest.Octet5, event.Dest.Octet6)
				fmt.Printf("%s[0x%x]\n", getEtherType(proto), event.Proto)
			} else {
				break
			}
		}
	}()

	<-ctrlC

	perf.Stop()
	fmt.Println("\nSummary:")
	fmt.Printf("\t%d Event(s) Received\n", perf.EventsReceived)
	fmt.Printf("\t%d Event(s) lost \n", perf.EventsLost)
	fmt.Println("\nDetaching program and exit...")
}

func getEtherType(proto int) string{
	var result string
	switch proto {
	case 2048:
		result = "Internet Protocol version 4 (IPv4)"
	case 2054:
		result = "Address Resolution Protocol (ARP)"
	default:
		result = "Unknown"
	}
	return result
}
