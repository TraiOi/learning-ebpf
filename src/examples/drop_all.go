package examples

import (
	"time"
	"fmt"
	"os"
	"os/signal"
	"flag"
	"github.com/dropbox/goebpf"
)


func DropAll() {
	elf := getELF("drop_all")
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

	matches := bpf.GetMapByName("matches")
	if matches == nil {
		fatalError("eBPF map 'matches' not found")
	}

	xdp := bpf.GetProgramByName("drop")
	if xdp == nil {
		fatalError("Program 'drop' not found.")
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

	// Add CTRL+C handler
	ctrlC := make(chan os.Signal, 1)
	signal.Notify(ctrlC, os.Interrupt)

	fmt.Println("XDP program successfully loaded and attached. Counters refreshed every second.")
	fmt.Println("Press CTRL+C to stop.")
	fmt.Println()

	ticker := time.NewTicker(1 * time.Second)
	for {
		select {
		case <-ticker.C:
			for i := 0; i < 132; i++ {
				value, err := matches.LookupInt(i)
				if err != nil {
					fatalError("LookupInt failed: %v", err)
				}
				if value > 0 {
					fmt.Printf("%d", value)
				}
			}
			fmt.Printf("\r")
		case <-ctrlC:
			fmt.Println("\nDetaching program and exit")
			return
		}
	}
}

