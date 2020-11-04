package examples

import (
	"os"
	"fmt"
	"flag"
	"github.com/dropbox/goebpf"
)

var iface = flag.String("i", "", "Interface to bind XDP prog to")

// Read ELF file
func getELF(elf string) string {
	return fmt.Sprintf("%s/%s.ko", os.Getenv("LIBKO"), elf)
}

// Print Error and exit
func fatalError(format string, args ...interface{}) {
	fmt.Fprintf(os.Stderr, format+"\n", args...)
	os.Exit(1)
}

// Print BPF info
func printBpfInfo(bpf goebpf.System) {
	fmt.Println("Maps:")
	for _, item := range bpf.GetMaps() {
		fmt.Printf("\t%s: %v, Fd %v\n", item.GetName(), item.GetType(), item.GetFd())
	}
	fmt.Println("\nPrograms:")
	for _, prog := range bpf.GetPrograms() {
		fmt.Printf("\t%s: %v, size %d, license '%s'\n", prog.GetName(), prog.GetType(), prog.GetSize(), prog.GetLicense())
	}
	fmt.Println()
}
