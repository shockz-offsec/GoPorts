package main

import (
	"context"
	"flag"
	"fmt"
	"goports/utils"
	"log"
	"net"
	"os"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"
)

const (
	top20     = "21-23,25,53,80,110-111,135,139,143,443,445,993,995,1723,3306,3389,5900,8080"
	top200tcp = "1,3,7,9,13,17,19,21-23,25-26,37,53,79-82,88,100,106,110-111,113,119,135,139,143-144,179,199,254-255,280,311,389,427,443-445,464-465,497,513-515,543-544,548,554,587,593,625,631,636,646,787,808,873,902,990,993,995,1000,1022,1024-1033,1035-1041,1044,1048-1050,1053-1054,1056,1058-1059,1064-1066,1069,1071,1074,1080,1110,1234,1433,1494,1521,1720,1723,1755,1761,1801,1900,1935,1998,2000-2003,2005,2049,2103,2105,2107,2121,2161,2301,2383,2401,2601,2717,2869,2967,3000-3001,3128,3268,3306,3389,3689-3690,3703,3986,4000-4001,4045,4899,5000-5001,5003,5009,5050-5051,5060,5101,5120,5190,5357,5432,5555,5631,5666,5800,5900-5901,6000-6002,6004,6112,6646,6666,7000,7070,7937-7938,8000,8002,8008-8010,8031,8080-8081,8443,8888,9000-9001,9090,9100,9102,9999-10001,10010,32768,32771,49152-49157,50000"
)

var (
	host    = flag.String("host", "127.0.0.1", "Host or IP address to scan")
	ports   = flag.String("ports", "1-65535", "Port range to be tested (Ex: 80,443,1-65535,1000-2000)")
	top_20  = flag.Bool("top20", false, "Scanner top 20 most scanned TCP ports")
	top_200 = flag.Bool("top200", false, "Scanner top 200 most scanned TCP ports")
	threads = flag.Int("threads", 900, "Number of threads to be used")
	timeout = flag.Duration("timeout", 1*time.Second, "Connection timeout in seconds")

	Green   = Color("\033[1;32m%s\033[0m")
	Black   = Color("\033[1;30m%s\033[0m")
	Red     = Color("\033[1;31m%s\033[0m")
	Yellow  = Color("\033[1;33m%s\033[0m")
	Magenta = Color("\033[1;35m%s\033[0m")
	Teal    = Color("\033[1;36m%s\033[0m")
)

type Output struct {
	Port     int
	Service  string
	Protocol string
	Open     bool
}

func Color(colorString string) func(...interface{}) string {
	sprint := func(args ...interface{}) string {
		return fmt.Sprintf(colorString,
			fmt.Sprint(args...))
	}
	return sprint
}

func formatter(ctx context.Context, r string) chan int {
	c := make(chan int)
	done := ctx.Done()

	go func() {
		defer close(c)
		blocks := strings.Split(r, ",")

		for _, block := range blocks {
			rg := strings.Split(block, "-")
			var minPort, maxPort int
			var err error

			minPort, err = strconv.Atoi(rg[0])

			if err != nil {
				log.Printf(Red("[!] It has not been possible to interpret the range: "), block)
				continue
			}

			if len(rg) == 1 {
				maxPort = minPort
			} else {
				maxPort, err = strconv.Atoi(rg[1])
				if maxPort < minPort {
					log.Printf(Red("[!] The upper limit cannot be numerically lower than the lower limit.\nIt has not been possible to interpret the range: "), block)
					continue
				}
				if err != nil {
					log.Printf(Red("[!] It has not been possible to interpret the range: "), block)
					continue
				}
			}
			for port := minPort; port <= maxPort; port++ {
				select {
				case c <- port:
				case <-done:
					return
				}
			}
		}
	}()
	return c
}

func parameters() string {

	flag.Usage = func() {
		fmt.Printf(Yellow("Usage of %s:\n\n"), os.Args[0])
		fmt.Print(Magenta("Examples:\n\n"))
		fmt.Printf("%-90s %-35s\n", Teal("go run goports"), Yellow("This command will scan all ports in localhost (127.0.0.1)"))
		fmt.Printf("%-90s %-35s\n", Teal("go run goports -host 10.10.10.10 -ports 21-23,80,443"), Yellow("This command will scan specific ports over a specific host"))
		fmt.Printf("%-90s %-35s\n", Teal("go run goports -host www.google.com -ports 80,443 -timeout 5 -threads 1000"), Yellow("This command will scan the specified ports over a specific host, setting a timeout of 5 seconds and using 1000 threads"))
		fmt.Printf("%-90s %-35s\n", Teal("go run goports -host www.google.com -top20 -threads 1000"), Yellow("This command will scan the top 20 tcp ports over a specific host using 1000 threads"))
		fmt.Printf("%-90s %-35s\n\n", Teal("go run goports -host www.google.com -top200 -threads 1000"), Yellow("This command will scan the top 200 tcp ports over a specific host using 1000 threads"))
		fmt.Print(Yellow("* Only open ports will be displayed\n\n"))
		fmt.Print(Yellow("* Remember to use just one of the following options : top20, top200 or nothing\n\n"))
		fmt.Print(Magenta("Options:\n\n"))
		flag.PrintDefaults()
	}

	flag.Parse()

	// Ensure at least one host and port are defined, otherwise exit and display usage
	if len(*host) == 0 || (len(*ports) == 0) {
		flag.Usage()
		os.Exit(1)
	}

	ports_to_process := *ports

	if *top_20 && *top_200 {
		fmt.Printf(Red("[!] Please just select one of these two options: %s or %s.\n\n"), Teal("top20"), Teal("top200"))
		fmt.Print(Yellow("You can check the manual using the option -help\n\n"))
		os.Exit(1)
	}

	if *top_20 {
		ports_to_process = top20
	} else if *top_200 {
		ports_to_process = top200tcp
	}

	return ports_to_process

}

func scanPorts(ctx context.Context, in <-chan int) chan Output {
	out := make(chan Output)
	done := ctx.Done()
	var wg sync.WaitGroup
	var s Output

	for i := 0; i < *threads; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				select {
				case port, ok := <-in:
					if !ok {
						return
					}
					s = scanPortTCP(port)

					select {
					case out <- s:
					case <-done:
						return
					}
				case <-done:
					return
				}
			}
		}()
	}
	go func() {
		wg.Wait()
		close(out)
	}()

	return out
}

func scanPortTCP(port int) Output {
	addr := fmt.Sprintf("%s:%d", *host, port)
	conn, err := net.DialTimeout("tcp", addr, *timeout)

	if err != nil {

		return Output{
			Port:     port,
			Service:  utils.Services[port],
			Protocol: "TCP",
			Open:     false,
		}
	}
	defer conn.Close()

	return Output{
		Port:     port,
		Service:  utils.Services[port],
		Protocol: "TCP",
		Open:     true,
	}
}

func resolveHost(host string) (addr, hostname string) {
	if isIPAddress(host) {
		addr = host
		r, err := net.LookupAddr(addr)
		if err != nil {
			hostname = ""
		} else {
			// Use first returned hostname and trim trailing period
			hostname = r[0][:len(r[0])-1]
		}
	} else {
		hostname = host
		r, err := net.LookupIP(hostname)
		if err != nil {
			fmt.Printf(Red("[!] Unable to resolve host: %v\n"), hostname)
			os.Exit(1)
		} else {
			// Use first returned address
			addr = r[0].String()
		}
	}
	return addr, hostname
}

func isIPAddress(addr string) bool {
	re := regexp.MustCompile(`(\d{1,3}\.){3}\d{1,3}`)
	return re.MatchString(addr)
}

func main() {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	start := time.Now()
	ports_to_process := parameters()
	addr, hostname := resolveHost(*host)

	if hostname != "" {
		fmt.Printf(Yellow("\n[*] Starting the scanning of ports %s of host %s (%s)\n\n"), *ports, *host, addr)
	} else {
		fmt.Printf(Yellow("\n[*] Starting the scanning of ports %s of host %s\n\n"), *ports, *host)
	}

	processed_ports := formatter(ctx, ports_to_process)
	scanned_ports := scanPorts(ctx, processed_ports)

	open := false

	for Output := range scanned_ports {
		if Output.Open {
			fmt.Printf("%-25s %-35s %-25s %s\n", "Port: "+Magenta(strconv.Itoa(Output.Port)), "Running: "+Teal(Output.Service), "Protocol: "+Black(Output.Protocol), "Status: "+Green("Open"))
			open = true
		}
	}

	if !open {
		fmt.Println(Red("[!] No open ports\n"))
	}

	elapsed := time.Since(start)
	fmt.Printf(Yellow("\n[*] Scan complete: %s scanned in %.3f seconds\n"), *host, elapsed.Seconds())
}
