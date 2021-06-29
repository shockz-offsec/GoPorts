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
	top200udp = "7,9,13,17,19,21-23,37,42,49,53,67-69,80,88,111,120,123,135-139,158,161-162,177,192,199,389,407,427,443,445,464,497,500,514-515,517-518,520,593,623,626,631,664,683,800,989-990,996-999,1001,1008,1019,1021-1034,1036,1038-1039,1041,1043-1045,1049,1068,1419,1433-1434,1645-1646,1701,1718-1719,1782,1812-1813,1885,1900,2000,2002,2048-2049,2148,2222-2223,2967,3052,3130,3283,3389,3456,3659,3703,4000,4045,4444,4500,4672,5000-5001,5060,5093,5351,5353,5355,5500,5632,6000-6001,6346,7938,9200,9876,10000,10080,11487,16680,17185,19283,19682,20031,22986,27892,30718,31337,32768-32773,32815,33281,33354,34555,34861-34862,37444,39213,41524,44968,49152-49154,49156,49158-49159,49162-49163,49165-49166,49168,49171-49172,49179-49182,49184-49196,49199-49202,49205,49208-49211,58002,65024"
)

var (
	host    = flag.String("host", "127.0.0.1", "Host or IP address to scan")
	ports   = flag.String("ports", "1-35535", "Port range to be tested (Ex: 80,443,1-65535,1000-2000)")
	top_20  = flag.Bool("top20", false, "Scanner top 20 most scanned ports.\nBy default they will be scanned only for TCP")
	top_200 = flag.Bool("top200", false, "Scanner top 200 most scanned ports\nBy default they will be scanned only for TCP")
	tcp     = flag.Bool("tcp", true, "Set scanning to be via TCP protocol")
	udp     = flag.Bool("udp", false, "Set scanning to be via UDP protocol")
	verbose = flag.Bool("verb", false, "Set verbose mode showing open/closed ports")
	threads = flag.Int("threads", 900, "Number of threads to be used")
	timeout = flag.Duration("timeout", 1*time.Second, "Connection timeout in seconds")

	Green   = Color("\033[1;32m%s\033[0m")
	Black   = Color("\033[1;30m%s\033[0m")
	Red     = Color("\033[1;31m%s\033[0m")
	Yellow  = Color("\033[1;33m%s\033[0m")
	Purple  = Color("\033[1;34m%s\033[0m")
	Magenta = Color("\033[1;35m%s\033[0m")
	Teal    = Color("\033[1;36m%s\033[0m")
	White   = Color("\033[1;37m%s\033[0m")
)

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
		fmt.Printf(Magenta("EXAMPLES:\n"))
		fmt.Printf(Teal("  goports -host www.google.com -ports 21-23,80,443\n"))
		fmt.Printf(Teal("  goports -host www.google.com -udp -ports 21-23,53\n"))
		fmt.Printf(Teal("  goports -host www.google.com -tcp 80,443 -udp 53 -timeout 5 -threads 900\n"))
		fmt.Printf(Teal("  goports -host www.google.com -top20 -threads 900 -verb\n\n"))
		fmt.Printf(Yellow("* Remember to use just one of the following options : top20, top200 or nothing\n\n"))
		fmt.Printf(Magenta("OPTIONS:\n"))
		flag.PrintDefaults()
	}

	flag.Parse()

	// Ensure at least one host and port are defined, otherwise exit and display usage
	if len(*host) == 0 || (len(*ports) == 0) {
		flag.Usage()
		os.Exit(1)
	}

	ports_to_process := *ports

	if *udp {
		*tcp = false
	}

	if *top_20 && *top_200 {
		fmt.Printf(Red("[!] Please just select one of these two options: %s or %s.\n\n"), Teal("top20"), Teal("top200"))
		fmt.Printf(Yellow("You can check the manual using the option -help\n\n"))
		os.Exit(1)
	}

	if *top_20 {
		ports_to_process = top20
	} else if *top_200 && *tcp {
		ports_to_process = top200tcp
	} else if *top_200 && *udp {
		ports_to_process = top200udp
	}

	//verbose

	return ports_to_process

}

func scanPorts(ctx context.Context, in <-chan int) chan string {
	out := make(chan string)
	done := ctx.Done()
	var wg sync.WaitGroup

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
					s := scanPort(port)
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

func scanPort(port int) string {
	addr := fmt.Sprintf("%s:%d", *host, port)
	conn, err := net.DialTimeout("tcp", addr, *timeout)

	if err != nil {
		return fmt.Sprintf("%d: %s", port, err.Error())
	}

	conn.Close()

	return fmt.Sprintf("Port: %s\tRunning: %s\tStatus: %s", Magenta(strconv.Itoa(port)), Teal(utils.Services[port]), Green("Open"))
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

	fmt.Print(ports_to_process)
	processed_ports := formatter(ctx, ports_to_process)
	scanned_ports := scanPorts(ctx, processed_ports)

	open := false

	for port := range scanned_ports {
		if strings.Contains(port, "Open") {
			fmt.Println(port)
			open = true
		}
	}
	if !open {
		fmt.Println(Red("[!] No open ports\n"))
	}

	elapsed := time.Since(start)
	fmt.Printf(Yellow("\n[*] Scan complete: %s scanned in %.3f seconds\n"), *host, elapsed.Seconds())
}

//UDP , FLAGS
//VERBOSE => SHOW CLOSED
