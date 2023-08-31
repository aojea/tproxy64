package main

import (
	"context"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"os/exec"
	"os/signal"
	"strconv"
	"sync"
	"syscall"

	"github.com/coreos/go-iptables/iptables"
	"golang.org/x/sys/unix"
)

const (
	tproxyDivertChain = "TPROXY-DIVERT"
	iptablesMark      = "1"
)

var (
	flagPort int
)

func init() {
	flag.IntVar(&flagPort, "p", 1, "port to listen")

	flag.Usage = func() {
		fmt.Fprint(os.Stderr, "Usage: tproxy64[options]\n\n")
		flag.PrintDefaults()
	}
}

func main() {
	// trap Ctrl+C and call cancel on the context
	ctx := context.Background()
	ctx, cancel := context.WithCancel(ctx)

	// Enable signal handler
	signalCh := make(chan os.Signal, 2)
	defer func() {
		close(signalCh)
		cancel()
	}()
	signal.Notify(signalCh, os.Interrupt, unix.SIGINT)

	// install iptables rules to divert traffic
	err := syncRules()
	if err != nil {
		log.Fatalf("Could not sync necessary iptables rules: %v", err)
	}
	log.Printf("Binding TCP TProxy listener to 0.0.0.0:%d\n", flagPort)

	// Create Listener Config
	lc := net.ListenConfig{
		Control: func(network, address string, c syscall.RawConn) error {
			return c.Control(func(fd uintptr) {
				// Enable IP_TRANSPARENT
				err := unix.SetsockoptInt(int(fd), syscall.SOL_IP, syscall.IP_TRANSPARENT, 1)
				if err != nil {
					log.Fatalf("Could not set SO_REUSEADDR socket option: %s", err)
					return
				}
			})
		},
	}

	// Start Listener
	tcpListener, err := lc.Listen(ctx, "tcp6", fmt.Sprint("[::]:%d", flagPort))
	if err != nil {
		log.Printf("Could not start TCP listener: %s", err)
		return
	}
	defer tcpListener.Close()

	go func() {
		for {
			conn, err := tcpListener.Accept()
			if err != nil {
				if netErr, ok := err.(net.Error); ok && netErr.Temporary() {
					log.Printf("Temporary error while accepting connection: %s", netErr)
				}

				log.Fatalf("Unrecoverable error while accepting connection: %s", err)
				return
			}

			go handleTCPConn(conn)
		}
	}()

	select {
	case <-signalCh:
		log.Printf("Exiting: received signal")
		cancel()
	case <-ctx.Done():
	}

	log.Println("TProxy listener closing")
}

func handleTCPConn(conn net.Conn) {
	log.Printf("Accepting TCP connection from %s with destination of %s", conn.RemoteAddr().String(), conn.LocalAddr().String())
	defer conn.Close()

	host, port, err := net.SplitHostPort(conn.LocalAddr().String())
	if err != nil {
		log.Printf("Failed to get remote address [%s]: %v", conn.LocalAddr().String(), err)
		return
	}
	ip4in6 := net.ParseIP(host)
	if ip4in6 == nil || ip4in6.To16() == nil {
		log.Printf("Failed to get remote address from IP [%s]: %v", host, err)
		return
	}

	// assume 64:ff9b::/96 and last 4 digits
	// https://www.rfc-editor.org/rfc/rfc6052.html
	ip4 := ip4in6[12:16]
	log.Printf("Connecting to [%s]", net.JoinHostPort(ip4.String(), port))
	remoteConn, err := net.Dial("tcp4", net.JoinHostPort(ip4.String(), port))
	if err != nil {
		log.Printf("Failed to connect to original destination [%s]: %s", conn.LocalAddr().String(), err)
		return
	}
	defer remoteConn.Close()

	var streamWait sync.WaitGroup
	streamWait.Add(2)

	streamConn := func(dst io.Writer, src io.Reader) {
		io.Copy(dst, src)
		streamWait.Done()
	}

	go streamConn(remoteConn, conn)
	go streamConn(conn, remoteConn)

	streamWait.Wait()
}

// syncRules syncs the tproxy rules to divert traffic to our server
func syncRules() error {
	// Install iptables rule to divert traffic to our webserver
	ipt, err := iptables.NewWithProtocol(iptables.ProtocolIPv6)
	if err != nil {
		return err
	}

	// make sure our custom chain exists
	// ip6tables -t mangle -N DIVERT
	// ip6tables -t mangle -A PREROUTING -p tcp -m socket -j DIVERT
	// ip6tables -t mangle -A DIVERT -j MARK --set-mark 1
	// ip6tables -t mangle -A DIVERT -j ACCEPT
	exists, err := ipt.ChainExists("mangle", tproxyDivertChain)
	if err != nil {
		return fmt.Errorf("failed to list chains: %v", err)
	}
	if !exists {
		if err = ipt.NewChain("mangle", tproxyDivertChain); err != nil {
			return err
		}
	}
	if err := ipt.AppendUnique("mangle", "PREROUTING", "-p", "tcp", "-m", "socket", "-j", tproxyDivertChain); err != nil {
		return err
	}
	if err := ipt.AppendUnique("mangle", tproxyDivertChain, "-j", "MARK", "--set-mark", "1"); err != nil {
		return err
	}
	if err := ipt.AppendUnique("mangle", tproxyDivertChain, "-j", "ACCEPT"); err != nil {
		return err
	}
	// # ip -6 rule add fwmark 1 lookup 100
	// # ip -6 route add local ::/0 dev lo table 100
	// TODO: make it idempotent, it creates new rules in each execution, create only if does not exist
	cmd := exec.Command("ip", "-6", "rule", "add", "fwmark", "1", "lookup", "100")
	if err := cmd.Run(); err != nil {
		return err
	}
	cmd = exec.Command("ip", "-6", "route", "add", "local", "::/0", "dev", "lo", "table", "100")
	if err := cmd.Run(); err != nil {
		// TODO it returns an error if route exists
		log.Printf("error trying to do AnyIP to the table 100: %v", err)
	}

	// ip6tables -t mangle -A PREROUTING -d 64:ff9b::/96 -p tcp -j TPROXY --tproxy-mark 0x1/0x1 --on-port 8080
	return ipt.InsertUnique("mangle", "PREROUTING", 1, "-p", "tcp", "-d", "64:ff9b::/96", "-j", "TPROXY", "--tproxy-mark", "0x1/0x1", "--on-port", strconv.Itoa(flagPort))
}
