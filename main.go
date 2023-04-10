package main

import (
	"context"
	"io"
	"log"
	"net"
	"os"
	"os/signal"
	"sync"
	"syscall"

	"golang.org/x/sys/unix"
)

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

	var err error
	log.Println("Binding TCP TProxy listener to 0.0.0.0:8080")

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
	tcpListener, err := lc.Listen(ctx, "tcp6", "0.0.0.0:8080")
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
