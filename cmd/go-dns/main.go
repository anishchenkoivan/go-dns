package main

import (
	"bytes"
	"log"
	"net"
	"os"

	"github.com/anishchenkoivan/go-dns/dns"
	"github.com/anishchenkoivan/go-dns/dns/provider"
)

func main() {
	log.SetOutput(os.Stdout)

	providers := []dns.ResourceProvider{
		provider.NewStaticProvider(),
	}

	if len(os.Args) >= 2 {
		p, err := provider.NewFileProvider(os.Args[1])
		if err != nil {
			log.Println(err)
		}
		providers = append(providers, p)
	}

	server := dns.NewServer(providers...)

	serve(server)
}

func serve(server *dns.Server) {
	// TODO: Add configurable port
	addr, err := net.ResolveUDPAddr("udp", "127.0.0.1:8080")
	if err != nil {
		log.Fatal(err)
	}

	conn, err := net.ListenUDP("udp", addr)
	if err != nil {
		log.Fatal(err)
	}
	defer func(conn *net.UDPConn) {
		err := conn.Close()
		if err != nil {
			log.Fatal(err)
		}
	}(conn)

	log.Println("Listening on UDP port 8080")
	buf := make([]byte, 512)
	for {
		n, clientAddr, err := conn.ReadFromUDP(buf)
		if err != nil {
			log.Println(err)
			continue
		}

		// TODO: use buffer pool instead of cloning
		go func(n int, buffer []byte, addr *net.UDPAddr) {
			request := dns.ParseQuery(&buffer)
			response := server.HandleRequest(request)
			serializedResponse := dns.SerializeQuery(&response)
			n, err := conn.WriteToUDP(serializedResponse, addr)
			if err != nil {
				log.Println(err)
			}
		}(n, bytes.Clone(buf[:n]), clientAddr)
	}
}
