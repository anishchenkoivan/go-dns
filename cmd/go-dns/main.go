package main

import (
	"bytes"
	"log"
	"net"
	"os"

	"github.com/anishchenkoivan/go-dns/dns"
)

func main() {
	//addr, err := net.ResolveUDPAddr("udp", ":8080")
	//if err != nil {
	//	log.Fatal("Error resolving address:", err)
	//}
	//
	//conn, err := net.ListenUDP("udp", addr)
	//if err != nil {
	//	log.Fatal("Error listening:", err)
	//}
	//defer conn.Close()
	//
	//fmt.Printf("UDP server listening on %s\n", conn.LocalAddr().String())
	//
	//buffer := make([]byte, 1024)
	//for {
	//	n, remoteAddr, err := conn.ReadFromUDP(buffer)
	//	if err != nil {
	//		fmt.Println("Error reading from UPD:", err)
	//		continue
	//	}
	//
	//	message := string(buffer[:n])
	//	fmt.Printf("Received %d bytes from %s: %s\n", n, remoteAddr, message)
	//}
	log.SetOutput(os.Stdout)
	server := dns.NewServer()

	serve(server)
}

func serve(server *dns.Server) {
	// TODO: Add configurable port
	addr, err := net.ResolveUDPAddr("udp", ":8080")
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
		n, _, err := conn.ReadFromUDP(buf)
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
		}(n, bytes.Clone(buf[:n]), addr)
	}
}
