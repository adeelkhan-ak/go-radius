package main

// Use tcpdump to create a test file
// tcpdump -w test.pcap

import (
	"fmt"
	"log"
	"os"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/pcap"
)

var (
	device      string = "ens33" // choose your device heres
	snapshotLen int32  = 1024
	promiscuous bool   = false
	err         error
	timeout     time.Duration = 30 * time.Second
	handle      *pcap.Handle
	pcapFile    string
)

func printPacketInfo(packet gopacket.Packet) {

	// this applicationLayer. applicationLayer contains the payload
	applicationLayer := packet.ApplicationLayer()
	if applicationLayer != nil {

		paylaod := packet.Data()
		paylaod = paylaod[42:]
		// Radius header
		radius_code := uint8(paylaod[0])
		fmt.Printf("accounting REquest : %d\n", radius_code)
		radius_id := uint8(paylaod[1])
		fmt.Printf("Packet identifier : %d\n", radius_id)
		l := uint16(paylaod[2])<<8 | uint16(paylaod[3])
		fmt.Printf("Length : %d\n", l)
		var authenticator [16]byte
		for i := range authenticator {
			authenticator[i] = paylaod[4+i]
		}
		fmt.Printf("Authenticator : %x\n", authenticator)
		paylaod = paylaod[20:]
		//fmt.Println("length ", len(paylaod))
		for len(paylaod) > 1 {
			types := paylaod[0]
			//fmt.Printf("types %d: ", types)
			length := paylaod[1]
			if types == 31 {
				fmt.Printf("Calling station id : %s\n", paylaod[1:14])

			}
			paylaod = paylaod[length:]
			//fmt.Println("length : ", length)

		}
		// Check for errors
		if err := packet.ErrorLayer(); err != nil {
			fmt.Println("Error decoding some part of the packet:", err)
		}
	}
}
func main() {
	argsWithoutProg := os.Args[1:]
	if len(argsWithoutProg) == 0 {
		fmt.Println("please use valid argument or use -h or --help for help menu")
		return
	}
	if argsWithoutProg[0] == "-f" || argsWithoutProg[0] == "--file" {
		if len(argsWithoutProg) < 2 {
			return
		}
		pcapFile = argsWithoutProg[1]
		// Open file instead of device
		handle, err = pcap.OpenOffline(pcapFile)
	}

	if len(argsWithoutProg) == 1 {
		if argsWithoutProg[0] == "-l" || argsWithoutProg[0] == "--live" {
			// for live environment
			handle, err = pcap.OpenLive(device, snapshotLen, promiscuous, timeout)
		}
		if argsWithoutProg[0] == "-h" || argsWithoutProg[0] == "--help" {
			// for help menu
			fmt.Println("arguments must be :")
			fmt.Println("-f or --file for using file e.g -f radius.pcap")
			fmt.Println("-l or --live for using live traffic ")
			fmt.Println("-h or --help for seeing help menu")
			return
		}
	}
	if err != nil {
		log.Fatal(err)
	}
	defer handle.Close()
	var filter string = "udp and port 1812 or port 1813"
	err = handle.SetBPFFilter(filter)
	if err != nil {
		log.Fatal(err)
	}
	// Loop through packets in file
	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
	for packet := range packetSource.Packets() {
		// Do something with a packet here.
		printPacketInfo(packet)
		return
	}

}
