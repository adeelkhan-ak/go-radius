package main

// Use tcpdump to create a test file
// tcpdump -w test.pcap
import (
	"fmt"
	"html"
	"log"
	"os"
	"os/exec"
	"runtime"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
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

type radius_attr struct {
	Type   byte
	Length byte
}
type ethernet struct {
	SrcMAC       string
	DstMAC       string
	EthernetType string
}
type ip struct {
	SrcIP string
	DstIP string
}

type port struct {
	SrcPort uint16
	DstPort uint16
}
type radius struct {
	Code             uint8
	PacketIdentifier uint8
	Length           uint16
	Authenticator    [16]byte
}

var clear map[string]func() //create a map for storing clear funcs

func init() {
	clear = make(map[string]func()) //Initialize it
	clear["linux"] = func() {
		cmd := exec.Command("clear") //Linux example, its tested
		cmd.Stdout = os.Stdout
		cmd.Run()
	}
	clear["windows"] = func() {
		cmd := exec.Command("cmd", "/c", "cls") //Windows example, its tested
		cmd.Stdout = os.Stdout
		cmd.Run()
	}
}

func CallClear() {
	value, ok := clear[runtime.GOOS] //runtime.GOOS -> linux, windows, darwin etc.
	if ok {                          //if we defined a clear func for that platform:
		value() //we execute it
	} else { //unsupported platform
		panic("Your platform is unsupported! I can't clear terminal screen :(")
	}
}
func logo() {

	colorReset := "\033[0m"
	colorGreen := "\033[32m"
	colorRed := "\033[31m"
	fmt.Print(string(colorRed), "")
	fmt.Print(string(colorGreen), "")
	str := html.UnescapeString("\u26AA")
	s := html.UnescapeString("\U0001F1F5\U0001F1F0")
	fmt.Println("            _ __   __ __    ___   __ __ ___  ")
	fmt.Printf("   	   | '_ \\ / _` /____| |%s || ||/ __|  \n", str)
	fmt.Println("   	   | |_) | (_| | |__| ||| ||_||\\__ \\  ")
	fmt.Println("   	   | .__/ \\__,_|____/\\|||_|___|/___/  ")
	fmt.Println("   	   | |\\ \\                          ")
	fmt.Printf("   	   |_| |_|")
	fmt.Println(string(colorReset), "", s)

}

const hexDigit = "0123456789abcdef"

func ethernet_parser(ethernet []byte) string {
	if len(ethernet) == 0 {
		return ""
	}
	buf := make([]byte, 0, len(ethernet)*3-1)
	for i, b := range ethernet {
		if i > 0 {
			buf = append(buf, ':')
		}
		buf = append(buf, hexDigit[b>>4])
		buf = append(buf, hexDigit[b&0xF])
	}
	return string(buf)
}
func printPacketInfo(packet gopacket.Packet) {

	var r_attr radius_attr
	var eth_net ethernet
	var ip_layer ip
	var udpPort port
	var radius radius
	// Layer2
	ethernetLayer := packet.Layer(layers.LayerTypeEthernet)
	if ethernetLayer != nil {
		fmt.Println("Ethernet layer detected.")
		ethernetPacket, _ := ethernetLayer.(*layers.Ethernet)
		eth_net.SrcMAC = ethernet_parser(ethernetPacket.SrcMAC)
		eth_net.DstMAC = ethernet_parser(ethernetPacket.DstMAC)
		fmt.Println("Source MAC: ", eth_net.SrcMAC)
		fmt.Println("Destination MAC: ", eth_net.DstMAC)
		eth_net.EthernetType = fmt.Sprint("", ethernetPacket.EthernetType)

		fmt.Println("Ethernet type: ", eth_net.EthernetType)
		fmt.Println()
	}

	// Layer 3
	ipLayer := packet.Layer(layers.LayerTypeIPv4)
	if ipLayer != nil {
		fmt.Println("IPv4 layer detected.")
		ip, _ := ipLayer.(*layers.IPv4)
		ip_layer.DstIP = fmt.Sprint("", ip.DstIP)
		ip_layer.SrcIP = fmt.Sprint("", ip.SrcIP)
		fmt.Printf("From %s to %s\n", ip_layer.SrcIP, ip_layer.DstIP)
		fmt.Println("Protocol: ", ip.Protocol)
		//fmt.Println()
	}

	// Layer 4
	udpLayer := packet.Layer(layers.LayerTypeUDP)
	if udpLayer != nil {
		udp, _ := udpLayer.(*layers.UDP)
		udpPort.SrcPort = uint16(udp.SrcPort)
		udpPort.DstPort = uint16(udp.DstPort)

		fmt.Printf("From port %d to %d\n", udpPort.SrcPort, udpPort.DstPort)
		fmt.Println()
	}
	// Iterate over all layers, printing out each layer type
	fmt.Println("All packet layers:")
	for _, layer := range packet.Layers() {
		fmt.Println("- ", layer.LayerType())
	}

	// this applicationLayer. applicationLayer contains the payload
	applicationLayer := packet.ApplicationLayer()
	if applicationLayer != nil {
		fmt.Println("Application layer/Payload found.")
		//fmt.Printf("%s\n", applicationLayer.Payload())

	}

	paylaod := packet.Data()
	paylaod = paylaod[42:]
	// Radius header
	radius.Code = uint8(paylaod[0])
	fmt.Printf("accounting REquest : %d\n", radius.Code)
	radius.PacketIdentifier = uint8(paylaod[1])
	fmt.Printf("Packet identifier : %d\n", radius.PacketIdentifier)
	radius.Length = uint16(paylaod[2])<<8 | uint16(paylaod[3])
	fmt.Printf("Length : %d\n", radius.Length)
	// var authenticator [16]byte
	for i := range radius.Authenticator {
		radius.Authenticator[i] = paylaod[4+i]
	}
	fmt.Printf("Authenticator : %x\n", radius.Authenticator)
	paylaod = paylaod[20:]
	//fmt.Println("length ", len(paylaod))
	for len(paylaod) > 1 {
		r_attr.Type = paylaod[0]
		//fmt.Printf("types %d: ", types)
		r_attr.Length = paylaod[1]
		if r_attr.Type == 31 {
			fmt.Printf("Calling station id : %s\n", paylaod[1:14])

		}
		paylaod = paylaod[r_attr.Length:]
		//fmt.Println("length : ", length)

	}
	// Check for errors
	if err := packet.ErrorLayer(); err != nil {
		fmt.Println("Error decoding some part of the packet:", err)
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

	CallClear()
	//fmt.Print("\033[2J") //Clear screen
	logo()

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
		fmt.Printf("\033[%d;%dH", 8, 1)
		// Do something with a packet here.
		printPacketInfo(packet)
		// return
	}

}
