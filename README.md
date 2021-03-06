![image](https://user-images.githubusercontent.com/67287458/147471198-93d37a4d-93bf-4c89-9dee-a29e8c3479af.png)

# go-radius
Radius parsing in golang using gopacket. You can parse from either live traffic or from pcap of your choice.

### RADIUS

RADIUS is an AAA (authentication, authorization, and accounting) protocol that manages network access. RADIUS uses two types of packets to manage the full AAA process: Access-Request, which manages authentication and authorization; and Accounting-Request, which manages accounting. Authentication and authorization are defined in RFC 2865 while accounting is described by RFC 2866

### How to run
```
# Get the gopacket package from GitHub
go get github.com/google/gopacket
# Pcap dev headers might be necessary
sudo apt-get install libpcap-dev
go build main.go  
./main -h       
```
