# go-radius
Radius parsing in golang using gopacket. You can parse from either live traffic or from pcap of your choice.

### RADIUS

RADIUS is an AAA (authentication, authorization, and accounting) protocol that manages network access. RADIUS uses two types of packets to manage the full AAA process: Access-Request, which manages authentication and authorization; and Accounting-Request, which manages accounting. Authentication and authorization are defined in RFC 2865 while accounting is described by RFC 2866

### How to run
```
go build main.go  
./main -h       
```
