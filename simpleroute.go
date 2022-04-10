package main

import (
	"fmt"
	"log"
	"net"
	"os"
	"strconv"
	"strings"
	"syscall"

	"golang.org/x/net/ipv4"
)

func sliceAtob(strings []string) ([]byte, error) {
	bytes := make([]byte, 0, len(strings))

	for _, str := range strings {
		i, err := strconv.Atoi(str)
		if err != nil {
			return bytes, err
		}
		bytes = append(bytes, byte(i))
	}

	return bytes, nil
}

func calcChecksum(b []byte) uint16 {
	var sum uint32
	for i := 0; i < len(b); i += 2 {
		sum += uint32(b[i]) | (uint32(b[i+1]) << 8)
	}
	sum = (sum >> 16) + (sum & 0xffff)
	sum = (sum >> 16) + (sum & 0xffff)
	return uint16(^sum)
}

func makePacket(dst []byte) ([]byte, error) {
	v4Header := ipv4.Header{
		Version:  4,
		Len:      20,
		TotalLen: 30,
		TTL:      3,
		Protocol: 1, //ICMP
		Dst:      net.IPv4(dst[0], dst[1], dst[2], dst[3]),
	}

	icmp := []byte{
		8,    //Type ICMP echo message
		0,    //Code
		0,    //Checksum
		0,    //Checksum
		0,    //Identifier
		0,    //Identifier
		0,    //Sequence Number
		0,    //Sequence Number
		0xc0, //Data
		0xDE, //Data
	}
	checksum := calcChecksum(icmp)
	icmp[2] = byte(checksum)
	icmp[3] = byte(checksum >> 8)

	ippacket, err := v4Header.Marshal()
	if err != nil {
		return ippacket, err
	}
	return append(ippacket, icmp...), nil
}

func convertIPv4AddrByteToStr(addr []byte) string {
	var strAddr string
	for cnt, s := range addr {
		strAddr += strconv.Itoa(int(s))
		if cnt != 3 {
			strAddr += "."
		}
	}
	return strAddr
}

func makeSocket() (sfd int, rfd int, serr error, rerr error) {
	sfd, serr = syscall.Socket(syscall.AF_INET, syscall.SOCK_RAW, syscall.IPPROTO_RAW)
	rfd, rerr = syscall.Socket(syscall.AF_INET, syscall.SOCK_RAW, syscall.IPPROTO_ICMP)
	return sfd, rfd, serr, rerr
}

func main() {
	if len(os.Args) < 2 {
		fmt.Println("Arg Err")
		os.Exit(1)
	}

	dst, err := sliceAtob(strings.Split(os.Args[1], "."))
	if err != nil {
		log.Fatal(err)
	}

	sfd, rfd, serr, rerr := makeSocket()
	if serr != nil || rerr != nil {
		log.Fatal(serr)
		log.Fatal(rerr)
	}

	sock_addr := syscall.SockaddrInet4{
		Port: 0,
		Addr: [4]byte{dst[0], dst[1], dst[2], dst[3]},
	}

	packet, err := makePacket(dst)
	if err != nil {
		log.Fatal(err)
	}

	err = syscall.Sendto(sfd, packet, 0, &sock_addr)
	if err != nil {
		log.Fatal(err)
	}

	recvIPv4Buf := make([]byte, 1024)
	var hopCnt int

	if _, _, err = syscall.Recvfrom(rfd, recvIPv4Buf, 0); err != nil {
		log.Fatal(err)
	}

	if recvIPv4Buf[9] == 1 { //IP Header Protocol: ICMP
		recvICMPBuf := recvIPv4Buf[20:]
		if recvICMPBuf[0] == 11 { //TTL Exceeded
			addr := convertIPv4AddrByteToStr(recvIPv4Buf[12:16])
			domain, err := net.LookupAddr(addr)
			if err != nil {
				log.Fatal(err)
			}
			fmt.Printf("%d. %s %s \n", hopCnt, addr, domain)
			hopCnt++
		}
	}

}
