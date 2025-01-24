package main

import "fmt"
import "golang.org/x/net/dns/dnsmessage"
import "golang.org/x/net/proxy"
import "io"
import "net"
import "net/netip"
import "time"

// Easy transparent proxy by abusing DNS
type LazyProxy struct {
	MyAddr netip.Prefix          // My IPv4 address
	Dialer proxy.Dialer          // Upstream dialer
	TLimit time.Duration         // Timeout to sniff virtual host
	Resolv map[string]netip.Addr // Specific resolutions
	listen [](*net.UDPConn)
	knowns map[netip.Addr]string
}

// Create listening sockets
func (self *LazyProxy) Listen() error {
	var err error
	self.listen = make([](*net.UDPConn), 4, 4)
	self.knowns = map[netip.Addr]string{}
	self.listen[0], err = net.ListenUDP("udp", net.UDPAddrFromAddrPort(netip.AddrPortFrom(self.MyAddr.Addr(), 53)))
	if err != nil {
		return err
	}
	self.listen[1], err = net.ListenUDP("udp", net.UDPAddrFromAddrPort(netip.MustParseAddrPort("255.255.255.255:67")))
	if err != nil {
		return err
	}
	self.listen[2], err = net.ListenUDP("udp", net.UDPAddrFromAddrPort(netip.AddrPortFrom(self.MyAddr.Addr(), 67)))
	if err != nil {
		return err
	}
	for portnm := uint16(1); portnm < 49152; portnm += 1 {
		var listen *net.TCPListener
		listen, err = net.ListenTCP("tcp", net.TCPAddrFromAddrPort(netip.AddrPortFrom(self.MyAddr.Addr(), portnm)))
		if err != nil {
			continue
		}
		go func() {
			defer listen.Close()
			for {
				var client *net.TCPConn
				client, err = listen.AcceptTCP()
				if err != nil {
					return
				}
				go func() {
					var hostnm string
					if value, ok := self.knowns[netip.MustParseAddr(µ(net.SplitHostPort(client.RemoteAddr().String()))[0].(string))]; ok {
						hostnm = value
					} else {
						_ = client.SetLinger(0)
						_ = client.Close()
						return
					}
					var buffer []byte = make([]byte, 0, 65535)
					client.SetReadDeadline(time.Now().Add(self.TLimit))
					value, length, _ := GuessB(client, buffer)
					buffer = buffer[0:length]
					if value != "" {
						hostnm = value
					}
					client.SetReadDeadline(time.Time{})
					var server io.ReadWriteCloser
					server, err = self.Dialer.Dial("tcp", fmt.Sprintf("%v:%v", hostnm, µ(net.SplitHostPort(client.LocalAddr().String()))[1].(string)))
					if err != nil {
						_ = client.SetLinger(0)
						_ = client.Close()
						return
					}
					if len(buffer) > 0 {
						_, err = server.Write(buffer)
						if err != nil {
							_ = client.SetLinger(0)
							_ = client.Close()
							return
						}
					}
					go func() {
						/*if _, ok := server.(io.ReaderFrom); ok {
							_, _ = server.(io.ReaderFrom).ReadFrom(client)
						} else {
							_, _ = client.WriteTo(server)
						}*/
						_, _ = io.Copy(server, client)
						_ = server.Close()
					}()
					go func() {
						_, err = client.ReadFrom(server)
						if err != nil {
							_ = client.SetLinger(0)
						}
						_ = client.Close()
					}()
				}()
			}
		}()
	}
	// TODO UDP
	return nil
}

// Serves DNS
func (self *LazyProxy) ServeDNS() error {
	var err error
	defer self.listen[0].Close()
	var buffer []byte = make([]byte, 0, 65535)
	for {
		var fromip netip.AddrPort
		length := 0
		length, fromip, err = self.listen[0].ReadFromUDPAddrPort(buffer[0:cap(buffer)])
		if err != nil {
			return err
		}
		buffer = buffer[0:length]
		var dnsmsg dnsmessage.Message
		err = dnsmsg.Unpack(buffer)
		if err != nil {
			continue
		}
		for _, value := range dnsmsg.Questions {
			if thing, ok := self.Resolv[value.Name.String()[0:len(value.Name.String())-1]]; ok {
				if value.Type == dnsmessage.TypeA && thing.Is4() {
					dnsmsg.Answers = append(dnsmsg.Answers, dnsmessage.Resource{
						Header: dnsmessage.ResourceHeader{
							Name:  value.Name,
							Class: value.Class,
							TTL:   0,
						},
						Body: &dnsmessage.AResource{
							A: thing.As4(),
						},
					})
				}
				if value.Type == dnsmessage.TypeAAAA && thing.Is6() {
					dnsmsg.Answers = append(dnsmsg.Answers, dnsmessage.Resource{
						Header: dnsmessage.ResourceHeader{
							Name:  value.Name,
							Class: value.Class,
							TTL:   0,
						},
						Body: &dnsmessage.AAAAResource{
							AAAA: thing.As16(),
						},
					})
				}
			} else {
				if value.Type == dnsmessage.TypeA {
					self.knowns[fromip.Addr()] = value.Name.String()[0 : len(value.Name.String())-1]
					dnsmsg.Answers = append(dnsmsg.Answers, dnsmessage.Resource{
						Header: dnsmessage.ResourceHeader{
							Name:  value.Name,
							Class: value.Class,
							TTL:   0,
						},
						Body: &dnsmessage.AResource{
							A: self.MyAddr.Addr().As4(),
						},
					})
				}
			}
		}
		_, err = self.listen[0].WriteToUDPAddrPort(µ((&dnsmessage.Message{
			Header: dnsmessage.Header{
				ID:       dnsmsg.Header.ID,
				Response: true,
				RCode:    dnsmessage.RCodeSuccess,
			},
			Questions: dnsmsg.Questions,
			Answers:   dnsmsg.Answers,
		}).Pack())[0].([]byte), fromip)
		if err != nil {
			return err
		}
	}
}

func µ(a ...any) []any {
	return a
}
