package main

import "net/netip"

// Implements just enough of DHCP. Not standards compliant.
func (self *LazyProxy) ServeDHCP() error {
	var err error
	var buffer []byte = make([]byte, 0, 65535)
	var nextip netip.Addr = self.MyAddr.Masked().Addr()
	defer self.listen[1].Close()
	defer self.listen[2].Close()
	masked := netip.PrefixFrom(netip.MustParseAddr("255.255.255.255"), self.MyAddr.Bits()).Masked().Addr().AsSlice()
outer:
	for {
		var mstype uint8  // DHCP Message Type
		var creqip []byte // Requested IP
		var hostnm string // Client hostname
		length := 0
		length, _, err = self.listen[1].ReadFromUDPAddrPort(buffer[0:cap(buffer)])
		if err != nil {
			return err
		}
		buffer = buffer[0:length]
		if len(buffer) < 243 {
			continue
		}
		if buffer[0] != 0x01 {
			continue
		}
		if string(buffer[236:240]) != string([]byte{0x63, 0x82, 0x53, 0x63}) {
			continue
		}
		for parse := buffer[240:len(buffer)]; parse[0] != 0xff; parse = parse[int(parse[1])+2 : len(parse)] {
			if len(parse) < int(parse[1])+3 {
				continue outer
			}
			switch parse[0] {
			case 53:
				mstype = parse[2]
			case 50:
				creqip = parse[2:6]
			case 54:
				if string(parse[2:6]) != string(self.MyAddr.Addr().AsSlice()) {
					continue outer
				}
			case 12:
				hostnm = string(append([]byte{}, parse[2:int(parse[1])+2]...))
			}
		}
		buffer = buffer[0:240]
		buffer[0] = 0x02
		switch mstype {
		case 1:
			nextip = nextip.Next()
			if self.MyAddr.Addr() == nextip {
				nextip = nextip.Next()
			}
			if !self.MyAddr.Contains(nextip) {
				nextip = self.MyAddr.Masked().Addr().Next()
				if self.MyAddr.Addr() == nextip {
					nextip = nextip.Next()
				}
			}
			copy(buffer[16:len(buffer)], nextip.AsSlice())
			buffer = append(buffer, []byte{0x35, 0x01, 0x02}...)
		case 3:
			if len(creqip) > 0 {
				copy(buffer[16:len(buffer)], creqip)
			}
			if hostnm != "" {
				self.Resolv[hostnm], _ = netip.AddrFromSlice(creqip)
			}
			buffer = append(buffer, []byte{0x35, 0x01, 0x05}...)
		default:
			continue
		}
		buffer = append(buffer, append([]byte{0x36, 0x04}, self.MyAddr.Addr().AsSlice()...)...) // Server identifier
		buffer = append(buffer, append([]byte{0x03, 0x04}, self.MyAddr.Addr().AsSlice()...)...) // Gateway
		buffer = append(buffer, append([]byte{0x06, 0x04}, self.MyAddr.Addr().AsSlice()...)...) // DNS
		buffer = append(buffer, append([]byte{0x01, 0x04}, masked...)...)                       // Mask
		buffer = append(buffer, []byte{0x33, 0x04, 0xff, 0xff, 0xff, 0xff}...)                  // Lease Time
		buffer = append(buffer, 0xff)
		_, err = self.listen[2].WriteToUDPAddrPort(buffer, netip.MustParseAddrPort("255.255.255.255:68"))
		if err != nil {
			return err
		}
	}
}
