// Copyright 2012, Google, Inc. All rights reserved.
//
// Use of this source code is governed by a BSD-style license
// that can be found in the LICENSE file in the root of the source
// tree.

package layers

import (
	"github.com/hatching/gopacket"
	"reflect"
	"testing"
)

// testPacketIPSecAHTransport is the packet:
//   20:45:10.325850 IP 192.168.1.1 > 192.168.1.2: AH(spi=0x00000101,seq=0x1): ICMP echo request, id 1560, seq 1, length 64
//      0x0000:  7ec0 ffc6 48f1 1a0e 3c4e 3b3a 0800 4500  ~...H...<N;:..E.
//      0x0010:  006c 650a 4000 4033 5201 c0a8 0101 c0a8  .le.@.@3R.......
//      0x0020:  0102 0104 0000 0000 0101 0000 0001 2533  ..............%3
//      0x0030:  01b1 a20b b6f1 bdbf 9d9e 0800 fbe5 0618  ................
//      0x0040:  0001 c6e1 a354 0000 0000 c8f7 0400 0000  .....T..........
//      0x0050:  0000 1011 1213 1415 1617 1819 1a1b 1c1d  ................
//      0x0060:  1e1f 2021 2223 2425 2627 2829 2a2b 2c2d  ...!"#$%&'()*+,-
//      0x0070:  2e2f 3031 3233 3435 3637                 ./01234567
var testPacketIPSecAHTransport = []byte{
	0x7e, 0xc0, 0xff, 0xc6, 0x48, 0xf1, 0x1a, 0x0e, 0x3c, 0x4e, 0x3b, 0x3a, 0x08, 0x00, 0x45, 0x00,
	0x00, 0x6c, 0x65, 0x0a, 0x40, 0x00, 0x40, 0x33, 0x52, 0x01, 0xc0, 0xa8, 0x01, 0x01, 0xc0, 0xa8,
	0x01, 0x02, 0x01, 0x04, 0x00, 0x00, 0x00, 0x00, 0x01, 0x01, 0x00, 0x00, 0x00, 0x01, 0x25, 0x33,
	0x01, 0xb1, 0xa2, 0x0b, 0xb6, 0xf1, 0xbd, 0xbf, 0x9d, 0x9e, 0x08, 0x00, 0xfb, 0xe5, 0x06, 0x18,
	0x00, 0x01, 0xc6, 0xe1, 0xa3, 0x54, 0x00, 0x00, 0x00, 0x00, 0xc8, 0xf7, 0x04, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d,
	0x1e, 0x1f, 0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28, 0x29, 0x2a, 0x2b, 0x2c, 0x2d,
	0x2e, 0x2f, 0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37,
}

func TestPacketIPSecAHTransport(t *testing.T) {
	p := gopacket.NewPacket(testPacketIPSecAHTransport, LinkTypeEthernet, gopacket.Default)
	if p.ErrorLayer() != nil {
		t.Error("Failed to decode packet:", p.ErrorLayer().Error())
	}
	checkLayers(p, []gopacket.LayerType{LayerTypeEthernet, LayerTypeIPv4, LayerTypeIPSecAH, LayerTypeICMPv4, gopacket.LayerTypePayload}, t)
	if got, ok := p.Layer(LayerTypeIPSecAH).(*IPSecAH); ok {
		want := &IPSecAH{
			Reserved:           0x0,
			SPI:                0x101,
			Seq:                1,
			AuthenticationData: []byte{0x25, 0x33, 0x01, 0xb1, 0xa2, 0x0b, 0xb6, 0xf1, 0xbd, 0xbf, 0x9d, 0x9e},
		}
		want.BaseLayer = BaseLayer{testPacketIPSecAHTransport[34:58], testPacketIPSecAHTransport[58:]}
		want.NextHeader = IPProtocolICMPv4
		want.HeaderLength = 0x4
		want.ActualLength = 0x18
		if !reflect.DeepEqual(want, got) {
			t.Errorf("IPSecAH layer mismatch, \nwant %#v\ngot  %#v\n", want, got)
		}
	}
}

func BenchmarkDecodePacketIPSecAHTransport(b *testing.B) {
	for i := 0; i < b.N; i++ {
		gopacket.NewPacket(testPacketIPSecAHTransport, LinkTypeEthernet, gopacket.NoCopy)
	}
}

// testPacketIPSecAHTunnel is the packet:
//   14:45:43.252917 IP 192.168.1.1 > 192.168.1.2: AH(spi=0x00000101,seq=0x1): IP 172.16.1.1 > 172.16.2.1: ICMP echo request, id 31322, seq 1, length 64 (ipip-proto-4)
//      0x0000:  7220 4d91 63c9 566c ed2d 73cd 0800 4500  r.M.c.Vl.-s...E.
//      0x0010:  0080 0000 4000 4033 b6f7 c0a8 0101 c0a8  ....@.@3........
//      0x0020:  0102 0404 0000 0000 0101 0000 0001 cca4  ................
//      0x0030:  01da 9eb4 fb75 10fe 5a59 4500 0054 a96f  .....u..ZYE..T.o
//      0x0040:  4000 4001 3617 ac10 0101 ac10 0201 0800  @.@.6...........
//      0x0050:  d75f 7a5a 0001 0741 3355 0000 0000 a9db  ._zZ...A3U......
//      0x0060:  0300 0000 0000 1011 1213 1415 1617 1819  ................
//      0x0070:  1a1b 1c1d 1e1f 2021 2223 2425 2627 2829  .......!"#$%&'()
//      0x0080:  2a2b 2c2d 2e2f 3031 3233 3435 3637       *+,-./01234567
var testPacketIPSecAHTunnel = []byte{
	0x72, 0x20, 0x4d, 0x91, 0x63, 0xc9, 0x56, 0x6c, 0xed, 0x2d, 0x73, 0xcd, 0x08, 0x00, 0x45, 0x00,
	0x00, 0x80, 0x00, 0x00, 0x40, 0x00, 0x40, 0x33, 0xb6, 0xf7, 0xc0, 0xa8, 0x01, 0x01, 0xc0, 0xa8,
	0x01, 0x02, 0x04, 0x04, 0x00, 0x00, 0x00, 0x00, 0x01, 0x01, 0x00, 0x00, 0x00, 0x01, 0xcc, 0xa4,
	0x01, 0xda, 0x9e, 0xb4, 0xfb, 0x75, 0x10, 0xfe, 0x5a, 0x59, 0x45, 0x00, 0x00, 0x54, 0xa9, 0x6f,
	0x40, 0x00, 0x40, 0x01, 0x36, 0x17, 0xac, 0x10, 0x01, 0x01, 0xac, 0x10, 0x02, 0x01, 0x08, 0x00,
	0xd7, 0x5f, 0x7a, 0x5a, 0x00, 0x01, 0x07, 0x41, 0x33, 0x55, 0x00, 0x00, 0x00, 0x00, 0xa9, 0xdb,
	0x03, 0x00, 0x00, 0x00, 0x00, 0x00, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19,
	0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f, 0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28, 0x29,
	0x2a, 0x2b, 0x2c, 0x2d, 0x2e, 0x2f, 0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37,
}

func TestPacketIPSecAHTunnel(t *testing.T) {
	p := gopacket.NewPacket(testPacketIPSecAHTunnel, LinkTypeEthernet, gopacket.Default)
	if p.ErrorLayer() != nil {
		t.Error("Failed to decode packet:", p.ErrorLayer().Error())
	}
	checkLayers(p, []gopacket.LayerType{LayerTypeEthernet, LayerTypeIPv4, LayerTypeIPSecAH, LayerTypeIPv4, LayerTypeICMPv4, gopacket.LayerTypePayload}, t)
	if got, ok := p.Layer(LayerTypeIPSecAH).(*IPSecAH); ok {
		want := &IPSecAH{
			Reserved:           0x0,
			SPI:                0x101,
			Seq:                1,
			AuthenticationData: []byte{0xcc, 0xa4, 0x01, 0xda, 0x9e, 0xb4, 0xfb, 0x75, 0x10, 0xfe, 0x5a, 0x59},
		}
		want.BaseLayer = BaseLayer{testPacketIPSecAHTunnel[34:58], testPacketIPSecAHTunnel[58:]}
		want.NextHeader = IPProtocolIPv4
		want.HeaderLength = 0x4
		want.ActualLength = 0x18
		if !reflect.DeepEqual(want, got) {
			t.Errorf("IPSecAH layer mismatch, \nwant %#v\ngot  %#v\n", want, got)
		}
	}
}

func BenchmarkDecodePacketIPSecAHTunnel(b *testing.B) {
	for i := 0; i < b.N; i++ {
		gopacket.NewPacket(testPacketIPSecAHTunnel, LinkTypeEthernet, gopacket.NoCopy)
	}
}

// testPacketIPSecESP is the packet:
//   04:30:37.629376 IP 190.0.0.1 > 190.0.0.2: ESP(spi=0x0000006e,seq=0x13), length 116
//      0x0000:  0000 0000 0012 0011 434a d70a 0800 4500  ........CJ....E.
//      0x0010:  0088 0000 4000 4032 be40 be00 0001 be00  ....@.@2.@......
//      0x0020:  0002 0000 006e 0000 0013 82f4 1077 0418  .....n.......w..
//      0x0030:  e8ce dc45 1bac 22bb daaf 2ad2 c2e8 315b  ...E.."...*...1[
//      0x0040:  ce9a 39da 2aae cf43 3716 70ab 7e7c 4676  ..9.*..C7.p.~|Fv
//      0x0050:  c3fc d109 c990 274d f81c 6534 9a40 a0ef  ......'M..e4.@..
//      0x0060:  46b1 7da5 05af dda8 d0ba 6e23 d1ee 1f10  F.}.......n#....
//      0x0070:  730c 7371 03b1 445c 2f70 852f 8475 12fb  s.sq..D\/p./.u..
//      0x0080:  b057 a19b a617 bae7 09ca 8836 942f 3334  .W.........6./34
//      0x0090:  312b 96d2 a4e3                           1+....
var testPacketIPSecESP = []byte{
	0x00, 0x00, 0x00, 0x00, 0x00, 0x12, 0x00, 0x11, 0x43, 0x4a, 0xd7, 0x0a, 0x08, 0x00, 0x45, 0x00,
	0x00, 0x88, 0x00, 0x00, 0x40, 0x00, 0x40, 0x32, 0xbe, 0x40, 0xbe, 0x00, 0x00, 0x01, 0xbe, 0x00,
	0x00, 0x02, 0x00, 0x00, 0x00, 0x6e, 0x00, 0x00, 0x00, 0x13, 0x82, 0xf4, 0x10, 0x77, 0x04, 0x18,
	0xe8, 0xce, 0xdc, 0x45, 0x1b, 0xac, 0x22, 0xbb, 0xda, 0xaf, 0x2a, 0xd2, 0xc2, 0xe8, 0x31, 0x5b,
	0xce, 0x9a, 0x39, 0xda, 0x2a, 0xae, 0xcf, 0x43, 0x37, 0x16, 0x70, 0xab, 0x7e, 0x7c, 0x46, 0x76,
	0xc3, 0xfc, 0xd1, 0x09, 0xc9, 0x90, 0x27, 0x4d, 0xf8, 0x1c, 0x65, 0x34, 0x9a, 0x40, 0xa0, 0xef,
	0x46, 0xb1, 0x7d, 0xa5, 0x05, 0xaf, 0xdd, 0xa8, 0xd0, 0xba, 0x6e, 0x23, 0xd1, 0xee, 0x1f, 0x10,
	0x73, 0x0c, 0x73, 0x71, 0x03, 0xb1, 0x44, 0x5c, 0x2f, 0x70, 0x85, 0x2f, 0x84, 0x75, 0x12, 0xfb,
	0xb0, 0x57, 0xa1, 0x9b, 0xa6, 0x17, 0xba, 0xe7, 0x09, 0xca, 0x88, 0x36, 0x94, 0x2f, 0x33, 0x34,
	0x31, 0x2b, 0x96, 0xd2, 0xa4, 0xe3,
}

func TestPacketIPSecESP(t *testing.T) {
	p := gopacket.NewPacket(testPacketIPSecESP, LinkTypeEthernet, gopacket.Default)
	if p.ErrorLayer() != nil {
		t.Error("Failed to decode packet:", p.ErrorLayer().Error())
	}
	checkLayers(p, []gopacket.LayerType{LayerTypeEthernet, LayerTypeIPv4, LayerTypeIPSecESP}, t)
}

func BenchmarkDecodePacketIPSecESP(b *testing.B) {
	for i := 0; i < b.N; i++ {
		gopacket.NewPacket(testPacketIPSecESP, LinkTypeEthernet, gopacket.NoCopy)
	}
}
