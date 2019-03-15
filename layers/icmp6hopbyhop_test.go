// Copyright 2012, Google, Inc. All rights reserved.
// Copyright 2009-2011 Andreas Krennmair. All rights reserved.
//
// Use of this source code is governed by a BSD-style license
// that can be found in the LICENSE file in the root of the source
// tree.

package layers

import (
	"github.com/hatching/gopacket"
	"testing"
)

var icmp6HopByHopData = []byte{
	// Ethernet layer
	0x33, 0x33, 0x00, 0x00, 0x00, 0x16, // destination
	0x1e, 0xc3, 0xe3, 0xb7, 0xc4, 0xd5, //  source
	0x86, 0xdd, // type IPv6

	// IPv6 layer
	0x60, 0x00, 0x00, 0x00, // version; traffic class; flow label
	0x00, 0x88, // payload length?
	0x00,                                                                                           // Next Header
	0x01,                                                                                           // Hop Limit
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // source
	0xff, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x16, // destination

	// IPv6 Hop-by-hop option
	0x3a,                               // Next Header - IPv6-ICMP
	0x00,                               // Hdr Ext Len
	0x05, 0x02, 0x00, 0x00, 0x01, 0x00, // Options and Padding

	// ICMPv6 layer
	0x8f, 0x00, // ICMP type 143, code 0

	0x9e, 0xed, 0x00, 0x00, 0x00, 0x06, 0x03, 0x00,
	0x00, 0x00, 0xff, 0x02, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0xff, 0xb7,
	0xc4, 0xd5, 0x03, 0x00, 0x00, 0x00, 0xff, 0x02,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x01, 0xff, 0x00, 0x00, 0x00, 0x04, 0x00,
	0x00, 0x00, 0xff, 0x02, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0xff, 0x11,
	0x00, 0x79, 0x04, 0x00, 0x00, 0x00, 0xff, 0x02,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x01, 0xff, 0x00, 0x00, 0x01, 0x04, 0x00,
	0x00, 0x00, 0xff, 0x05, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x02, 0x04, 0x00, 0x00, 0x00, 0xff, 0x02,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x02,
}

func TestPacketICMPv6WithHopByHop(t *testing.T) {
	var ethLayerResp Ethernet
	var ipV6LayerResp IPv6
	var icmpLayerResp ICMPv6
	var payload gopacket.Payload

	parser := gopacket.NewDecodingLayerParser(LayerTypeEthernet, &ethLayerResp, &ipV6LayerResp, &icmpLayerResp, &payload)
	parser.IgnoreUnsupported = true // avoid `No decoder for layer type ICMPv6RouterAdvertisement` error

	respLayers := make([]gopacket.LayerType, 0)
	err := parser.DecodeLayers(icmp6HopByHopData, &respLayers)

	if err != nil {
		t.Errorf("error decoding layers %s", err)
		return
	}

	expectedType := uint8(icmp6HopByHopData[62])
	actualType := uint8(icmpLayerResp.TypeCode.Type())
	if expectedType != actualType {
		t.Errorf("expected ICMP layer's TypeCode to be %d but was %d", expectedType, actualType)
	}

	p := gopacket.NewPacket(icmp6HopByHopData, LinkTypeEthernet, gopacket.Default)
	if p.ErrorLayer() != nil {
		t.Error("Failed to decode packet:", p.ErrorLayer().Error())
	}
	checkLayers(p, []gopacket.LayerType{LayerTypeEthernet, LayerTypeIPv6, LayerTypeIPv6HopByHop, LayerTypeICMPv6}, t)
	// See https://github.com/hatching/gopacket/issues/517
	// checkSerialization(p, t)
}
