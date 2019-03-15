// Copyright 2018 The GoPacket Authors. All rights reserved.
//
// Use of this source code is governed by a BSD-style license
// that can be found in the LICENSE file in the root of the source
// tree.

package layers

import (
	"encoding/binary"
	"errors"
	"fmt"

	"github.com/hatching/gopacket"
)

type TLSHandshakeType uint8

const (
	TLSHandshakeHelloRequest       TLSHandshakeType = 0
	TLSHandshakeClientHello        TLSHandshakeType = 1
	TLSHandshakeServerHello        TLSHandshakeType = 2
	TLSHandshakeCertificate        TLSHandshakeType = 11
	TLSHandshakeServerKeyExchange  TLSHandshakeType = 12
	TLSHandshakeCertificateRequest TLSHandshakeType = 13
	TLSHandshakeServerHelloDone    TLSHandshakeType = 14
	TLSHandshakeCertificateVerify  TLSHandshakeType = 15
	TLSHandshakeClientKeyExchange  TLSHandshakeType = 16
	TLSHandshakeFinished           TLSHandshakeType = 20
)

// TLSHandshakeRecord defines the structure of a Handshare Record
type TLSHandshakeRecord struct {
	TLSRecordHeader

	HandshakeType   TLSHandshakeType
	HandshakeLength int

	ServerHello []TLSHandshakeServerHelloRecord
}

// DecodeFromBytes decodes the slice into the TLS struct.
func (t *TLSHandshakeRecord) decodeFromBytes(h TLSRecordHeader, data []byte, df gopacket.DecodeFeedback) error {
	// TLS Record Header
	t.ContentType = h.ContentType
	t.Version = h.Version
	t.Length = h.Length

	if len(data) != int(t.Length) {
		return errors.New("TLS Handshake length mismatch")
	}

	// TODO Is this an error?
	if t.Length < 4 {
		return nil
	}

	t.HandshakeType = TLSHandshakeType(data[0])
	t.HandshakeLength = int(data[1])*0x10000 + int(data[2])*0x100 + int(data[3])
	if t.HandshakeLength+4 > len(data) {
		df.SetTruncated()
		return errors.New("TLS Handshake length mismatch")
	}

	switch t.HandshakeType {
	case TLSHandshakeServerHello:
		var r TLSHandshakeServerHelloRecord
		err := r.decodeFromBytes(data[4:4+t.HandshakeLength], df)
		if err != nil {
			return err
		}
		t.ServerHello = append(t.ServerHello, r)
	default:
		// TODO More Handshake handlers.
		return fmt.Errorf("TLS Handshake message not implemented yet: %d", t.HandshakeType)
	}
	return nil
}

type TLSHandshakeServerHelloRecord struct {
	Version           uint16
	Random            []byte
	SessionId         []byte
	CipherSuite       uint16
	CompressionMethod uint8

	// TODO Extensions
}

func (t *TLSHandshakeServerHelloRecord) decodeFromBytes(data []byte, df gopacket.DecodeFeedback) error {
	if len(data) < 38 {
		df.SetTruncated()
		return errors.New("TLS Handshake ServerHello packet length mismatch")
	}

	t.Version = binary.BigEndian.Uint16(data[:2])
	t.Random = data[2:34]
	length := int(data[34])
	if length+38 > len(data) {
		df.SetTruncated()
		return errors.New("TLS Handshake ServerHello packet length mismatch")
	}

	t.SessionId = data[35 : length+35]
	t.CipherSuite = binary.BigEndian.Uint16(data[35+length : 37+length])
	t.CompressionMethod = data[length+37]
	return nil
}
