// Copyright 2012 Google, Inc. All rights reserved.
// Copyright 2009-2012 Andreas Krennmair. All rights reserved.

package layers

import (
	"errors"
	"fmt"
	"github.com/gconnell/gopacket"
)

// EnumMetadata keeps track of a set of metadata for each enumeration value
// for protocol enumerations.
type EnumMetadata struct {
	// DecodeWith is the decoder to use to decode this protocol's data.
	DecodeWith gopacket.Decoder
	// Name is the name of the enumeration value.
	Name string
}

// errorFunc returns a decoder that spits out a specific error message.
func errorFunc(msg string) gopacket.Decoder {
	var e = errors.New(msg)
	return gopacket.DecodeFunc(func([]byte, gopacket.PacketBuilder) error {
		return e
	})
}

// EthernetType is an enumeration of ethernet type values, and acts as a decoder
// for any type it supports.
type EthernetType uint16

const (
	// EthernetTypeLLC is not an actual ethernet type.  It is instead a
	// placeholder we use in Ethernet frames that use the 802.3 standard of
	// srcmac|dstmac|length|LLC instead of srcmac|dstmac|ethertype.
	EthernetTypeLLC            EthernetType = 0
	EthernetTypeCiscoDiscovery EthernetType = 0x2000
	EthernetTypeIPv4           EthernetType = 0x0800
	EthernetTypeARP            EthernetType = 0x0806
	EthernetTypeIPv6           EthernetType = 0x86DD
	EthernetTypeDot1Q          EthernetType = 0x8100
	EthernetTypePPPoEDiscovery EthernetType = 0x8863
	EthernetTypePPPoESession   EthernetType = 0x8864
	EthernetTypeMPLSUnicast    EthernetType = 0x8847
	EthernetTypeMPLSMulticast  EthernetType = 0x8848
	EthernetTypeEthernetCTP    EthernetType = 0x9000
)

// IPProtocol is an enumeration of IP protocol values, and acts as a decoder
// for any type it supports.
type IPProtocol uint8

const (
	IPProtocolIPv6HopByHop IPProtocol = 0
	IPProtocolICMP         IPProtocol = 1
	IPProtocolTCP          IPProtocol = 6
	IPProtocolUDP          IPProtocol = 17
	IPProtocolRUDP         IPProtocol = 27
	IPProtocolIPv6         IPProtocol = 41
	IPProtocolIPv6Routing  IPProtocol = 43
	IPProtocolIPv6Fragment IPProtocol = 44
	IPProtocolGRE          IPProtocol = 47
	IPProtocolESP          IPProtocol = 50
	IPProtocolAH           IPProtocol = 51
	IPProtocolNoNextHeader IPProtocol = 59
	IPProtocolIPIP         IPProtocol = 94
	IPProtocolEtherIP      IPProtocol = 97
	IPProtocolSCTP         IPProtocol = 132
	IPProtocolUDPLite      IPProtocol = 136
	IPProtocolMPLSInIP     IPProtocol = 137
)

// LinkType is an enumeration of link types, and acts as a decoder for any
// link type it supports.
type LinkType uint8

const (
	// According to pcap-linktype(7).
	LinkTypeNull           LinkType = 0
	LinkTypeEthernet       LinkType = 1
	LinkTypeTokenRing      LinkType = 6
	LinkTypeArcNet         LinkType = 7
	LinkTypeSLIP           LinkType = 8
	LinkTypePPP            LinkType = 9
	LinkTypeFDDI           LinkType = 10
	LinkTypeATM_RFC1483    LinkType = 100
	LinkTypeRaw            LinkType = 101
	LinkTypePPP_HDLC       LinkType = 50
	LinkTypePPPEthernet    LinkType = 51
	LinkTypeC_HDLC         LinkType = 104
	LinkTypeIEEE802_11     LinkType = 105
	LinkTypeFRelay         LinkType = 107
	LinkTypeLoop           LinkType = 108
	LinkTypeLinuxSLL       LinkType = 113
	LinkTypeLTalk          LinkType = 104
	LinkTypePFLog          LinkType = 117
	LinkTypePrismHeader    LinkType = 119
	LinkTypeIPOverFC       LinkType = 122
	LinkTypeSunATM         LinkType = 123
	LinkTypeIEEE80211Radio LinkType = 127
	LinkTypeARCNetLinux    LinkType = 129
	LinkTypeLinuxIRDA      LinkType = 144
	LinkTypeLinuxLAPD      LinkType = 177
)

// PPPoECode is the PPPoE code enum, taken from http://tools.ietf.org/html/rfc2516
type PPPoECode uint8

const (
	PPPoECodePADI    PPPoECode = 0x09
	PPPoECodePADO    PPPoECode = 0x07
	PPPoECodePADR    PPPoECode = 0x19
	PPPoECodePADS    PPPoECode = 0x65
	PPPoECodePADT    PPPoECode = 0xA7
	PPPoECodeSession PPPoECode = 0x00
)

// PPPType is an enumeration of PPP type values, and acts as a decoder for any
// type it supports.
type PPPType uint16

const (
	PPPTypeIPv4 PPPType = 0x0021
	PPPTypeIPv6 PPPType = 0x0057
)

// SCTPChunkType is an enumeration of chunk types inside SCTP packets.
type SCTPChunkType uint8

const (
	SCTPChunkTypeData             SCTPChunkType = 0
	SCTPChunkTypeInit             SCTPChunkType = 1
	SCTPChunkTypeInitAck          SCTPChunkType = 2
	SCTPChunkTypeSack             SCTPChunkType = 3
	SCTPChunkTypeHeartbeat        SCTPChunkType = 4
	SCTPChunkTypeHeartbeatAck     SCTPChunkType = 5
	SCTPChunkTypeAbort            SCTPChunkType = 6
	SCTPChunkTypeShutdown         SCTPChunkType = 7
	SCTPChunkTypeShutdownAck      SCTPChunkType = 8
	SCTPChunkTypeError            SCTPChunkType = 9
	SCTPChunkTypeCookieEcho       SCTPChunkType = 10
	SCTPChunkTypeCookieAck        SCTPChunkType = 11
	SCTPChunkTypeShutdownComplete SCTPChunkType = 14
)

var (
	// Each of the following arrays contains mappings of how to handle enum
	// values for various enum types in gopacket/layers.
	//
	// So, EthernetTypeMetadata[2] contains information on how to handle EthernetType
	// 2, including which name to give it and which decoder to use to decode
	// packet data of that type.  These arrays are filled by default with all of the
	// protocols gopacket/layers knows how to handle, but users of the library can
	// add new decoders or override existing ones.  For example, if you write a better
	// TCP decoder, you can override IPProtocolMetadata[IPProtocolTCP].DecodeWith
	// with your new decoder, and all gopacket/layers decoding will use your new
	// decoder whenever they encounter that IPProtocol.
	EthernetTypeMetadata  [65536]EnumMetadata
	IPProtocolMetadata    [265]EnumMetadata
	SCTPChunkTypeMetadata [265]EnumMetadata
	PPPTypeMetadata       [65536]EnumMetadata
	PPPoECodeMetadata     [256]EnumMetadata
	LinkTypeMetadata      [256]EnumMetadata
)

func (a EthernetType) Decode(data []byte, p gopacket.PacketBuilder) error {
	return EthernetTypeMetadata[a].DecodeWith.Decode(data, p)
}
func (a EthernetType) String() string {
	return EthernetTypeMetadata[a].Name
}
func (a IPProtocol) Decode(data []byte, p gopacket.PacketBuilder) error {
	return IPProtocolMetadata[a].DecodeWith.Decode(data, p)
}
func (a IPProtocol) String() string {
	return IPProtocolMetadata[a].Name
}
func (a SCTPChunkType) Decode(data []byte, p gopacket.PacketBuilder) error {
	return SCTPChunkTypeMetadata[a].DecodeWith.Decode(data, p)
}
func (a SCTPChunkType) String() string {
	return SCTPChunkTypeMetadata[a].Name
}
func (a PPPType) Decode(data []byte, p gopacket.PacketBuilder) error {
	return PPPTypeMetadata[a].DecodeWith.Decode(data, p)
}
func (a PPPType) String() string {
	return PPPTypeMetadata[a].Name
}
func (a LinkType) Decode(data []byte, p gopacket.PacketBuilder) error {
	return LinkTypeMetadata[a].DecodeWith.Decode(data, p)
}
func (a LinkType) String() string {
	return LinkTypeMetadata[a].Name
}
func (a PPPoECode) Decode(data []byte, p gopacket.PacketBuilder) error {
	return PPPoECodeMetadata[a].DecodeWith.Decode(data, p)
}
func (a PPPoECode) String() string {
	return PPPoECodeMetadata[a].Name
}

func init() {
	for i := 0; i < 65536; i++ {
		EthernetTypeMetadata[i] = EnumMetadata{
			DecodeWith: errorFunc(fmt.Sprintf("Unable to decode ethernet type %d", i)),
			Name:       fmt.Sprintf("UnknownEthernetType(%d)", i),
		}
		PPPTypeMetadata[i] = EnumMetadata{
			DecodeWith: errorFunc(fmt.Sprintf("Unable to decode PPP type %d", i)),
			Name:       fmt.Sprintf("UnknownPPPType(%d)", i),
		}
	}
	for i := 0; i < 256; i++ {
		IPProtocolMetadata[i] = EnumMetadata{
			DecodeWith: errorFunc(fmt.Sprintf("Unable to decode IP protocol %d", i)),
			Name:       fmt.Sprintf("UnknownIPProtocol(%d)", i),
		}
		SCTPChunkTypeMetadata[i] = EnumMetadata{
			DecodeWith: errorFunc(fmt.Sprintf("Unable to decode SCTP chunk type %d", i)),
			Name:       fmt.Sprintf("UnknownSCTPChunkType(%d)", i),
		}
		PPPoECodeMetadata[i] = EnumMetadata{
			DecodeWith: errorFunc(fmt.Sprintf("Unable to decode PPPoE code %d", i)),
			Name:       fmt.Sprintf("UnknownPPPoECode(%d)", i),
		}
		LinkTypeMetadata[i] = EnumMetadata{
			DecodeWith: errorFunc(fmt.Sprintf("Unable to decode link type %d", i)),
			Name:       fmt.Sprintf("UnknownLinkType(%d)", i),
		}
	}

	EthernetTypeMetadata[EthernetTypeLLC] = EnumMetadata{DecodeWith: gopacket.DecodeFunc(decodeLLC), Name: "LLC"}
	EthernetTypeMetadata[EthernetTypeIPv4] = EnumMetadata{DecodeWith: gopacket.DecodeFunc(decodeIPv4), Name: "IPv4"}
	EthernetTypeMetadata[EthernetTypeIPv6] = EnumMetadata{DecodeWith: gopacket.DecodeFunc(decodeIPv6), Name: "IPv6"}
	EthernetTypeMetadata[EthernetTypeARP] = EnumMetadata{DecodeWith: gopacket.DecodeFunc(decodeARP), Name: "ARP"}
	EthernetTypeMetadata[EthernetTypeDot1Q] = EnumMetadata{DecodeWith: gopacket.DecodeFunc(decodeDot1Q), Name: "Dot1Q"}
	EthernetTypeMetadata[EthernetTypePPPoEDiscovery] = EnumMetadata{DecodeWith: gopacket.DecodeFunc(decodePPPoE), Name: "PPPoEDiscovery"}
	EthernetTypeMetadata[EthernetTypePPPoESession] = EnumMetadata{DecodeWith: gopacket.DecodeFunc(decodePPPoE), Name: "PPPoESession"}
	EthernetTypeMetadata[EthernetTypeEthernetCTP] = EnumMetadata{DecodeWith: gopacket.DecodeFunc(decodeEthernetCTP), Name: "EthernetCTP"}
	EthernetTypeMetadata[EthernetTypeCiscoDiscovery] = EnumMetadata{DecodeWith: gopacket.DecodeFunc(decodeCiscoDiscovery), Name: "CiscoDiscovery"}
	EthernetTypeMetadata[EthernetTypeMPLSUnicast] = EnumMetadata{DecodeWith: gopacket.DecodeFunc(decodeMPLS), Name: "MPLSUnicast"}
	EthernetTypeMetadata[EthernetTypeMPLSMulticast] = EnumMetadata{DecodeWith: gopacket.DecodeFunc(decodeMPLS), Name: "MPLSMulticast"}

	IPProtocolMetadata[IPProtocolTCP] = EnumMetadata{DecodeWith: gopacket.DecodeFunc(decodeTCP), Name: "TCP"}
	IPProtocolMetadata[IPProtocolUDP] = EnumMetadata{DecodeWith: gopacket.DecodeFunc(decodeUDP), Name: "UDP"}
	IPProtocolMetadata[IPProtocolICMP] = EnumMetadata{DecodeWith: gopacket.DecodeFunc(decodeICMP), Name: "ICMP"}
	IPProtocolMetadata[IPProtocolSCTP] = EnumMetadata{DecodeWith: gopacket.DecodeFunc(decodeSCTP), Name: "SCTP"}
	IPProtocolMetadata[IPProtocolIPv6] = EnumMetadata{DecodeWith: gopacket.DecodeFunc(decodeIPv6), Name: "IPv6"}
	IPProtocolMetadata[IPProtocolIPIP] = EnumMetadata{DecodeWith: gopacket.DecodeFunc(decodeIPv4), Name: "IPv4"}
	IPProtocolMetadata[IPProtocolEtherIP] = EnumMetadata{DecodeWith: gopacket.DecodeFunc(decodeEtherIP), Name: "EtherIP"}
	IPProtocolMetadata[IPProtocolRUDP] = EnumMetadata{DecodeWith: gopacket.DecodeFunc(decodeRUDP), Name: "RUDP"}
	IPProtocolMetadata[IPProtocolGRE] = EnumMetadata{DecodeWith: gopacket.DecodeFunc(decodeGRE), Name: "GRE"}
	IPProtocolMetadata[IPProtocolIPv6HopByHop] = EnumMetadata{DecodeWith: gopacket.DecodeFunc(decodeIPv6HopByHop), Name: "IPv6HopByHop"}
	IPProtocolMetadata[IPProtocolIPv6Routing] = EnumMetadata{DecodeWith: gopacket.DecodeFunc(decodeIPv6Routing), Name: "IPv6Routing"}
	IPProtocolMetadata[IPProtocolIPv6Fragment] = EnumMetadata{DecodeWith: gopacket.DecodeFunc(decodeIPv6Fragment), Name: "IPv6Fragment"}
	IPProtocolMetadata[IPProtocolAH] = EnumMetadata{DecodeWith: gopacket.DecodeFunc(decodeIPSecAH), Name: "IPSecAH"}
	IPProtocolMetadata[IPProtocolESP] = EnumMetadata{DecodeWith: gopacket.DecodeFunc(decodeIPSecESP), Name: "IPSecESP"}
	IPProtocolMetadata[IPProtocolUDPLite] = EnumMetadata{DecodeWith: gopacket.DecodeFunc(decodeUDPLite), Name: "UDPLite"}
	IPProtocolMetadata[IPProtocolMPLSInIP] = EnumMetadata{DecodeWith: gopacket.DecodeFunc(decodeMPLS), Name: "MPLS"}
	IPProtocolMetadata[IPProtocolNoNextHeader] = EnumMetadata{DecodeWith: errorFunc("NoNextHeader with non-zero byte payload"), Name: "NoNextHeader"}

	SCTPChunkTypeMetadata[SCTPChunkTypeData] = EnumMetadata{DecodeWith: gopacket.DecodeFunc(decodeSCTPData), Name: "Data"}
	SCTPChunkTypeMetadata[SCTPChunkTypeInit] = EnumMetadata{DecodeWith: gopacket.DecodeFunc(decodeSCTPInit), Name: "Init"}
	SCTPChunkTypeMetadata[SCTPChunkTypeInitAck] = EnumMetadata{DecodeWith: gopacket.DecodeFunc(decodeSCTPInit), Name: "InitAck"}
	SCTPChunkTypeMetadata[SCTPChunkTypeSack] = EnumMetadata{DecodeWith: gopacket.DecodeFunc(decodeSCTPSack), Name: "Sack"}
	SCTPChunkTypeMetadata[SCTPChunkTypeHeartbeat] = EnumMetadata{DecodeWith: gopacket.DecodeFunc(decodeSCTPHeartbeat), Name: "Heartbeat"}
	SCTPChunkTypeMetadata[SCTPChunkTypeHeartbeatAck] = EnumMetadata{DecodeWith: gopacket.DecodeFunc(decodeSCTPHeartbeat), Name: "HeartbeatAck"}
	SCTPChunkTypeMetadata[SCTPChunkTypeAbort] = EnumMetadata{DecodeWith: gopacket.DecodeFunc(decodeSCTPError), Name: "Abort"}
	SCTPChunkTypeMetadata[SCTPChunkTypeError] = EnumMetadata{DecodeWith: gopacket.DecodeFunc(decodeSCTPError), Name: "Error"}
	SCTPChunkTypeMetadata[SCTPChunkTypeShutdown] = EnumMetadata{DecodeWith: gopacket.DecodeFunc(decodeSCTPShutdown), Name: "Shutdown"}
	SCTPChunkTypeMetadata[SCTPChunkTypeShutdownAck] = EnumMetadata{DecodeWith: gopacket.DecodeFunc(decodeSCTPShutdownAck), Name: "ShutdownAck"}
	SCTPChunkTypeMetadata[SCTPChunkTypeCookieEcho] = EnumMetadata{DecodeWith: gopacket.DecodeFunc(decodeSCTPCookieEcho), Name: "CookieEcho"}
	SCTPChunkTypeMetadata[SCTPChunkTypeCookieAck] = EnumMetadata{DecodeWith: gopacket.DecodeFunc(decodeSCTPEmptyLayer), Name: "CookieAck"}
	SCTPChunkTypeMetadata[SCTPChunkTypeShutdownComplete] = EnumMetadata{DecodeWith: gopacket.DecodeFunc(decodeSCTPEmptyLayer), Name: "ShutdownComplete"}

	PPPTypeMetadata[PPPTypeIPv4] = EnumMetadata{DecodeWith: gopacket.DecodeFunc(decodeIPv4), Name: "IPv4"}
	PPPTypeMetadata[PPPTypeIPv6] = EnumMetadata{DecodeWith: gopacket.DecodeFunc(decodeIPv6), Name: "IPv6"}

	PPPoECodeMetadata[PPPoECodeSession] = EnumMetadata{DecodeWith: gopacket.DecodeFunc(decodePPP), Name: "PPP"}

	LinkTypeMetadata[LinkTypeEthernet] = EnumMetadata{DecodeWith: gopacket.DecodeFunc(decodeEthernet), Name: "Ethernet"}
	LinkTypeMetadata[LinkTypePPP] = EnumMetadata{DecodeWith: gopacket.DecodeFunc(decodePPP), Name: "PPP"}
}