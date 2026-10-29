// Copyright 2026 The gVisor Authors.
// SPDX-License-Identifier: Apache-2.0

package netfilter

import (
	"fmt"

	"gvisor.dev/gvisor/pkg/abi/linux"
	"gvisor.dev/gvisor/pkg/marshal"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/header"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
)

const matcherNameAddrtype = "addrtype"

func init() {
	registerMatchMaker(addrtypeMarshaler{rev: 0})
	registerMatchMaker(addrtypeMarshaler{rev: 1})
}

type addrtypeMarshaler struct{ rev uint8 }

func (addrtypeMarshaler) name() string       { return matcherNameAddrtype }
func (am addrtypeMarshaler) revision() uint8 { return am.rev }
func (am addrtypeMarshaler) marshal(m matcher) []byte {
	a := m.(*AddrtypeMatcher)
	var data []byte
	if am.rev == 0 {
		info := linux.XTAddrtypeInfo{Source: a.source, Dest: a.dest, InvertSource: a.invertSource, InvertDest: a.invertDest}
		data = marshal.Marshal(&info)
	} else {
		info := linux.XTAddrtypeInfoV1{Source: a.source, Dest: a.dest, Flags: a.flags}
		data = marshal.Marshal(&info)
	}
	buf := marshalEntryMatch(matcherNameAddrtype, data)
	var entry linux.XTEntryMatch
	entry.UnmarshalBytes(buf)
	entry.Revision = am.rev
	entry.MarshalBytes(buf)
	return buf
}
func (am addrtypeMarshaler) unmarshal(_ IDMapper, buf []byte, filter stack.IPHeaderFilter) (stack.Matcher, error) {
	// This extension currently implements the IPv4 local routing table used
	// by inet_dev_addr_type. IPv6 has different route lookup semantics.
	if filter.NetworkProtocol() != header.IPv4ProtocolNumber {
		return nil, fmt.Errorf("legacy addrtype supports IPv4 only")
	}
	a := &AddrtypeMatcher{rev: am.rev}
	switch am.rev {
	case 0:
		var info linux.XTAddrtypeInfo
		if len(buf) != 16 {
			return nil, fmt.Errorf("invalid aligned addrtype revision 0 size: %d", len(buf))
		}
		info.UnmarshalUnsafe(buf)
		a.source, a.dest = info.Source, info.Dest
		a.invertSource, a.invertDest = info.InvertSource, info.InvertDest
	case 1:
		var info linux.XTAddrtypeInfoV1
		if len(buf) != info.SizeBytes() {
			return nil, fmt.Errorf("invalid addrtype revision 1 size: %d", len(buf))
		}
		info.UnmarshalUnsafe(buf)
		a.source, a.dest, a.flags = info.Source, info.Dest, info.Flags
		if info.Flags&linux.XT_ADDRTYPE_LIMIT_IFACE_IN != 0 && info.Flags&linux.XT_ADDRTYPE_LIMIT_IFACE_OUT != 0 {
			return nil, fmt.Errorf("addrtype cannot limit both input and output interfaces")
		}
		if info.Flags&linux.XT_ADDRTYPE_INVERT_SOURCE != 0 {
			a.invertSource = 1
		}
		if info.Flags&linux.XT_ADDRTYPE_INVERT_DEST != 0 {
			a.invertDest = 1
		}
	default:
		return nil, fmt.Errorf("unsupported addrtype revision %d", am.rev)
	}
	return a, nil
}

// AddrtypeMatcher implements the legacy IPv4 addrtype revisions 0 and 1.
// The stack is the network namespace that owns the table, not the namespace
// of the process which installed it. It is serialized with the rules.
// +stateify savable
type AddrtypeMatcher struct {
	stack        *stack.Stack
	rev          uint8
	source       uint16
	dest         uint16
	flags        uint32
	invertSource uint32
	invertDest   uint32
}

func (*AddrtypeMatcher) name() string      { return matcherNameAddrtype }
func (a *AddrtypeMatcher) revision() uint8 { return a.rev }
func (a *AddrtypeMatcher) supportsHook(hook stack.Hook) bool {
	if a.flags&linux.XT_ADDRTYPE_LIMIT_IFACE_IN != 0 && (hook == stack.Output || hook == stack.Postrouting) {
		return false
	}
	if a.flags&linux.XT_ADDRTYPE_LIMIT_IFACE_OUT != 0 && (hook == stack.Prerouting || hook == stack.Input) {
		return false
	}
	return true
}
func (a *AddrtypeMatcher) addressType(addr tcpip.Address, iface string) uint16 {
	// Linux's IPv4 addrtype consults the local table, not the main routing
	// table. An ordinary nonlocal address remains UNICAST without a route.
	if addr.As4()[0] == 0 || addr == header.IPv4Broadcast {
		return linux.XT_ADDRTYPE_BROADCAST
	}
	if header.IsV4MulticastAddress(addr) {
		return linux.XT_ADDRTYPE_MULTICAST
	}
	local, broadcast := a.stack.ClassifyLocalIPv4Address(addr, iface)
	if local {
		return linux.XT_ADDRTYPE_LOCAL
	}
	if broadcast {
		return linux.XT_ADDRTYPE_BROADCAST
	}
	return linux.XT_ADDRTYPE_UNICAST
}

// Match implements stack.Matcher.Match.
func (a *AddrtypeMatcher) Match(hook stack.Hook, pkt *stack.PacketBuffer, input, output string) (bool, bool) {
	if pkt.NetworkProtocolNumber != header.IPv4ProtocolNumber || len(pkt.NetworkHeader().Slice()) < header.IPv4MinimumSize || a.stack == nil {
		return false, true
	}
	var iface string
	if a.flags&linux.XT_ADDRTYPE_LIMIT_IFACE_IN != 0 {
		iface = input
	}
	if a.flags&linux.XT_ADDRTYPE_LIMIT_IFACE_OUT != 0 {
		iface = output
	}
	iph := header.IPv4(pkt.NetworkHeader().Slice())
	// Revision 0 used a uint32 XOR rather than a boolean inversion. Preserve
	// those ABI semantics even for callers passing values other than 0 or 1.
	matches := func(addr tcpip.Address, mask uint16, invert uint32) bool {
		if mask == 0 {
			return true
		}
		var value uint32
		if a.addressType(addr, iface)&mask != 0 {
			value = 1
		}
		return value^invert != 0
	}
	return matches(iph.SourceAddress(), a.source, a.invertSource) && matches(iph.DestinationAddress(), a.dest, a.invertDest), false
}
