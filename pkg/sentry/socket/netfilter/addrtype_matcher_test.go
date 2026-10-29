// Copyright 2026 The gVisor Authors.
// SPDX-License-Identifier: Apache-2.0

package netfilter

import (
	"bytes"
	"fmt"
	"testing"

	"gvisor.dev/gvisor/pkg/abi/linux"
	"gvisor.dev/gvisor/pkg/marshal"
	"gvisor.dev/gvisor/pkg/syserr"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/header"
	"gvisor.dev/gvisor/pkg/tcpip/link/channel"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv4"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
)

func TestAddrtypeABI(t *testing.T) {
	for _, rev := range []uint8{0, 1} {
		t.Run(fmt.Sprint(rev), func(t *testing.T) {
			var data []byte
			if rev == 0 {
				info := linux.XTAddrtypeInfo{Source: linux.XT_ADDRTYPE_UNICAST, Dest: linux.XT_ADDRTYPE_LOCAL, InvertSource: 0, InvertDest: 1}
				data = marshal.Marshal(&info)
			} else {
				info := linux.XTAddrtypeInfoV1{Source: linux.XT_ADDRTYPE_UNICAST, Dest: linux.XT_ADDRTYPE_LOCAL, Flags: linux.XT_ADDRTYPE_INVERT_DEST | linux.XT_ADDRTYPE_LIMIT_IFACE_IN}
				data = marshal.Marshal(&info)
			}
			buf := marshalEntryMatch(matcherNameAddrtype, data)
			var entry linux.XTEntryMatch
			entry.UnmarshalBytes(buf)
			entry.Revision = rev
			entry.MarshalBytes(buf)
			parsed, err := parseMatchers(nil, emptyIPv4Filter, buf)
			if err != nil {
				t.Fatal(err)
			}
			got := parsed[0].(*AddrtypeMatcher)
			if got.rev != rev || got.invertSource != 0 || got.invertDest != 1 {
				t.Fatalf("wrong revision/inversion: %+v", got)
			}
			if output := marshalMatcher(got); !bytes.Equal(output, buf) {
				t.Fatalf("ABI round trip changed: %x != %x", output, buf)
			}
			entry.Revision = 2
			entry.MarshalBytes(buf)
			if _, err := parseMatchers(nil, emptyIPv4Filter, buf); err == nil {
				t.Fatal("accepted unknown revision")
			}
		})
	}
}

func TestAddrtypeInvalidABI(t *testing.T) {
	for _, rev := range []uint8{0, 1} {
		m := addrtypeMarshaler{rev: rev}
		for _, length := range []int{0, 4, 7, 9, 17} {
			if _, err := m.unmarshal(nil, make([]byte, length), emptyIPv4Filter); err == nil {
				t.Errorf("rev %d accepted %d bytes", rev, length)
			}
		}
		if _, err := m.unmarshal(nil, make([]byte, 16), emptyIPv6Filter); err == nil {
			t.Error("accepted IPv6")
		}
	}
	info := linux.XTAddrtypeInfoV1{Flags: linux.XT_ADDRTYPE_LIMIT_IFACE_IN | linux.XT_ADDRTYPE_LIMIT_IFACE_OUT}
	if _, err := (addrtypeMarshaler{rev: 1}).unmarshal(nil, marshal.Marshal(&info), emptyIPv4Filter); err == nil {
		t.Fatal("accepted both interface limits")
	}
}

func addrtypeStack(t *testing.T, local tcpip.Address) *stack.Stack {
	t.Helper()
	s := stack.New(stack.Options{NetworkProtocols: []stack.NetworkProtocolFactory{ipv4.NewProtocol}})
	t.Cleanup(s.Destroy)
	for id := tcpip.NICID(1); id <= 2; id++ {
		if err := s.CreateNICWithOptions(id, channel.New(1, 1500, ""), stack.NICOptions{Name: fmt.Sprintf("eth%d", id)}); err != nil {
			t.Fatal(err)
		}
	}
	if err := s.AddProtocolAddress(1, tcpip.ProtocolAddress{Protocol: header.IPv4ProtocolNumber, AddressWithPrefix: tcpip.AddressWithPrefix{Address: local, PrefixLen: 24}}, stack.AddressProperties{}); err != nil {
		t.Fatal(err)
	}
	// Spoofing must not make remote addresses look LOCAL to the matcher.
	if err := s.SetSpoofing(2, true); err != nil {
		t.Fatal(err)
	}
	return s
}
func addrtypePacket(src, dst tcpip.Address) *stack.PacketBuffer {
	p := stack.NewPacketBuffer(stack.PacketBufferOptions{ReserveHeaderBytes: header.IPv4MinimumSize})
	p.NetworkProtocolNumber = header.IPv4ProtocolNumber
	header.IPv4(p.NetworkHeader().Push(header.IPv4MinimumSize)).Encode(&header.IPv4Fields{TotalLength: header.IPv4MinimumSize, SrcAddr: src, DstAddr: dst, TTL: 64})
	return p
}
func TestAddrtypeNamespaceAndAddressClasses(t *testing.T) {
	local := tcpip.AddrFrom4([4]byte{192, 0, 2, 1})
	s := addrtypeStack(t, local)
	other := addrtypeStack(t, tcpip.AddrFrom4([4]byte{198, 51, 100, 1}))
	for _, test := range []struct {
		addr [4]byte
		kind uint16
	}{
		{[4]byte{192, 0, 2, 1}, linux.XT_ADDRTYPE_LOCAL},
		{[4]byte{192, 0, 2, 99}, linux.XT_ADDRTYPE_UNICAST},
		{[4]byte{198, 51, 100, 1}, linux.XT_ADDRTYPE_UNICAST},
		{[4]byte{192, 0, 2, 255}, linux.XT_ADDRTYPE_BROADCAST},
		{[4]byte{192, 0, 2, 0}, linux.XT_ADDRTYPE_UNICAST},
		{[4]byte{0, 1, 2, 3}, linux.XT_ADDRTYPE_BROADCAST},
		{[4]byte{255, 255, 255, 255}, linux.XT_ADDRTYPE_BROADCAST},
		{[4]byte{224, 0, 0, 1}, linux.XT_ADDRTYPE_MULTICAST},
	} {
		a := tcpip.AddrFrom4(test.addr)
		t.Run(a.String(), func(t *testing.T) {
			m := AddrtypeMatcher{stack: s, source: linux.XT_ADDRTYPE_LOCAL, dest: test.kind}
			p := addrtypePacket(local, a)
			defer p.DecRef()
			if match, hotdrop := m.Match(stack.Output, p, "", "eth1"); !match || hotdrop {
				t.Fatalf("Match = %t,%t", match, hotdrop)
			}
			m.invertDest = 1
			if match, _ := m.Match(stack.Output, p, "", "eth1"); match {
				t.Fatal("inversion did not negate match")
			}
		})
	}
	p := addrtypePacket(local, local)
	defer p.DecRef()
	for _, limit := range []uint32{linux.XT_ADDRTYPE_LIMIT_IFACE_IN, linux.XT_ADDRTYPE_LIMIT_IFACE_OUT} {
		m := AddrtypeMatcher{stack: s, dest: linux.XT_ADDRTYPE_LOCAL, flags: limit}
		if match, _ := m.Match(stack.Forward, p, "eth1", "eth1"); !match {
			t.Fatal("failed scoped LOCAL")
		}
		if match, _ := m.Match(stack.Forward, p, "eth2", "eth2"); match {
			t.Fatal("matched LOCAL on wrong interface")
		}
	}
	m := AddrtypeMatcher{stack: other, dest: linux.XT_ADDRTYPE_LOCAL}
	if match, _ := m.Match(stack.Output, p, "", "eth1"); match {
		t.Fatal("leaked another namespace's LOCAL address")
	}
	if err := s.RemoveAddress(1, local); err != nil {
		t.Fatal(err)
	}
	m.stack = s
	if match, _ := m.Match(stack.Output, p, "", "eth1"); match {
		t.Fatal("cached removed address")
	}
}

// A subnet's lowest address is ordinary unicast until explicitly assigned.
func TestAddrtypeAssignedSubnetLowestAddress(t *testing.T) {
	addr := tcpip.AddrFrom4([4]byte{192, 0, 2, 0})
	s := addrtypeStack(t, addr)
	p := addrtypePacket(addr, addr)
	defer p.DecRef()
	m := AddrtypeMatcher{stack: s, source: linux.XT_ADDRTYPE_LOCAL, dest: linux.XT_ADDRTYPE_LOCAL}
	if match, hotdrop := m.Match(stack.Output, p, "", "eth1"); !match || hotdrop {
		t.Fatalf("assigned lowest address: Match = %t,%t", match, hotdrop)
	}
}

func TestAddrtypeTableBindingAndHooks(t *testing.T) {
	for _, flags := range []uint32{0, linux.XT_ADDRTYPE_LIMIT_IFACE_IN, linux.XT_ADDRTYPE_LIMIT_IFACE_OUT} {
		for _, hook := range []stack.Hook{stack.Prerouting, stack.Input, stack.Output, stack.Postrouting} {
			t.Run(fmt.Sprintf("flags=%d/hook=%d", flags, hook), func(t *testing.T) {
				accept := &acceptTarget{AcceptTarget: stack.AcceptTarget{NetworkProtocol: header.IPv4ProtocolNumber}}
				table := stack.Table{BuiltinChains: makeHookEntries(map[stack.Hook]int{}), Underflows: makeHookEntries(map[stack.Hook]int{})}
				index := -1
				for _, h := range []stack.Hook{stack.Prerouting, stack.Input, stack.Output, stack.Postrouting} {
					table.BuiltinChains[h] = len(table.Rules)
					if h == hook {
						index = len(table.Rules)
						rule := makeRule(accept)
						rule.Matchers = []stack.Matcher{&AddrtypeMatcher{rev: 1, dest: linux.XT_ADDRTYPE_LOCAL, flags: flags}}
						table.Rules = append(table.Rules, rule)
					}
					table.Underflows[h] = len(table.Rules)
					table.Rules = append(table.Rules, makeRule(accept))
				}
				s := addrtypeStack(t, tcpip.AddrFrom4([4]byte{192, 0, 2, 1}))
				err := SetEntries(nil, s, marshalReplace(table, natTable, false), false)
				invalid := flags == linux.XT_ADDRTYPE_LIMIT_IFACE_IN && (hook == stack.Output || hook == stack.Postrouting) || flags == linux.XT_ADDRTYPE_LIMIT_IFACE_OUT && (hook == stack.Prerouting || hook == stack.Input)
				if invalid {
					if err != syserr.ErrInvalidArgument {
						t.Fatalf("invalid hook: %v", err)
					}
					return
				}
				if err != nil {
					t.Fatal(err)
				}
				got := s.IPTables().GetTable(stack.NATID, false).Rules[index].Matchers[0].(*AddrtypeMatcher)
				if got.stack != s {
					t.Fatal("matcher not bound to owning network stack")
				}
			})
		}
	}
}
