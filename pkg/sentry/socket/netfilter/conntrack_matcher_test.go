// Copyright 2026 The gVisor Authors.
// SPDX-License-Identifier: Apache-2.0

package netfilter

import (
	"bytes"
	"context"
	"testing"

	"gvisor.dev/gvisor/pkg/abi/linux"
	"gvisor.dev/gvisor/pkg/marshal"
	"gvisor.dev/gvisor/pkg/state"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
)

func TestConntrackMatcherABI(t *testing.T) {
	info := linux.XTConntrackMtinfo3{MatchFlags: linux.XT_CONNTRACK_STATE | linux.XT_CONNTRACK_DIRECTION, InvertFlags: linux.XT_CONNTRACK_DIRECTION, StateMask: linux.XT_CONNTRACK_STATE_ESTABLISHED | linux.XT_CONNTRACK_STATE_RELATED}
	buf := marshalEntryMatch(matcherNameConntrack, marshal.Marshal(&info))
	var entry linux.XTEntryMatch
	entry.UnmarshalBytes(buf)
	entry.Revision = 3
	entry.MarshalBytes(buf)
	m, err := parseMatchers(nil, emptyIPv4Filter, buf)
	if err != nil {
		t.Fatal(err)
	}
	if out := marshalMatcher(m[0]); !bytes.Equal(out, buf) {
		t.Fatal("conntrack ABI round trip changed")
	}
	for _, rev := range []uint8{0, 1, 2, 4} {
		entry.Revision = rev
		entry.MarshalBytes(buf)
		if _, err := parseMatchers(nil, emptyIPv4Filter, buf); err == nil {
			t.Errorf("accepted unsupported revision %d", rev)
		}
	}
	for _, flags := range []uint16{linux.XT_CONNTRACK_PROTO, linux.XT_CONNTRACK_STATUS, linux.XT_CONNTRACK_EXPIRES, linux.XT_CONNTRACK_ORIGSRC_PORT} {
		info.MatchFlags = flags
		if _, err := (conntrackMarshaler{}).unmarshal(nil, marshal.Marshal(&info), emptyIPv4Filter); err == nil {
			t.Errorf("silently ignored predicate %#x", flags)
		}
	}
	info.MatchFlags = linux.XT_CONNTRACK_STATE
	info.StateMask = linux.XT_CONNTRACK_STATE_UNTRACKED
	if _, err := (conntrackMarshaler{}).unmarshal(nil, marshal.Marshal(&info), emptyIPv4Filter); err == nil {
		t.Fatal("accepted unsupported untracked state")
	}
}
func TestConntrackInvalidState(t *testing.T) {
	p := stack.NewPacketBuffer(stack.PacketBufferOptions{})
	defer p.DecRef()
	c := ConntrackMatcher{info: linux.XTConntrackMtinfo3{MatchFlags: linux.XT_CONNTRACK_STATE, StateMask: linux.XT_CONNTRACK_STATE_INVALID}}
	if match, drop := c.Match(stack.Forward, p, "", ""); !match || drop {
		t.Fatal("unassociated packet must match INVALID")
	}
	c.info.InvertFlags = linux.XT_CONNTRACK_STATE
	if match, _ := c.Match(stack.Forward, p, "", ""); match {
		t.Fatal("INVALID inversion failed")
	}
	c.info.InvertFlags = 0
	c.info.StateMask = linux.XT_CONNTRACK_STATE_ESTABLISHED | linux.XT_CONNTRACK_STATE_RELATED
	if match, _ := c.Match(stack.Forward, p, "", ""); match {
		t.Fatal("unassociated packet passed Docker conntrack rule")
	}
}

func TestConntrackMatcherSaveRestore(t *testing.T) {
	original := &ConntrackMatcher{info: linux.XTConntrackMtinfo3{MatchFlags: linux.XT_CONNTRACK_STATE, InvertFlags: linux.XT_CONNTRACK_STATE, StateMask: linux.XT_CONNTRACK_STATE_INVALID}}
	var image bytes.Buffer
	if _, err := state.Save(context.Background(), &image, &original); err != nil {
		t.Fatal(err)
	}
	var restored *ConntrackMatcher
	if _, err := state.Load(context.Background(), &image, &restored); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(marshalMatcher(original), marshalMatcher(restored)) {
		t.Fatal("matcher ABI changed after restore")
	}
	pkt := stack.NewPacketBuffer(stack.PacketBufferOptions{})
	defer pkt.DecRef()
	if match, _ := restored.Match(stack.Forward, pkt, "", ""); match {
		t.Fatal("restored inversion lost")
	}
}
