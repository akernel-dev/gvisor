// Copyright 2026 The gVisor Authors.
// SPDX-License-Identifier: Apache-2.0

package netfilter

import (
	"context"
	"fmt"

	"gvisor.dev/gvisor/pkg/abi/linux"
	"gvisor.dev/gvisor/pkg/marshal"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
)

const matcherNameConntrack = "conntrack"
const conntrackMatchRevision = 3

func init() { registerMatchMaker(conntrackMarshaler{}) }

type conntrackMarshaler struct{}

func (conntrackMarshaler) name() string    { return matcherNameConntrack }
func (conntrackMarshaler) revision() uint8 { return conntrackMatchRevision }
func (conntrackMarshaler) marshal(m matcher) []byte {
	c := m.(*ConntrackMatcher)
	buf := marshalEntryMatch(matcherNameConntrack, marshal.Marshal(&c.info))
	var entry linux.XTEntryMatch
	entry.UnmarshalBytes(buf)
	entry.Revision = conntrackMatchRevision
	entry.MarshalBytes(buf)
	return buf
}
func (conntrackMarshaler) unmarshal(_ IDMapper, buf []byte, _ stack.IPHeaderFilter) (stack.Matcher, error) {
	var info linux.XTConntrackMtinfo3
	if len(buf) != (info.SizeBytes()+7)&^7 {
		return nil, fmt.Errorf("invalid conntrack revision 3 size: %d", len(buf))
	}
	info.UnmarshalBytes(buf)
	supported := uint16(linux.XT_CONNTRACK_STATE | linux.XT_CONNTRACK_DIRECTION)
	if info.MatchFlags & ^supported != 0 || info.InvertFlags & ^supported != 0 {
		return nil, fmt.Errorf("legacy conntrack supports state and direction matching only")
	}
	states := uint16(linux.XT_CONNTRACK_STATE_INVALID | linux.XT_CONNTRACK_STATE_NEW | linux.XT_CONNTRACK_STATE_ESTABLISHED | linux.XT_CONNTRACK_STATE_RELATED)
	if info.MatchFlags&linux.XT_CONNTRACK_STATE != 0 && info.StateMask & ^states != 0 {
		return nil, fmt.Errorf("unsupported legacy conntrack state mask: %#x", info.StateMask)
	}
	return &ConntrackMatcher{info: info}, nil
}

// ConntrackMatcher supports revision 3 state and direction matches. Unsupported
// tuple, status, expiry and untracked/NAT-state predicates are rejected at install.
// +stateify savable
type ConntrackMatcher struct {
	info linux.XTConntrackMtinfo3 `state:".([]byte)"`
}

func (*ConntrackMatcher) name() string    { return matcherNameConntrack }
func (*ConntrackMatcher) revision() uint8 { return conntrackMatchRevision }
func (c *ConntrackMatcher) Match(_ stack.Hook, pkt *stack.PacketBuffer, _, _ string) (bool, bool) {
	info := &c.info
	state := pkt.ConnectionTrackingState()
	if info.MatchFlags&linux.XT_CONNTRACK_STATE != 0 {
		bit := uint16(linux.XT_CONNTRACK_STATE_INVALID)
		switch state {
		case stack.ConnTrackStateNew:
			bit = linux.XT_CONNTRACK_STATE_NEW
		case stack.ConnTrackStateEstablished, stack.ConnTrackStateEstablishedReply:
			bit = linux.XT_CONNTRACK_STATE_ESTABLISHED
		case stack.ConnTrackStateRelated:
			bit = linux.XT_CONNTRACK_STATE_RELATED
		}
		matches := info.StateMask&bit != 0
		if matches == (info.InvertFlags&linux.XT_CONNTRACK_STATE != 0) {
			return false, false
		}
	}
	if !pkt.IsConnTrackConfigured() {
		return info.MatchFlags&linux.XT_CONNTRACK_STATE != 0, false
	}
	if info.MatchFlags&linux.XT_CONNTRACK_DIRECTION != 0 {
		original := !pkt.IsReplyPacket()
		if original == (info.InvertFlags&linux.XT_CONNTRACK_DIRECTION != 0) {
			return false, false
		}
	}
	return true, false
}

// saveInfo is invoked by stateify. ABI structures are marshaled explicitly;
// they do not implement the checkpoint serializer's SaverLoader interface.
func (c *ConntrackMatcher) saveInfo() []byte { return marshal.Marshal(&c.info) }

// loadInfo is invoked by stateify.
func (c *ConntrackMatcher) loadInfo(_ context.Context, data []byte) { c.info.UnmarshalBytes(data) }
