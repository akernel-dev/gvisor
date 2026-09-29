// Copyright 2026 The gVisor Authors.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package stack

import (
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/header"
	"testing"
)

type nilEndpointQueue struct{ called bool }

func (q *nilEndpointQueue) QueuePacket(TransportEndpoint, TransportEndpointID, *PacketBuffer) {
	q.called = true
}

func TestDemuxDoesNotQueueMissingEndpoint(t *testing.T) {
	queue := &nilEndpointQueue{}
	key := protocolIDs{header.IPv4ProtocolNumber, header.TCPProtocolNumber}
	ep := &multiPortEndpoint{
		demux:      &transportDemuxer{queuedProtocols: map[protocolIDs]queuedTransportProtocol{key: queue}},
		netProto:   header.IPv4ProtocolNumber,
		transProto: header.TCPProtocolNumber,
		endpoints:  []TransportEndpoint{nil},
	}
	byNIC := &endpointsByNIC{endpoints: map[tcpip.NICID]*multiPortEndpoint{0: ep}}
	pkt := NewPacketBuffer(PacketBufferOptions{})
	defer pkt.DecRef()
	id := TransportEndpointID{LocalAddress: tcpip.AddrFrom4([4]byte{127, 0, 0, 1})}
	if got := byNIC.handlePacket(id, pkt); got || queue.called {
		t.Fatalf("missing endpoint delivered: handled=%t queued=%t", got, queue.called)
	}
}
