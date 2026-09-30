// Copyright 2022 The gVisor Authors.
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

package tcp

import (
	"bytes"
	"context"
	"os"
	"testing"
	"time"

	"gvisor.dev/gvisor/pkg/refs"
	"gvisor.dev/gvisor/pkg/state"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/faketime"
	"gvisor.dev/gvisor/pkg/tcpip/header"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv4"
	"gvisor.dev/gvisor/pkg/tcpip/ports"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
	"gvisor.dev/gvisor/pkg/waiter"
)

func TestMain(m *testing.M) {
	refs.SetLeakMode(refs.LeaksPanic)
	code := m.Run()
	refs.DoLeakCheck()
	os.Exit(code)
}

func TestRestoreSenderGSO(t *testing.T) {
	for _, mode := range []stack.GSOType{stack.GSONone, stack.GSOGvisor, stack.GSOTCPv4, stack.GSOTCPv6} {
		ep := &Endpoint{gso: stack.GSO{Type: mode}}
		s := &sender{ep: ep, TCPSenderState: TCPSenderState{MaxPayloadSize: 1400}}
		s.ep.mu.Lock()
		s.restoreGSO()
		s.ep.mu.Unlock()
		if got, want := s.gso, mode != stack.GSONone; got != want {
			t.Errorf("mode %v: sender GSO = %v, want %v", mode, got, want)
		}
		if mode != stack.GSONone && ep.gso.MSS != 1400 {
			t.Errorf("mode %v: MSS = %d, want 1400", mode, ep.gso.MSS)
		}
	}
}

// Changing either key after restore invalidates sequence/timestamp continuity
// for fresh connections that reuse tuples retained in the peer's TIME_WAIT.
func TestProtocolSecretsSurviveCheckpoint(t *testing.T) {
	originalStack := stack.New(stack.Options{TransportProtocols: []stack.TransportProtocolFactory{NewProtocol}})
	defer originalStack.Destroy()
	p := originalStack.TransportProtocolInstance(ProtocolNumber).(*protocol)
	for i := range p.seqnumSecret {
		p.seqnumSecret[i] = byte(i + 1)
		p.tsOffsetSecret[i] = byte(i + 33)
	}
	var buf bytes.Buffer
	if _, err := state.Save(context.Background(), &buf, originalStack); err != nil {
		t.Fatal(err)
	}
	restoredStack := stack.New(stack.Options{TransportProtocols: []stack.TransportProtocolFactory{NewProtocol}})
	defer restoredStack.Destroy()
	if _, err := state.Load(context.Background(), bytes.NewReader(buf.Bytes()), restoredStack); err != nil {
		t.Fatal(err)
	}
	restored := restoredStack.TransportProtocolInstance(ProtocolNumber).(*protocol)
	if restored.seqnumSecret != p.seqnumSecret {
		t.Error("ISN key changed across checkpoint")
	}
	if restored.tsOffsetSecret != p.tsOffsetSecret {
		t.Error("timestamp key changed across checkpoint")
	}
}

func TestTimeWaitRestorePreservesDeadline(t *testing.T) {
	clock := faketime.NewManualClock()
	s := stack.New(stack.Options{Clock: clock, TransportProtocols: []stack.TransportProtocolFactory{NewProtocol}})
	defer s.Destroy()
	ep := newEndpoint(s, s.TransportProtocolInstance(ProtocolNumber).(*protocol), header.IPv4ProtocolNumber, &waiter.Queue{})
	ep.mu.Lock()
	ep.setEndpointState(StateTimeWait)
	startTimeWait(ep)
	ep.mu.Unlock()
	// Each reload loses the host timer, but must keep the saved deadline.
	for i := 0; i < 2; i++ {
		clock.Advance(20 * time.Second)
		ep.mu.Lock()
		ep.timeWaitTimer.Stop()
		ep.restoreTimeWaitTimer()
		ep.mu.Unlock()
	}
	clock.Advance(19 * time.Second)
	if got := ep.EndpointState(); got != StateTimeWait {
		t.Fatalf("expired early: %v", got)
	}
	clock.Advance(time.Second)
	if got := ep.EndpointState(); got != StateClose {
		t.Fatalf("reload extended TIME_WAIT: got %v, want %v", got, StateClose)
	}
}

func TestTimeWaitDoesNotExpireWhileStackPaused(t *testing.T) {
	clock := faketime.NewManualClock()
	s := stack.New(stack.Options{Clock: clock, NetworkProtocols: []stack.NetworkProtocolFactory{ipv4.NewProtocol}, TransportProtocols: []stack.TransportProtocolFactory{NewProtocol}})
	defer s.Destroy()
	ep := newEndpoint(s, s.TransportProtocolInstance(ProtocolNumber).(*protocol), header.IPv4ProtocolNumber, &waiter.Queue{})
	ep.ID = stack.TransportEndpointID{LocalPort: 1234}
	if err := s.RegisterTransportEndpoint([]tcpip.NetworkProtocolNumber{header.IPv4ProtocolNumber}, ProtocolNumber, ep.ID, ep, ports.Flags{}, 0); err != nil {
		t.Fatal(err)
	}
	ep.mu.Lock()
	ep.setEndpointState(StateTimeWait)
	startTimeWait(ep)
	ep.mu.Unlock()
	ep.protocol.Pause()
	clock.Advance(60 * time.Second)
	// Simulate a callback already queued when Stop was called as well.
	ep.timeWaitTimerExpired()
	if got := ep.EndpointState(); got != StateTimeWait {
		ep.protocol.Resume()
		t.Fatalf("TIME_WAIT expired during snapshot pause: %v", got)
	}
	ep.protocol.Resume()
	clock.Advance(0)
	if got := ep.EndpointState(); got != StateClose {
		t.Fatalf("TIME_WAIT did not expire after resume: %v", got)
	}
}
