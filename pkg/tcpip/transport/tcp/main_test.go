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
	"os"
	"testing"

	"gvisor.dev/gvisor/pkg/refs"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
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
