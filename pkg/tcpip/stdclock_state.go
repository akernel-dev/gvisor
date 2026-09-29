// Copyright 2021 The gVisor Authors.
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

package tcpip

import (
	"context"
	"time"
)

// saveMonotonicOffset snapshots elapsed time without changing the live clock.
// Changing the offset while keeping baseTime would count elapsed time twice
// when the original sandbox resumes after a checkpoint.
func (s *stdClock) saveMonotonicOffset() MonotonicTime {
	return s.NowMonotonic()
}

func (s *stdClock) loadMonotonicOffset(_ context.Context, offset MonotonicTime) {
	s.monotonicOffset = offset
}

// afterLoad is invoked by stateify.
func (s *stdClock) afterLoad(context.Context) {
	s.baseTime = time.Now()
}
