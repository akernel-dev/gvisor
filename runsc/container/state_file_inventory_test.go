// Copyright 2026 The gVisor Authors.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     https://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package container

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
)

func TestStateFileAtomicReaders(t *testing.T) {
	dir := t.TempDir()
	id := FullID{ContainerID: "container", SandboxID: "sandbox"}
	writer := StateFile{RootDir: dir, ID: id}
	if err := writer.LockForNew(); err != nil {
		t.Fatal(err)
	}
	defer writer.close()
	defer writer.UnlockOrDie()
	type record struct {
		Generation int
		Payload    string
	}
	value := func(i int) record { return record{i, strings.Repeat(fmt.Sprint(i)+"/", 32768)} }
	if err := writer.SaveLocked(value(0)); err != nil {
		t.Fatal(err)
	}
	done := make(chan struct{})
	failures := make(chan error, 4)
	var readers sync.WaitGroup
	for i := 0; i < 4; i++ {
		readers.Add(1)
		go func() {
			defer readers.Done()
			reader := StateFile{RootDir: dir, ID: id}
			for {
				var got record
				if err := reader.load(&got, LoadOpts{ReadOnly: true}); err != nil {
					failures <- err
					return
				}
				if got.Payload != value(got.Generation).Payload {
					failures <- fmt.Errorf("torn generation %d", got.Generation)
					return
				}
				select {
				case <-done:
					return
				default:
				}
			}
		}()
	}
	for i := 1; i <= 100; i++ {
		if err := writer.SaveLocked(value(i)); err != nil {
			t.Error(err)
			break
		}
	}
	close(done)
	readers.Wait()
	close(failures)
	for err := range failures {
		t.Error(err)
	}
	// The writer has held the lifecycle lock throughout all reads.
	var got record
	if err := writer.loadLocked(&got); err != nil || got.Generation != 100 {
		t.Fatalf("last state=%+v, err=%v", got.Generation, err)
	}
}

func TestStateFileFailedPublicationPreservesPrevious(t *testing.T) {
	dir := t.TempDir()
	s := StateFile{RootDir: dir, ID: FullID{ContainerID: "c", SandboxID: "s"}}
	if err := s.LockForNew(); err != nil {
		t.Fatal(err)
	}
	defer s.close()
	defer s.UnlockOrDie()
	if err := s.SaveLocked("previous"); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(s.tmpStatePath(), 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(s.tmpStatePath(), "keep"), nil, 0600); err != nil {
		t.Fatal(err)
	}
	if err := s.SaveLocked("new"); err == nil {
		t.Fatal("publication unexpectedly succeeded")
	}
	var got string
	if err := s.load(&got, LoadOpts{ReadOnly: true}); err != nil || got != "previous" {
		t.Fatalf("previous state lost: %q %v", got, err)
	}
	ids, err := List(dir)
	if err != nil || len(ids) != 1 || ids[0] != s.ID {
		t.Fatalf("temporary state was enumerated: %v %v", ids, err)
	}
}
