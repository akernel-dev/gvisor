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

package container

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	specs "github.com/opencontainers/runtime-spec/specs-go"
	"gvisor.dev/gvisor/pkg/sentry/checkpoint"
	"gvisor.dev/gvisor/runsc/boot"
	"gvisor.dev/gvisor/runsc/config"
	"gvisor.dev/gvisor/runsc/specutils"
)

func TestFilestoreArtifactAdoption(t *testing.T) {
	for _, tc := range []struct {
		name        string
		saved       string
		artifact    string
		fingerprint string
		legacy      bool
		wantErr     string
	}{
		{name: "empty"},
		{name: "nonempty", saved: "contents", artifact: "contents"},
		{name: "truncated", saved: "contents", wantErr: "size"},
		{name: "unexpected_contents", artifact: "contents", wantErr: "size"},
		{name: "diverged", saved: "original", artifact: "modified", wantErr: "fingerprint mismatch"},
		{name: "short_fingerprint", saved: "contents", artifact: "contents", fingerprint: "x", wantErr: "fingerprint mismatch"},
		{name: "legacy_empty", legacy: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			artifactPath := filepath.Join(dir, "filestore-0")
			if err := os.WriteFile(artifactPath, []byte(tc.saved), 0600); err != nil {
				t.Fatal(err)
			}
			c := &Container{Spec: &specs.Spec{}}
			if !tc.legacy {
				f, err := os.Open(artifactPath)
				if err != nil {
					t.Fatal(err)
				}
				fp, err := checkpoint.FingerprintFile(f)
				f.Close()
				if err != nil {
					t.Fatal(err)
				}
				if tc.fingerprint != "" {
					fp = tc.fingerprint
				}
				rid := c.filestoreResourceID("/")
				sidecar, err := os.Create(filepath.Join(dir, filestoresSidecarName))
				if err != nil {
					t.Fatal(err)
				}
				err = checkpoint.WriteFilestoreSidecar(sidecar, []checkpoint.FilestoreSidecarEntry{{
					File:              "filestore-0",
					ResourceContainer: rid.ContainerName,
					ResourcePath:      rid.Path,
					SizeBytes:         uint64(len(tc.saved)),
					Fingerprint:       fp,
				}})
				sidecar.Close()
				if err != nil {
					t.Fatal(err)
				}
			}
			if err := os.WriteFile(artifactPath, []byte(tc.artifact), 0600); err != nil {
				t.Fatal(err)
			}
			// Consuming adoption exercises validation on filesystems without
			// reflink support. Clone-on-adopt uses the same validation.
			a, err := newFilestoreAdopter(&config.Config{FilestoreAdoptDir: dir}, c)
			if err != nil {
				t.Fatal(err)
			}
			f, err := a.adopt(c, "/")
			if f != nil {
				defer f.Close()
			}
			if tc.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
					t.Fatalf("adopt: got %v, want error containing %q", err, tc.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatalf("adopt: %v", err)
			}
			info, err := f.Stat()
			if err != nil {
				t.Fatal(err)
			}
			if got := info.Size(); got != int64(len(tc.artifact)) {
				t.Errorf("adopted file size = %d, want %d", got, len(tc.artifact))
			}
		})
	}
}

func TestAnonymousFilestoreMountConfig(t *testing.T) {
	for _, tc := range []struct {
		name, overlay      string
		anonymous, wantErr bool
	}{
		{"anonymous", "root:dir=/filestore", true, false},
		{"memory", "root:memory", true, true},
		{"self", "root:self", true, true},
		{"disabled", "none", true, true},
		{"legacy", "root:dir=/filestore", false, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			source := t.TempDir()
			annotations := map[string]string{
				boot.MountPrefix + "data.source": source,
				boot.MountPrefix + "data.type":   "tmpfs",
				boot.MountPrefix + "data.share":  "container",
			}
			if tc.anonymous {
				annotations[boot.MountPrefix+"data.filestore"] = "anonymous"
			}
			spec := &specs.Spec{
				Root:        &specs.Root{Path: source, Readonly: true},
				Mounts:      []specs.Mount{{Source: source, Destination: "/data", Type: "bind"}},
				Annotations: annotations,
			}
			hints, err := boot.NewPodMountHints(spec)
			if err != nil {
				t.Fatal(err)
			}
			var overlay config.Overlay2
			if err := overlay.Set(tc.overlay); err != nil {
				t.Fatal(err)
			}
			c := &Container{Spec: spec}
			err = c.initGoferConfs(overlay, hints, nil)
			if tc.wantErr {
				if err == nil || !strings.Contains(err.Error(), "requires overlay2 dir= medium") {
					t.Fatalf("got %v, want unsupported backing error", err)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if len(c.GoferMountConfs) != 2 {
				t.Fatalf("got %d mount configs, want 2", len(c.GoferMountConfs))
			}
			want := specutils.GoferMountConf{Lower: specutils.NoneLower, Upper: specutils.SelfOverlay}
			if tc.anonymous {
				want.Upper = specutils.AnonOverlay
			}
			if got := c.GoferMountConfs[1]; got != want {
				t.Fatalf("mount config = %+v, want %+v", got, want)
			}
		})
	}
}
