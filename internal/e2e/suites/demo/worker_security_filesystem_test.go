// Copyright 2026 Google LLC
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

package demo

import (
	"context"
	"encoding/json"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/agent-substrate/substrate/internal/e2e"
	"github.com/agent-substrate/substrate/internal/resources"
	"github.com/agent-substrate/substrate/pkg/api/v1alpha1"
	"github.com/agent-substrate/substrate/pkg/proto/ateapipb"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/utils/ptr"
)

// TestWorkerSecurityFilesystem verifies the guest operations and ownership
// restore that a root-only counter does not exercise.
func TestWorkerSecurityFilesystem(t *testing.T) {
	clients := e2e.GetClients()
	src := e2e.SubstrateCounterFixture()
	pool, err := clients.SubstrateK8s.ApiV1alpha1().WorkerPools(src.PoolNamespace).Get(t.Context(), src.PoolName, metav1.GetOptions{})
	if err != nil {
		t.Fatal(err)
	}
	image := os.Getenv("E2E_WORKER_FILESYSTEM_PROBE_IMAGE")
	if image == "" {
		image = e2e.ResolveFixtureImage(t, "github.com/agent-substrate/substrate/internal/e2e/fixtures/probe")
	}
	if !strings.Contains(image, "@sha256:") {
		t.Fatal("E2E_WORKER_FILESYSTEM_PROBE_IMAGE must be pinned by digest")
	}
	for _, restricted := range []bool{false, true} {
		name := "defaults"
		if restricted {
			name = "restricted"
		}
		t.Run(name, func(t *testing.T) {
			ctx := t.Context()
			ns := e2e.CreateNamespace(t)
			template := pool.Spec.Template.DeepCopy()
			if template == nil {
				template = &v1alpha1.WorkerPoolPodTemplate{}
			}
			template.ServiceAccountName = nil
			template.SecurityContext = nil
			if restricted {
				template.SecurityContext = &v1alpha1.WorkerPoolSecurityContext{DropCapabilities: v1alpha1.DroppableWorkerCapabilities[pool.Spec.DefaultSandboxClass()], NoNewPrivileges: ptr.To(true)}
				if profile := os.Getenv("E2E_WORKER_SECCOMP_PROFILE"); profile != "" {
					template.SecurityContext.SeccompProfile = &corev1.SeccompProfile{Type: corev1.SeccompProfileTypeLocalhost, LocalhostProfile: ptr.To(profile)}
				}
			}
			actorName := "worker-filesystem-" + ns.Name
			at := e2e.CreateSubstrateCounterTemplate(ctx, t, clients, ns.Name, e2e.SubstrateTemplateOptions{
				Atespace: demoAtespace, Name: actorName, PoolName: "worker-filesystem", PoolReplicas: 1, PoolTemplate: template, Labels: map[string]string{"worker-filesystem": ns.Name},
				Modify: func(at *ateapipb.ActorTemplate) {
					at.Containers = []*ateapipb.Container{{
						Name: "probe", Image: image, Command: []string{"/ko-app/probe"},
						VolumeMounts: []*ateapipb.VolumeMount{{Name: "data", MountPath: "/home/counter"}},
						WakeupProbe: &ateapipb.WakeupProbe{
							HttpGet: &ateapipb.HttpGetAction{Path: "/healthz", Port: 80}, TimeoutSeconds: 30,
						},
						SecurityContext: &ateapipb.SecurityContext{Capabilities: &ateapipb.Capabilities{
							Add: []string{"CHOWN", "DAC_OVERRIDE", "FOWNER", "FSETID", "SETUID", "SETGID", "MKNOD"},
						}},
					}}
				},
			})
			ref := &ateapipb.ObjectRef{Atespace: demoAtespace, Name: actorName}
			if _, err := clients.SubstrateAPI.CreateActor(ctx, &ateapipb.CreateActorRequest{Actor: &ateapipb.Actor{Metadata: &ateapipb.ResourceMetadata{Atespace: demoAtespace, Name: actorName}, ActorTemplate: e2e.TemplateRef(at)}}); err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() {
				ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
				defer cancel()
				_, _ = clients.SubstrateAPI.SuspendActor(ctx, &ateapipb.SuspendActorRequest{Actor: ref})
				_, _ = clients.SubstrateAPI.DeleteActor(ctx, &ateapipb.DeleteActorRequest{Actor: ref})
			})
			for turn := 1; turn <= 3; turn++ {
				if _, err := e2e.ResumeActorAwaitCapacity(t, ctx, clients, &ateapipb.ResumeActorRequest{Actor: ref}); err != nil {
					t.Fatal(err)
				}
				method, path := "GET", "/filesystem"
				if turn == 1 {
					method = "POST"
				}
				if e2e.IsMicroVM() {
					path += "?nonroot=1"
				}
				raw, err := callActorPath(t, resources.ActorRef{Atespace: demoAtespace, Name: actorName}, method, path)
				if err != nil {
					t.Fatal(err)
				}
				assertWorkerFilesystem(t, raw)
				if turn == 1 {
					_, err = clients.SubstrateAPI.PauseActor(ctx, &ateapipb.PauseActorRequest{Actor: ref})
				} else {
					_, err = clients.SubstrateAPI.SuspendActor(ctx, &ateapipb.SuspendActorRequest{Actor: ref})
				}
				if err != nil {
					t.Fatal(err)
				}
			}
		})
	}
}

func assertWorkerFilesystem(t *testing.T, raw string) {
	t.Helper()
	var response struct {
		Error string
		Files []struct {
			Path, Contents string
			UID, GID, Mode uint32
		}
	}
	if err := json.Unmarshal([]byte(raw), &response); err != nil {
		t.Fatal(err)
	}
	if response.Error != "" || len(response.Files) != 2 {
		t.Fatalf("guest filesystem operations: %s", raw)
	}
	for _, file := range response.Files {
		if file.Path != "/var/worker-security/owned" && file.Path != "/home/counter/worker-security/owned" {
			t.Fatalf("unexpected filesystem test path: %s", raw)
		}
		if file.UID != 1000 || file.GID != 1000 || file.Mode != 0o2755 || file.Contents != "worker filesystem state" {
			t.Fatalf("guest file ownership, mode or contents changed: %s", raw)
		}
	}
	if response.Files[0].Path == response.Files[1].Path {
		t.Fatalf("rootfs and durable-directory checks returned the same path: %s", raw)
	}
}
