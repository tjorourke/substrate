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

package v1alpha1

import (
	"context"
	"fmt"
	"slices"
	"strings"
	"testing"

	corev1 "k8s.io/api/core/v1"
	k8errors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/utils/ptr"
)

const gpuResourceName = corev1.ResourceName("nvidia.com/gpu")

func gpuTemplate(limits, requests corev1.ResourceList) *WorkerPoolPodTemplate {
	return &WorkerPoolPodTemplate{
		Resources: &corev1.ResourceRequirements{Limits: limits, Requests: requests},
	}
}

func TestWorkerPoolSecurityValidation(t *testing.T) {
	tests := []struct {
		name     string
		settings WorkerPoolSecurityContext
		errMsg   string
	}{
		{"empty", WorkerPoolSecurityContext{}, ""},
		{"drop capabilities", WorkerPoolSecurityContext{DropCapabilities: []corev1.Capability{"SYS_PTRACE", "MKNOD"}}, ""},
		{"drop all", WorkerPoolSecurityContext{DropCapabilities: []corev1.Capability{"ALL"}}, "dropCapabilities[0]: Unsupported value"},
		{"retain file ownership", WorkerPoolSecurityContext{DropCapabilities: []corev1.Capability{"CHOWN"}}, "dropCapabilities[0]: Unsupported value"},
		{"retain foreign file modes", WorkerPoolSecurityContext{DropCapabilities: []corev1.Capability{"FOWNER"}}, "dropCapabilities[0]: Unsupported value"},
		{"unknown capability", WorkerPoolSecurityContext{DropCapabilities: []corev1.Capability{"NOT_A_CAPABILITY"}}, "dropCapabilities[0]: Unsupported value"},
		{"duplicate capability", WorkerPoolSecurityContext{DropCapabilities: []corev1.Capability{"MKNOD", "MKNOD"}}, "dropCapabilities[1]: Duplicate value"},
		{"no new privileges", WorkerPoolSecurityContext{NoNewPrivileges: ptr.To(true)}, ""},
		{"privileges allowed", WorkerPoolSecurityContext{NoNewPrivileges: ptr.To(false)}, ""},
		{"runtime default", WorkerPoolSecurityContext{SeccompProfile: &corev1.SeccompProfile{Type: corev1.SeccompProfileTypeRuntimeDefault}}, ""},
		{"unconfined", WorkerPoolSecurityContext{SeccompProfile: &corev1.SeccompProfile{Type: corev1.SeccompProfileTypeUnconfined}}, ""},
		{"localhost", WorkerPoolSecurityContext{SeccompProfile: &corev1.SeccompProfile{Type: corev1.SeccompProfileTypeLocalhost, LocalhostProfile: ptr.To("profiles/worker.json")}}, ""},
		{"missing type", WorkerPoolSecurityContext{SeccompProfile: &corev1.SeccompProfile{}}, "invalid seccomp profile type"},
		{"unknown type", WorkerPoolSecurityContext{SeccompProfile: &corev1.SeccompProfile{Type: "Unknown"}}, "invalid seccomp profile type"},
		{"missing localhost path", WorkerPoolSecurityContext{SeccompProfile: &corev1.SeccompProfile{Type: corev1.SeccompProfileTypeLocalhost}}, "localhostProfile is required only for Localhost"},
		{"empty localhost path", WorkerPoolSecurityContext{SeccompProfile: &corev1.SeccompProfile{Type: corev1.SeccompProfileTypeLocalhost, LocalhostProfile: ptr.To("")}}, "localhostProfile is required only for Localhost"},
		{"path on runtime default", WorkerPoolSecurityContext{SeccompProfile: &corev1.SeccompProfile{Type: corev1.SeccompProfileTypeRuntimeDefault, LocalhostProfile: ptr.To("worker.json")}}, "localhostProfile is required only for Localhost"},
		{"absolute path", WorkerPoolSecurityContext{SeccompProfile: &corev1.SeccompProfile{Type: corev1.SeccompProfileTypeLocalhost, LocalhostProfile: ptr.To("/worker.json")}}, "localhostProfile must be a relative path without traversal"},
		{"path traversal", WorkerPoolSecurityContext{SeccompProfile: &corev1.SeccompProfile{Type: corev1.SeccompProfileTypeLocalhost, LocalhostProfile: ptr.To("profiles/../worker.json")}}, "localhostProfile must be a relative path without traversal"},
	}
	for i, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			for _, operation := range []string{"create", "update"} {
				t.Run(operation, func(t *testing.T) {
					wp := &WorkerPool{
						ObjectMeta: metav1.ObjectMeta{Name: fmt.Sprintf("security-validation-%d-%s", i, operation), Namespace: "default"},
						Spec: WorkerPoolSpec{
							Replicas: 1, WorkerImage: "ateom:v1",
							SandboxClasses: []WorkerPoolSandboxClass{{Name: SandboxClassGvisor}},
						},
					}
					if operation == "update" {
						if err := k8sClient.Create(t.Context(), wp); err != nil {
							t.Fatalf("create valid WorkerPool: %v", err)
						}
						t.Cleanup(func() { _ = k8sClient.Delete(context.Background(), wp) })
					}
					wp.Spec.Template = &WorkerPoolPodTemplate{SecurityContext: tt.settings.DeepCopy()}
					var err error
					if operation == "update" {
						err = k8sClient.Update(t.Context(), wp)
					} else {
						err = k8sClient.Create(t.Context(), wp)
						if err == nil {
							t.Cleanup(func() { _ = k8sClient.Delete(context.Background(), wp) })
						}
					}
					if tt.errMsg == "" {
						if err != nil {
							t.Fatalf("%s WorkerPool: %v", operation, err)
						}
						return
					}
					if !k8errors.IsInvalid(err) || !strings.Contains(err.Error(), "spec.template.securityContext") || !strings.Contains(err.Error(), tt.errMsg) {
						t.Fatalf("%s WorkerPool: got %v, want securityContext validation error containing %q", operation, err, tt.errMsg)
					}
				})
			}
		})
	}
}

// Guest filesystem permissions must not be removed merely because a root-only
// counter can start. These drops broke ownership restore or guest operations.
func TestWorkerPoolRetainsFilesystemCapabilities(t *testing.T) {
	for _, class := range []SandboxClass{SandboxClassGvisor, SandboxClassMicroVM} {
		retained := []corev1.Capability{"CHOWN", "FOWNER", "SETUID", "SETFCAP"}
		if class == SandboxClassMicroVM {
			retained = append(retained, "MKNOD", "FSETID", "DAC_READ_SEARCH")
		}
		for i, capability := range retained {
			t.Run(string(class)+"/"+string(capability), func(t *testing.T) {
				wp := &WorkerPool{ObjectMeta: metav1.ObjectMeta{Name: fmt.Sprintf("retain-fs-%s-%d", class, i), Namespace: "default"}, Spec: WorkerPoolSpec{Replicas: 1, WorkerImage: "ateom:v1", SandboxClasses: []WorkerPoolSandboxClass{{Name: class}}, Template: &WorkerPoolPodTemplate{SecurityContext: &WorkerPoolSecurityContext{DropCapabilities: []corev1.Capability{capability}}}}}
				err := k8sClient.Create(t.Context(), wp)
				if !k8errors.IsInvalid(err) {
					t.Fatalf("dropping %s on %s: got %v, want rejection", capability, class, err)
				}
			})
		}
	}
}

// TestWorkerPoolDropCapabilitiesByClass checks that validation admits exactly
// DroppableWorkerCapabilities for each sandbox class, one capability at a time
// and all together.
func TestWorkerPoolDropCapabilitiesByClass(t *testing.T) {
	// Every capability either class grants by default, plus ALL.
	candidates := []corev1.Capability{
		"ALL", "CHOWN", "DAC_OVERRIDE", "DAC_READ_SEARCH", "FOWNER", "FSETID", "MKNOD", "NET_ADMIN",
		"NET_RAW", "SETFCAP", "SETGID", "SETPCAP", "SETUID", "SYS_ADMIN", "SYS_CHROOT", "SYS_PTRACE",
	}
	for _, class := range []SandboxClass{SandboxClassGvisor, SandboxClassMicroVM} {
		droppable := DroppableWorkerCapabilities[class]
		cases := []struct {
			name string
			drop []corev1.Capability
			ok   bool
		}{{name: "every droppable capability", drop: droppable, ok: true}}
		for _, capability := range candidates {
			cases = append(cases, struct {
				name string
				drop []corev1.Capability
				ok   bool
			}{name: string(capability), drop: []corev1.Capability{capability}, ok: slices.Contains(droppable, capability)})
		}
		for i, tt := range cases {
			t.Run(string(class)+"/"+tt.name, func(t *testing.T) {
				wp := &WorkerPool{
					ObjectMeta: metav1.ObjectMeta{Name: fmt.Sprintf("drop-%s-%d", class, i), Namespace: "default"},
					Spec: WorkerPoolSpec{
						Replicas: 1, WorkerImage: "ateom:v1",
						SandboxClasses: []WorkerPoolSandboxClass{{Name: class}},
						Template:       &WorkerPoolPodTemplate{SecurityContext: &WorkerPoolSecurityContext{DropCapabilities: tt.drop}},
					},
				}
				err := k8sClient.Create(t.Context(), wp)
				if err == nil {
					t.Cleanup(func() { _ = k8sClient.Delete(context.Background(), wp) })
				}
				if tt.ok {
					if err != nil {
						t.Fatalf("create WorkerPool dropping %v: %v", tt.drop, err)
					}
					return
				}
				if !k8errors.IsInvalid(err) || !strings.Contains(err.Error(), "spec.template.securityContext.dropCapabilities") {
					t.Fatalf("create WorkerPool dropping %v: got %v, want a dropCapabilities validation error", tt.drop, err)
				}
			})
		}
	}
}

func TestWorkerPoolValidation(t *testing.T) {
	ctx := context.Background()

	basePool := &WorkerPool{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test",
			Namespace: "default",
		},
		Spec: WorkerPoolSpec{
			Replicas:       1,
			WorkerImage:    "ateom:latest",
			SandboxClasses: []WorkerPoolSandboxClass{{Name: SandboxClassGvisor}},
		},
	}

	tests := []struct {
		name    string
		mutate  func(*WorkerPool)
		wantErr bool
		errMsg  string
	}{{
		name:    "base worker pool",
		mutate:  func(wp *WorkerPool) {},
		wantErr: false,
	}, {
		name: "replicas below minimum",
		mutate: func(wp *WorkerPool) {
			wp.Spec.Replicas = -1
		},
		wantErr: true,
		errMsg:  "spec.replicas: Invalid value: -1: spec.replicas in body should be greater than or equal to 0",
	}, {
		name: "missing workerImage",
		mutate: func(wp *WorkerPool) {
			wp.Spec.WorkerImage = ""
		},
		wantErr: true,
		errMsg:  "spec.workerImage: Invalid value: \"\": spec.workerImage in body should be at least 1 chars long",
	}, {
		name: "missing sandboxClasses",
		mutate: func(wp *WorkerPool) {
			wp.Spec.SandboxClasses = nil
		},
		wantErr: true,
		errMsg:  "spec.sandboxClasses: Required value",
	}, {
		name: "empty sandboxClasses",
		mutate: func(wp *WorkerPool) {
			wp.Spec.SandboxClasses = []WorkerPoolSandboxClass{}
		},
		wantErr: true,
		errMsg:  "spec.sandboxClasses",
	}, {
		name: "sandboxClass with empty name",
		mutate: func(wp *WorkerPool) {
			wp.Spec.SandboxClasses = []WorkerPoolSandboxClass{{}}
		},
		wantErr: true,
		errMsg:  "spec.sandboxClasses[0].name",
	}, {
		name: "more than one sandboxClass",
		mutate: func(wp *WorkerPool) {
			wp.Spec.SandboxClasses = []WorkerPoolSandboxClass{{Name: SandboxClassGvisor}, {Name: SandboxClassMicroVM}}
		},
		wantErr: true,
		errMsg:  "spec.sandboxClasses: Too many",
	}, {
		name: "unknown sandboxClass",
		mutate: func(wp *WorkerPool) {
			wp.Spec.SandboxClasses = []WorkerPoolSandboxClass{{Name: "kata"}}
		},
		wantErr: true,
		errMsg:  "spec.sandboxClasses[0].name: Unsupported value",
	}, {
		name: "sandboxClass with configRef",
		mutate: func(wp *WorkerPool) {
			wp.Spec.SandboxClasses = []WorkerPoolSandboxClass{{
				Name:      SandboxClassGvisor,
				ConfigRef: &SandboxConfigReference{Name: "gvisor-default"},
			}}
		},
		wantErr: false,
	}, {
		name: "configRef with empty name",
		mutate: func(wp *WorkerPool) {
			wp.Spec.SandboxClasses = []WorkerPoolSandboxClass{{
				Name:      SandboxClassGvisor,
				ConfigRef: &SandboxConfigReference{},
			}}
		},
		wantErr: true,
		errMsg:  "spec.sandboxClasses[0].configRef.name",
	}, {
		name: "configRef name of 253 characters",
		mutate: func(wp *WorkerPool) {
			wp.Spec.SandboxClasses = []WorkerPoolSandboxClass{{
				Name:      SandboxClassGvisor,
				ConfigRef: &SandboxConfigReference{Name: strings.Repeat("a", 253)},
			}}
		},
		wantErr: false,
	}, {
		name: "configRef name of 254 characters",
		mutate: func(wp *WorkerPool) {
			wp.Spec.SandboxClasses = []WorkerPoolSandboxClass{{
				Name:      SandboxClassGvisor,
				ConfigRef: &SandboxConfigReference{Name: strings.Repeat("a", 254)},
			}}
		},
		wantErr: true,
		errMsg:  "spec.sandboxClasses[0].configRef.name",
	}, {
		name: "valid template",
		mutate: func(wp *WorkerPool) {
			wp.Spec.Template = &WorkerPoolPodTemplate{
				Labels: map[string]WorkerPoolLabelValue{
					"project":                    "agent-substrate",
					"policy.example.com/profile": "sandbox_host",
				},
				Annotations: map[string]string{
					"policy.example.com/exemption": "sandbox-host",
				},
				NodeSelector: map[string]string{"workload": "substrate"},
				Tolerations: []corev1.Toleration{{
					Key:      "gpu",
					Operator: corev1.TolerationOpExists,
					Effect:   corev1.TaintEffectNoSchedule,
				}},
				Resources: &corev1.ResourceRequirements{
					Requests: corev1.ResourceList{
						corev1.ResourceCPU:    resource.MustParse("500m"),
						corev1.ResourceMemory: resource.MustParse("1Gi"),
					},
					Limits: corev1.ResourceList{
						corev1.ResourceCPU:    resource.MustParse("1"),
						corev1.ResourceMemory: resource.MustParse("2Gi"),
					},
				},
			}
		},
		wantErr: false,
	}, {
		name: "invalid worker label key",
		mutate: func(wp *WorkerPool) {
			wp.Spec.Template = &WorkerPoolPodTemplate{Labels: map[string]WorkerPoolLabelValue{"bad key": "value"}}
		},
		wantErr: true,
		errMsg:  "label keys must be valid Kubernetes qualified names",
	}, {
		name: "invalid worker label value",
		mutate: func(wp *WorkerPool) {
			wp.Spec.Template = &WorkerPoolPodTemplate{Labels: map[string]WorkerPoolLabelValue{"project": "bad value"}}
		},
		wantErr: true,
		errMsg:  "spec.template.labels.project in body should match",
	}, {
		name: "reserved ate.dev label",
		mutate: func(wp *WorkerPool) {
			wp.Spec.Template = &WorkerPoolPodTemplate{Labels: map[string]WorkerPoolLabelValue{"ate.dev/custom": "value"}}
		},
		wantErr: true,
		errMsg:  "ate.dev and its subdomains are reserved",
	}, {
		name: "reserved ate.dev subdomain label",
		mutate: func(wp *WorkerPool) {
			wp.Spec.Template = &WorkerPoolPodTemplate{Labels: map[string]WorkerPoolLabelValue{"policy.ate.dev/exemption": "value"}}
		},
		wantErr: true,
		errMsg:  "ate.dev and its subdomains are reserved",
	}, {
		name: "reserved ate.dev annotation",
		mutate: func(wp *WorkerPool) {
			wp.Spec.Template = &WorkerPoolPodTemplate{Annotations: map[string]string{"ate.dev/custom": "value"}}
		},
		wantErr: true,
		errMsg:  "ate.dev and its subdomains are reserved",
	}, {
		name: "reserved ate.dev subdomain annotation",
		mutate: func(wp *WorkerPool) {
			wp.Spec.Template = &WorkerPoolPodTemplate{Annotations: map[string]string{"policy.ate.dev/exemption": "value"}}
		},
		wantErr: true,
		errMsg:  "ate.dev and its subdomains are reserved",
	}, {
		name: "invalid worker annotation key",
		mutate: func(wp *WorkerPool) {
			wp.Spec.Template = &WorkerPoolPodTemplate{Annotations: map[string]string{"bad key": "value"}}
		},
		wantErr: true,
		errMsg:  "annotation keys must be valid Kubernetes qualified names",
	}, {
		name: "too many worker labels",
		mutate: func(wp *WorkerPool) {
			labels := make(map[string]WorkerPoolLabelValue, 65)
			for i := range 65 {
				labels[fmt.Sprintf("label-%d", i)] = "value"
			}
			wp.Spec.Template = &WorkerPoolPodTemplate{Labels: labels}
		},
		wantErr: true,
		errMsg:  "spec.template.labels: Too many",
	}, {
		name: "too many worker annotations",
		mutate: func(wp *WorkerPool) {
			annotations := make(map[string]string, 65)
			for i := range 65 {
				annotations[fmt.Sprintf("annotation-%d", i)] = "value"
			}
			wp.Spec.Template = &WorkerPoolPodTemplate{Annotations: annotations}
		},
		wantErr: true,
		errMsg:  "spec.template.annotations: Too many",
	}, {
		name: "too many tolerations",
		mutate: func(wp *WorkerPool) {
			tolerations := make([]corev1.Toleration, 17)
			for i := range tolerations {
				tolerations[i] = corev1.Toleration{
					Key:      "key",
					Operator: corev1.TolerationOpExists,
					Effect:   corev1.TaintEffectNoSchedule,
				}
			}
			wp.Spec.Template = &WorkerPoolPodTemplate{Tolerations: tolerations}
		},
		wantErr: true,
		errMsg:  "spec.template.tolerations: Too many",
	}, {
		// Devices are no longer interpreted: the limit only places the pod.
		name: "extended resource on a pool is not interpreted",
		mutate: func(wp *WorkerPool) {
			wp.Spec.SandboxClasses = []WorkerPoolSandboxClass{{Name: SandboxClassMicroVM}}
			wp.Spec.Template = gpuTemplate(corev1.ResourceList{gpuResourceName: resource.MustParse("1")}, nil)
		},
		wantErr: false,
	}}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			wp := basePool.DeepCopy()
			tt.mutate(wp)

			err := k8sClient.Create(ctx, wp)
			if err != nil && !tt.wantErr {
				t.Errorf("unexpected failure: %v", err)
			}
			if err == nil && tt.wantErr {
				t.Errorf("unexpected success, expected %q", tt.errMsg)
			}
			if err != nil && tt.wantErr && tt.errMsg != "" && !strings.Contains(err.Error(), tt.errMsg) {
				t.Errorf("wrong error:\n  wanted: %q\n     got: %q", tt.errMsg, err.Error())
			}

			if err == nil {
				_ = k8sClient.Delete(ctx, wp)
			}
		})
	}
}

func TestWorkerPoolReservedMetadataUpdate(t *testing.T) {
	ctx := context.Background()
	wp := &WorkerPool{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-reserved-metadata-update",
			Namespace: "default",
		},
		Spec: WorkerPoolSpec{
			Replicas:       1,
			WorkerImage:    "example.com/ateom:latest",
			SandboxClasses: []WorkerPoolSandboxClass{{Name: SandboxClassGvisor}},
		},
	}
	if err := k8sClient.Create(ctx, wp); err != nil {
		t.Fatalf("create WorkerPool: %v", err)
	}
	t.Cleanup(func() { _ = k8sClient.Delete(ctx, wp) })

	wp.Spec.Template = &WorkerPoolPodTemplate{
		Annotations: map[string]string{"security.ate.dev/exemption": "value"},
	}
	err := k8sClient.Update(ctx, wp)
	if err == nil {
		t.Fatal("update unexpectedly accepted a reserved annotation")
	}
	if want := "ate.dev and its subdomains are reserved"; !strings.Contains(err.Error(), want) {
		t.Errorf("wrong error:\n  wanted: %q\n     got: %q", want, err.Error())
	}
}

// TestWorkerPoolSandboxClassesUpdate verifies that the names in
// spec.sandboxClasses cannot change after creation, while the rest of an
// entry can.
func TestWorkerPoolSandboxClassesUpdate(t *testing.T) {
	ctx := context.Background()
	tests := []struct {
		name    string
		mutate  func(*WorkerPool)
		wantErr string
	}{{
		name: "change the sandbox class",
		mutate: func(wp *WorkerPool) {
			wp.Spec.SandboxClasses[0].Name = SandboxClassMicroVM
		},
		wantErr: "sandboxClasses names are immutable",
	}, {
		name: "set configRef",
		mutate: func(wp *WorkerPool) {
			wp.Spec.SandboxClasses[0].ConfigRef = &SandboxConfigReference{Name: "gvisor-release1"}
		},
	}}
	for i, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			wp := &WorkerPool{
				ObjectMeta: metav1.ObjectMeta{
					Name:      fmt.Sprintf("test-sandbox-classes-update-%d", i),
					Namespace: "default",
				},
				Spec: WorkerPoolSpec{
					Replicas:       1,
					WorkerImage:    "example.com/ateom:latest",
					SandboxClasses: []WorkerPoolSandboxClass{{Name: SandboxClassGvisor}},
				},
			}
			if err := k8sClient.Create(ctx, wp); err != nil {
				t.Fatalf("create WorkerPool: %v", err)
			}
			t.Cleanup(func() { _ = k8sClient.Delete(ctx, wp) })

			tt.mutate(wp)
			err := k8sClient.Update(ctx, wp)
			if tt.wantErr == "" {
				if err != nil {
					t.Fatalf("update: %v", err)
				}
				return
			}
			if err == nil {
				t.Fatalf("update unexpectedly accepted, want %q", tt.wantErr)
			}
			if !strings.Contains(err.Error(), tt.wantErr) {
				t.Errorf("wrong error:\n  wanted: %q\n     got: %q", tt.wantErr, err.Error())
			}
		})
	}
}
