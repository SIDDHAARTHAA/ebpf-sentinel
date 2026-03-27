package k8s

import "testing"

// TestParseContainerFromCgroupHandlesDocker verifies Docker cgroup paths resolve to Docker IDs.
func TestParseContainerFromCgroupHandlesDocker(t *testing.T) {
	cgroup := "12:memory:/docker/a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6\n"

	containerID, runtime := parseContainerFromCgroup(cgroup)

	if containerID != "a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6" {
		t.Fatalf("unexpected container id: %s", containerID)
	}
	if runtime != "docker" {
		t.Fatalf("unexpected runtime: %s", runtime)
	}
}

// TestParseContainerFromCgroupHandlesContainerd verifies systemd-scoped containerd paths are normalized.
func TestParseContainerFromCgroupHandlesContainerd(t *testing.T) {
	cgroup := "0::/kubepods/burstable/pod12345678-90ab-cdef-1234-567890abcdef/cri-containerd-0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef.scope\n"

	containerID, runtime := parseContainerFromCgroup(cgroup)

	if containerID != "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef" {
		t.Fatalf("unexpected container id: %s", containerID)
	}
	if runtime != "containerd" {
		t.Fatalf("unexpected runtime: %s", runtime)
	}
}

// TestParseContainerFromCgroupHandlesCrio verifies CRI-O systemd unit names resolve correctly.
func TestParseContainerFromCgroupHandlesCrio(t *testing.T) {
	cgroup := "0::/kubepods.slice/kubepods-burstable.slice/kubepods-burstable-pod123.slice/crio-abcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdef.scope\n"

	containerID, runtime := parseContainerFromCgroup(cgroup)

	if containerID != "abcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdef" {
		t.Fatalf("unexpected container id: %s", containerID)
	}
	if runtime != "cri-o" {
		t.Fatalf("unexpected runtime: %s", runtime)
	}
}

// TestNormalizeRuntimeContainerID verifies runtime-qualified container IDs are stripped correctly.
func TestNormalizeRuntimeContainerID(t *testing.T) {
	containerID, runtime := normalizeRuntimeContainerID("containerd://0123456789abcdef")

	if containerID != "0123456789abcdef" {
		t.Fatalf("unexpected container id: %s", containerID)
	}
	if runtime != "containerd" {
		t.Fatalf("unexpected runtime: %s", runtime)
	}
}
