# eBPF Sentinel — full project spec

A zero-instrumentation observability agent. It watches every application on a Linux host by tapping the kernel's syscall layer using eBPF. No SDK. No config changes to the observed app. No restarts.

---

## What it does, in one paragraph

eBPF Sentinel runs as a privileged process (or DaemonSet pod in Kubernetes) on a Linux host. It loads small eBPF programs into the kernel that fire every time a relevant syscall happens — accepting a connection, making an outbound connection, reading/writing data, spawning a process. It collects those events, reconstructs them into meaningful HTTP flows, detects anomalous behaviour patterns, exports traces in OpenTelemetry format to Jaeger, and exposes Prometheus metrics. The applications being observed don't know any of this is happening.

---

## Final repo structure

```
ebpf-sentinel/
│
├── ebpf/                          # all eBPF C programs
│   ├── vmlinux.h                  # generated from your kernel via bpftool
│   ├── common.h                   # shared structs used by C and Go
│   ├── accept.bpf.c               # kretprobe: sys_accept4
│   ├── connect.bpf.c              # kprobe: sys_connect
│   ├── exec.bpf.c                 # tracepoint: sched_process_exec
│   └── write.bpf.c                # kprobe: sys_write (for L7 reconstruction)
│
├── agent/
│   ├── main.go                    # entry point — wires everything, handles signals
│   │
│   ├── tracer/                    # one file per eBPF probe
│   │   ├── accept.go              # loads accept probe, reads ring buffer
│   │   ├── connect.go
│   │   ├── exec.go
│   │   └── write.go
│   │
│   ├── flow/
│   │   ├── tracker.go             # reconstructs L7 HTTP flows from raw events
│   │   └── types.go               # HTTPFlow, Connection structs
│   │
│   ├── anomaly/
│   │   ├── detector.go            # watches for unexpected syscall patterns
│   │   └── profiles.go            # loads YAML profiles, defines rules
│   │
│   ├── export/
│   │   ├── otlp.go                # converts flows to OTLP spans, sends to Jaeger
│   │   └── prometheus.go          # exposes /metrics endpoint
│   │
│   └── config/
│       └── config.go              # loads config from env + config file
│
├── profiles/
│   └── default.yaml               # anomaly detection profiles (nginx, postgres, etc.)
│
├── deploy/
│   ├── docker-compose.yml         # local dev: sentinel + jaeger + prometheus + grafana
│   ├── Dockerfile                 # multi-stage: builds Go binary, runs privileged
│   └── k8s/
│       ├── daemonset.yaml         # privileged DaemonSet, one pod per node
│       ├── rbac.yaml              # ClusterRole + ServiceAccount
│       └── configmap.yaml         # profiles.yaml mounted as a ConfigMap
│
├── Makefile
├── go.mod
├── go.sum
└── .gitignore
```

---

## Build phases — do these in order

### Phase 1 — one probe fires, you see it in the terminal

**Goal:** `sudo ./bin/sentinel` prints a line every time a TCP connection is accepted on your machine. Nothing else. No storage, no diffing, no exports.

Files to create:
- `ebpf/common.h` — define the `accept_event` struct
- `ebpf/accept.bpf.c` — the kretprobe on `sys_accept4`
- `agent/tracer/accept.go` — `//go:generate` directive, ring buffer reader
- `agent/main.go` — calls `tracer.RunAccept(ctx)`, prints events to stdout

When this works, you'll see output like:
```
[ACCEPT] pid=4821 comm=node fd=12 remote=203.0.113.42:54321
```

That line means your eBPF program ran inside the kernel and sent data to your Go process. This is the hardest milestone — everything after this is easier.

**Gotcha:** `bpf2go` runs `clang` under the hood. It needs to find `vmlinux.h`. Put it at `ebpf/vmlinux.h` and add `-I../ebpf` to your bpf2go flags in the go:generate comment. The exact flag syntax is:

```go
//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc clang -cflags "-O2 -g -Wall -I../ebpf" Accept ../ebpf/accept.bpf.c
```

**Gotcha:** Run `go generate` from inside `agent/tracer/`, not the repo root. Or fix the paths in the generate comment accordingly.

**Gotcha:** The generated files are `accept_bpfel.go` (little-endian) and `accept_bpfeb.go` (big-endian). On x86/ARM you'll only use the little-endian one. Both get generated — that's normal.

**Gotcha:** Your struct in `common.h` must exactly match your Go struct in memory layout. Use fixed-width types in C (`u32`, `u64`, `__u16`) and matching Go types (`uint32`, `uint64`, `uint16`). If they don't match, you'll read garbage. Add padding explicitly if needed — the kernel aligns structs and Go's `binary.Read` is strict.

---

### Phase 2 — connect and exec probes

**Goal:** Also capture outbound connections and process spawns.

Files to add:
- `ebpf/connect.bpf.c`
- `ebpf/exec.bpf.c`
- `agent/tracer/connect.go`
- `agent/tracer/exec.go`

Update `main.go` to run all three tracers concurrently via goroutines.

The connect probe uses `kprobe` (not `kretprobe`) because you want the destination address from the arguments, not the return value. The exec probe uses a tracepoint (`SEC("tracepoint/sched/sched_process_exec")`), not a kprobe — tracepoints are more stable across kernel versions because they're explicitly defined interfaces.

**Gotcha:** Getting the remote IP from the connect probe requires reading a `sockaddr` struct from kernel memory using `bpf_probe_read_kernel()`. The address is passed as a pointer argument to `sys_connect`. You need to cast it to `struct sockaddr_in` for IPv4 or `struct sockaddr_in6` for IPv6 and read the fields with BPF CO-RE helpers. Don't try to dereference the pointer directly — the verifier will reject it.

**Gotcha:** `sched_process_exec` gives you the new process name and PID but not the parent PID directly. To get the parent, read `task->real_parent->tgid` from the `task_struct` via `bpf_get_current_task()` and BPF_CORE_READ. This is where BTF earns its keep — `task_struct` layout varies heavily across kernels.

---

### Phase 3 — L7 HTTP flow reconstruction

**Goal:** Given a stream of raw read/write events, reconstruct "process X made a POST /api/login and got 200 back in 14ms."

Files to add:
- `ebpf/write.bpf.c` — captures the first N bytes of every write syscall
- `agent/tracer/write.go`
- `agent/flow/types.go` — define `Connection`, `HTTPFlow`, `PartialFlow`
- `agent/flow/tracker.go` — stateful reconstruction engine

The `FlowTracker` maintains a map of `(pid, fd) → PartialFlow`. When it sees a write event whose bytes start with an HTTP method (`GET `, `POST `, etc.), it opens a new partial flow and records the method and path. When it later sees a read event on the same `(pid, fd)` whose bytes start with `HTTP/1.` and contain a status code, it closes the flow and emits a complete `HTTPFlow`.

**Gotcha:** Your write.bpf.c should NOT capture all bytes of every write — that's too much data for the ring buffer and violates the verifier's stack size limit (512 bytes). Capture only the first 256 bytes. That's enough to identify HTTP request/response lines.

**Gotcha:** HTTP/1.1 requests and responses can span multiple syscalls. A large POST body will be split across several `write()` calls. For phase 3, only handle the simple case: the HTTP headers fit in the first write. Mark this with a TODO comment. Full reassembly is a phase 4+ problem.

**Gotcha:** The `FlowTracker` map will grow forever if connections aren't cleaned up. Add a background goroutine that evicts `PartialFlow` entries older than 30 seconds. Stale entries come from connections that were opened but never completed (aborted requests, long-polling, etc.).

**Gotcha:** The `(pid, fd)` key can be reused — when a connection closes, the kernel can give the same fd number to a new connection in the same process. Track connection open/close events from your accept and a corresponding close probe, or just evict based on age.

---

### Phase 4 — anomaly detection

**Goal:** Read a YAML file defining what "normal" looks like for known processes. Emit an alert when something unexpected happens.

Files to add:
- `agent/anomaly/profiles.go`
- `agent/anomaly/detector.go`
- `profiles/default.yaml`

The detector receives every event from all tracers. It checks:
- **Unexpected outbound connection:** a process connected to a destination not in its allowed subnet list
- **Unexpected process spawn:** a process spawned a child when `allow_exec: false`
- **Privileged port access:** a process bound to or connected from a port below 1024 unexpectedly
- **Unknown process:** a process made network syscalls but has no profile defined

Alerts are structs emitted to a channel. The exporter (phase 5) will turn them into Prometheus counter increments and log lines.

`profiles/default.yaml` example:
```yaml
profiles:
  nginx:
    expected_subnets: ["10.0.0.0/8", "172.16.0.0/12"]
    allow_exec: false
    alert_on_unknown_dest: true

  node:
    expected_subnets: ["10.0.0.0/8", "127.0.0.1/32"]
    expected_ports: [5432, 6379, 8080]
    allow_exec: false

  postgres:
    expected_subnets: ["127.0.0.1/32"]
    allow_exec: false
```

**Gotcha:** Process names (`comm`) are at most 15 characters in the kernel (TASK_COMM_LEN = 16 including null terminator). Your C struct should be `char comm[16]` and your profiles should match on truncated names. `my-long-service-name` becomes `my-long-service` in `comm`.

**Gotcha:** Container processes have different comm values than you might expect. A Node.js process inside a container still shows as `node` — but its PID namespace is isolated. When running in Kubernetes, you'll want to correlate PIDs to container IDs using the cgroup hierarchy (phase 6).

---

### Phase 5 — export: OTLP traces + Prometheus metrics

**Goal:** Flows go to Jaeger. Metrics scraped by Prometheus. Docker Compose runs everything locally.

Files to add:
- `agent/export/otlp.go`
- `agent/export/prometheus.go`
- `deploy/docker-compose.yml`

**OTLP exporter:** For each completed `HTTPFlow`, create an OpenTelemetry span. Set attributes:
- `http.method`, `http.url`, `http.status_code`
- `net.peer.ip`, `net.peer.port`
- `process.pid`, `process.executable.name`
- `sentinel.source = "ebpf"` — so consumers know this came from eBPF, not SDK instrumentation

Use `go.opentelemetry.io/otel/exporters/otlp/otlptrace/otlptracegrpc` to send to Jaeger.

**Prometheus metrics to expose:**
```
sentinel_accepted_connections_total{comm, namespace}
sentinel_http_requests_total{comm, method, status, path}
sentinel_http_duration_seconds{comm, method, path} (histogram)
sentinel_anomalies_total{comm, type}
sentinel_events_dropped_total{probe}         ← ring buffer overflow counter
sentinel_ringbuf_capacity_bytes{probe}
```

The `events_dropped_total` metric is important — it tells you if your ring buffer is too small and you're losing data.

**Docker Compose:**
```yaml
services:
  sentinel:
    build: .
    privileged: true
    pid: host
    network_mode: host
    volumes:
      - /sys/kernel/debug:/sys/kernel/debug
      - /sys/fs/bpf:/sys/fs/bpf
      - ./profiles:/etc/sentinel/profiles
    environment:
      - OTEL_EXPORTER_OTLP_ENDPOINT=http://jaeger:4317
      - PROMETHEUS_PORT=9090

  jaeger:
    image: jaegertracing/all-in-one:latest
    ports:
      - "16686:16686"   # Jaeger UI
      - "4317:4317"     # OTLP gRPC

  prometheus:
    image: prom/prometheus:latest
    ports:
      - "9091:9090"
    volumes:
      - ./deploy/prometheus.yml:/etc/prometheus/prometheus.yml

  grafana:
    image: grafana/grafana:latest
    ports:
      - "3000:3000"
```

**Gotcha:** `network_mode: host` is required so the sentinel can see host network interfaces. Without it, it's inside Docker's network namespace and misses the host's traffic.

**Gotcha:** `/sys/kernel/debug` requires `debugfs` to be mounted on the host. Check with `mount | grep debugfs`. On most distros it's mounted automatically. On some minimal cloud images it isn't. Add a startup check.

---

### Phase 6 — container and Kubernetes awareness

**Goal:** Tag every event with the container ID and Kubernetes pod name it came from. This is what makes the tool useful in real environments.

This is the most interesting engineering challenge in the project.

**How it works:** Every process in a container has a cgroup path that encodes the container ID. You can read it from `/proc/<pid>/cgroup`. For a Docker container the line looks like:

```
12:memory:/docker/a1b2c3d4e5f6...
```

For a Kubernetes pod:
```
12:memory:/kubepods/burstable/pod<pod-uid>/<container-id>
```

In your Go agent, when you receive an event with a PID, look up `/proc/<pid>/cgroup`, parse the container ID out of it, then optionally query the local container runtime (Docker socket or containerd socket) to get the container name and image.

For Kubernetes pod name resolution: the kubelet exposes a read-only API at `http://localhost:10255/pods` (if enabled) or you can use the Kubernetes API server with a ServiceAccount token. Parse the pod list to find which pod owns a given container ID.

**What to add:**
- `agent/k8s/resolver.go` — resolves pid → container ID → pod name
- Cache the resolution (cgroup reads are cheap, API calls are not)
- Add `k8s.pod.name`, `k8s.namespace.name`, `k8s.container.name` to OTLP span attributes
- Add `pod` and `namespace` labels to all Prometheus metrics

**Gotcha:** `/proc/<pid>/cgroup` must be read from the **host's** `/proc`, not the container's `/proc`. In the Kubernetes DaemonSet, mount `hostPID: true` and `/proc` from the host. In Docker Compose, use `pid: host`.

**Gotcha:** Container IDs are 64-character hex strings in Docker, shorter in containerd. The cgroup path format differs between Docker, containerd, and CRI-O. Handle all three or at minimum handle the one your target environment uses and document the limitation.

**Gotcha:** PID namespaces mean that PID 42 inside a container is a different process than PID 42 on the host. Your eBPF program runs in the host's PID namespace (because it runs in the kernel), so PIDs it sees are host PIDs. `/proc/<host-pid>/cgroup` is the right file to read. Don't confuse host PIDs with container PIDs.

---

### Phase 7 — Kubernetes DaemonSet deployment

Files to add:
- `deploy/k8s/daemonset.yaml`
- `deploy/k8s/rbac.yaml`
- `deploy/k8s/configmap.yaml`
- `deploy/Dockerfile`

**Dockerfile — multi-stage:**
```dockerfile
# Stage 1: build
FROM golang:1.22-bullseye AS builder

RUN apt-get update && apt-get install -y \
    clang llvm libbpf-dev linux-headers-generic pkg-config

WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download

COPY . .
RUN go generate ./agent/tracer/...
RUN CGO_ENABLED=0 go build -o /bin/sentinel ./agent/

# Stage 2: runtime
FROM debian:bullseye-slim
RUN apt-get update && apt-get install -y libbpf0 && rm -rf /var/lib/apt/lists/*
COPY --from=builder /bin/sentinel /bin/sentinel
ENTRYPOINT ["/bin/sentinel"]
```

**DaemonSet YAML key points:**
```yaml
spec:
  template:
    spec:
      hostPID: true
      hostNetwork: true
      serviceAccountName: ebpf-sentinel
      containers:
      - name: sentinel
        image: yourrepo/ebpf-sentinel:latest
        securityContext:
          privileged: true
        volumeMounts:
        - name: debugfs
          mountPath: /sys/kernel/debug
          readOnly: false
        - name: bpffs
          mountPath: /sys/fs/bpf
        - name: proc
          mountPath: /host/proc
          readOnly: true
        - name: profiles
          mountPath: /etc/sentinel/profiles
        env:
        - name: HOST_PROC
          value: /host/proc
        - name: NODE_NAME
          valueFrom:
            fieldRef:
              fieldPath: spec.nodeName
      volumes:
      - name: debugfs
        hostPath: { path: /sys/kernel/debug }
      - name: bpffs
        hostPath: { path: /sys/fs/bpf }
      - name: proc
        hostPath: { path: /proc }
      - name: profiles
        configMap: { name: ebpf-sentinel-profiles }
```

**RBAC:** The DaemonSet pod needs a ServiceAccount with permission to list/watch pods (for pod name resolution). Create a `ClusterRole` with `pods: [get, list, watch]` and bind it to the ServiceAccount.

**Gotcha:** Some Kubernetes clusters run with `PodSecurityAdmission` policies that block privileged pods. You need to label the namespace to allow it:
```
kubectl label namespace ebpf-sentinel pod-security.kubernetes.io/enforce=privileged
```

**Gotcha:** The `NODE_NAME` env var (injected via the Downward API) is how your agent knows which node it's on. Use it to filter Kubernetes API results — you only care about pods running on your node.

**Gotcha:** On managed Kubernetes (EKS, GKE, AKS), the kernel version is controlled by the cloud provider. GKE Autopilot doesn't support privileged pods at all — you need GKE Standard. EKS and AKS support privileged DaemonSets. Document this clearly.

---

## The complete data flow

```
1. Node.js calls write() to send HTTP response
   ↓
2. CPU switches to kernel mode (syscall instruction)
   ↓
3. Kernel's sys_write handler begins executing
   ↓
4. Your eBPF write probe fires
   → reads pid, fd, first 256 bytes of data
   → calls bpf_ringbuf_reserve() to claim a slot
   → fills the slot with the event struct
   → calls bpf_ringbuf_submit()
   ↓
5. Kernel finishes sys_write, sends bytes to NIC
   ↓
6. Go agent's ringbuf.Reader.Read() returns the event
   ↓
7. FlowTracker.OnWrite() receives the event
   → parses HTTP status line
   → matches to an open PartialFlow by (pid, fd)
   → creates a complete HTTPFlow
   ↓
8. K8s resolver tags the flow with pod name + namespace
   ↓
9. OTLP exporter creates a span, sends to Jaeger
   Prometheus exporter increments http_requests_total
   AnomalyDetector checks against profiles, maybe fires alert
```

---

## Cross-cutting gotchas

**Ring buffer sizing:** Start with 256KB per probe. If you see `sentinel_events_dropped_total` increasing, double it. Maximum is bounded by your kernel's `BPF_MAP_MAX_ENTRIES` and available locked memory. Check the locked memory limit: `ulimit -l`. If it's too low, either raise it or reduce ring buffer sizes.

**Verifier errors:** When the kernel rejects your eBPF program, the error message is cryptic. The most common causes: accessing memory without checking for null first, stack frame exceeding 512 bytes, loop that the verifier can't prove terminates, calling a helper that requires a newer kernel version than you have. Read the verifier output carefully — it tells you the exact instruction number that failed.

**Kernel version matrix:** Test on multiple kernels. Features you use:
- Ring buffer maps: kernel 5.8+
- BPF CO-RE: kernel 5.2+ (with BTF enabled, which most distros do since 5.4)
- `bpf_get_current_task_btf()`: kernel 5.11+
- Tracepoints for exec: kernel 4.x, stable everywhere

If you want to support older kernels, replace ring buffer with `BPF_MAP_TYPE_PERF_EVENT_ARRAY` (perf buffer). Different API in Go (`perf.Reader` instead of `ringbuf.Reader`) but same concept.

**Graceful shutdown:** When your Go process exits, the eBPF programs are automatically detached — the kernel cleans them up when the file descriptors close. But you should still handle SIGTERM/SIGINT cleanly: cancel the context, wait for all goroutines to finish, close the ringbuf readers, close the eBPF objects. Unclean shutdown on a DaemonSet pod restart leaves nothing dangling (kernel handles it) but you'll drop in-flight events.

**Memory pressure:** Each open connection tracked in `FlowTracker` consumes memory. In a high-traffic environment (thousands of connections/second), the tracker map can grow fast. Set a max size and evict oldest entries when you hit it. Log when eviction happens — it means you're missing flows.

**Testing without a cluster:** Use `kind` (Kubernetes in Docker) for local testing of the DaemonSet. One caveat: kind runs a Docker container as the node, so the kernel is the host's kernel. eBPF probes still work because the kernel is shared. Your container ID resolution will see Docker-in-Docker paths that look slightly different.

**CI pipeline:** eBPF programs can't be built in a standard GitHub Actions runner (no kernel headers, no BPF support). Use a self-hosted runner on a Linux VM, or use Docker-in-Docker with a privileged container in CI. The `cilium/ebpf` project itself uses this pattern in their CI. Alternatively, just run `go generate` locally and commit the generated files — controversial but practical for a solo project.

---

## What the demo looks like

1. Start everything: `docker compose up`
2. Run a test app (any Node.js or Python server): `docker run -p 8080:8080 node:alpine node -e "require('http').createServer((r,s)=>s.end('ok')).listen(8080)"`
3. Send traffic: `for i in $(seq 100); do curl localhost:8080/api/test; done`
4. Open Jaeger UI at `localhost:16686` — you see 100 traces, each showing the HTTP request, method, path, status, latency. The Node.js app has zero instrumentation.
5. Open Prometheus at `localhost:9091` — query `sentinel_http_requests_total` — you see the counter climbing.
6. Run something suspicious: `docker exec <container> /bin/sh -c "curl evil.com"` — anomaly detector fires, alert logged, `sentinel_anomalies_total` increments.

That demo, live, is worth more than any explanation.

---

## Resume talking points this project gives you

- "I wrote eBPF programs in C that run inside the Linux kernel at syscall boundaries"
- "I implemented CO-RE using BTF so the same binary works across kernel versions without recompilation"
- "I reconstructed L7 HTTP flows from raw socket events with zero application instrumentation"
- "I built a DaemonSet that automatically covers every node in a Kubernetes cluster including nodes added after deployment"
- "I correlated kernel-level PID events to Kubernetes pod names by parsing cgroup hierarchies and querying the Kubernetes API"
- "I exported traces in OpenTelemetry format, which made the tool vendor-neutral — same data goes to Jaeger, Grafana Tempo, or Datadog"

Each of those is a sentence that makes a systems-focused interviewer lean forward.