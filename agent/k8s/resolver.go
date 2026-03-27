package k8s

import (
	"bufio"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/siddhaarthaa/ebpf-sentinel/agent/config"
)

var containerIDPattern = regexp.MustCompile(`[a-f0-9]{12,64}`)

type ProcessMetadata struct {
	PID              uint32
	ContainerID      string
	ContainerRuntime string
	ContainerName    string
	PodName          string
	Namespace        string
}

type cachedProcessMetadata struct {
	metadata  ProcessMetadata
	expiresAt time.Time
}

type podMetadata struct {
	ContainerName string
	PodName       string
	Namespace     string
}

type Resolver struct {
	hostProc    string
	nodeName    string
	httpClient  *http.Client
	apiURL      string
	bearerToken string
	pidTTL      time.Duration
	podTTL      time.Duration

	mu            sync.Mutex
	pidCache      map[uint32]cachedProcessMetadata
	podCache      map[string]podMetadata
	podCacheUntil time.Time
}

type podListResponse struct {
	Items []podListItem `json:"items"`
}

type podListItem struct {
	Metadata podMetadataEnvelope `json:"metadata"`
	Status   podStatusEnvelope   `json:"status"`
}

type podMetadataEnvelope struct {
	Name      string `json:"name"`
	Namespace string `json:"namespace"`
}

type podStatusEnvelope struct {
	ContainerStatuses          []podContainerStatus `json:"containerStatuses"`
	InitContainerStatuses      []podContainerStatus `json:"initContainerStatuses"`
	EphemeralContainerStatuses []podContainerStatus `json:"ephemeralContainerStatuses"`
}

type podContainerStatus struct {
	Name        string `json:"name"`
	ContainerID string `json:"containerID"`
}

// NewResolver builds a metadata resolver that can map host PIDs to container and pod identity.
func NewResolver(cfg config.Config) (*Resolver, error) {
	resolver := &Resolver{
		hostProc: cfg.HostProc,
		nodeName: cfg.NodeName,
		pidTTL:   15 * time.Second,
		podTTL:   30 * time.Second,
		pidCache: make(map[uint32]cachedProcessMetadata),
		podCache: make(map[string]podMetadata),
	}

	client, apiURL, bearerToken, err := buildKubernetesClient()
	if err != nil {
		return nil, err
	}

	resolver.httpClient = client
	resolver.apiURL = apiURL
	resolver.bearerToken = bearerToken
	return resolver, nil
}

// ResolvePID returns the best available host, container, and Kubernetes metadata for one PID.
func (r *Resolver) ResolvePID(pid uint32) ProcessMetadata {
	now := time.Now()

	r.mu.Lock()
	cached, exists := r.pidCache[pid]
	if exists && now.Before(cached.expiresAt) {
		r.mu.Unlock()
		return cached.metadata
	}
	r.mu.Unlock()

	metadata := r.resolvePIDUncached(pid, now)

	r.mu.Lock()
	r.pidCache[pid] = cachedProcessMetadata{
		metadata:  metadata,
		expiresAt: now.Add(r.pidTTL),
	}
	r.mu.Unlock()

	return metadata
}

// resolvePIDUncached reads cgroup information and applies optional pod enrichment.
func (r *Resolver) resolvePIDUncached(pid uint32, now time.Time) ProcessMetadata {
	metadata := hostMetadata(pid)
	cgroupText, err := r.readCgroupFile(pid)
	if err != nil {
		return metadata
	}

	containerID, runtime := parseContainerFromCgroup(cgroupText)
	if containerID == "" {
		return metadata
	}

	metadata.ContainerID = containerID
	metadata.ContainerRuntime = runtime
	metadata.ContainerName = shortContainerID(containerID)
	metadata.PodName = "unknown"
	metadata.Namespace = "container"

	if podInfo, ok := r.resolvePodMetadata(containerID, now); ok {
		metadata.ContainerName = podInfo.ContainerName
		metadata.PodName = podInfo.PodName
		metadata.Namespace = podInfo.Namespace
	}

	return metadata
}

// readCgroupFile loads the host cgroup file for one PID from the configured proc root.
func (r *Resolver) readCgroupFile(pid uint32) (string, error) {
	path := filepath.Join(r.hostProc, strconv.FormatUint(uint64(pid), 10), "cgroup")
	data, err := os.ReadFile(path)
	if err != nil {
		return "", fmt.Errorf("read cgroup file: %w", err)
	}

	return string(data), nil
}

// resolvePodMetadata looks up cached Kubernetes pod identity for one container ID.
func (r *Resolver) resolvePodMetadata(containerID string, now time.Time) (podMetadata, bool) {
	key := normalizeContainerID(containerID)

	r.mu.Lock()
	if now.Before(r.podCacheUntil) {
		metadata, exists := r.podCache[key]
		r.mu.Unlock()
		return metadata, exists
	}
	r.mu.Unlock()

	r.refreshPodCache(now)

	r.mu.Lock()
	defer r.mu.Unlock()

	metadata, exists := r.podCache[key]
	return metadata, exists
}

// refreshPodCache refreshes the in-memory container-to-pod map from the Kubernetes API when available.
func (r *Resolver) refreshPodCache(now time.Time) {
	if r.httpClient == nil || r.apiURL == "" || r.bearerToken == "" {
		r.mu.Lock()
		r.podCacheUntil = now.Add(r.podTTL)
		r.mu.Unlock()
		return
	}

	pods, err := r.fetchPods()
	if err != nil {
		r.mu.Lock()
		r.podCacheUntil = now.Add(r.podTTL)
		r.mu.Unlock()
		return
	}

	nextCache := make(map[string]podMetadata)
	for _, item := range pods.Items {
		storePodStatuses(nextCache, item.Metadata.Name, item.Metadata.Namespace, item.Status.ContainerStatuses)
		storePodStatuses(nextCache, item.Metadata.Name, item.Metadata.Namespace, item.Status.InitContainerStatuses)
		storePodStatuses(nextCache, item.Metadata.Name, item.Metadata.Namespace, item.Status.EphemeralContainerStatuses)
	}

	r.mu.Lock()
	r.podCache = nextCache
	r.podCacheUntil = now.Add(r.podTTL)
	r.mu.Unlock()
}

// fetchPods queries the Kubernetes API server for pods on the current node when configured.
func (r *Resolver) fetchPods() (podListResponse, error) {
	requestURL := r.apiURL + "/api/v1/pods"
	if r.nodeName != "" {
		query := url.Values{}
		query.Set("fieldSelector", "spec.nodeName="+r.nodeName)
		requestURL += "?" + query.Encode()
	}

	req, err := http.NewRequest(http.MethodGet, requestURL, nil)
	if err != nil {
		return podListResponse{}, fmt.Errorf("build pods request: %w", err)
	}

	req.Header.Set("Authorization", "Bearer "+r.bearerToken)

	resp, err := r.httpClient.Do(req)
	if err != nil {
		return podListResponse{}, fmt.Errorf("fetch pods: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return podListResponse{}, fmt.Errorf("fetch pods: unexpected status %s", resp.Status)
	}

	var pods podListResponse
	if err := json.NewDecoder(resp.Body).Decode(&pods); err != nil {
		return podListResponse{}, fmt.Errorf("decode pods response: %w", err)
	}

	return pods, nil
}

// buildKubernetesClient configures an in-cluster API client when the service account environment is present.
func buildKubernetesClient() (*http.Client, string, string, error) {
	host := strings.TrimSpace(os.Getenv("KUBERNETES_SERVICE_HOST"))
	if host == "" {
		return nil, "", "", nil
	}

	port := strings.TrimSpace(os.Getenv("KUBERNETES_SERVICE_PORT"))
	if port == "" {
		port = "443"
	}

	tokenBytes, err := os.ReadFile("/var/run/secrets/kubernetes.io/serviceaccount/token")
	if err != nil {
		if os.IsNotExist(err) {
			return nil, "", "", nil
		}
		return nil, "", "", fmt.Errorf("read kubernetes service account token: %w", err)
	}

	transport := http.DefaultTransport.(*http.Transport).Clone()
	tlsConfig, err := loadClusterTLSConfig()
	if err != nil {
		return nil, "", "", err
	}
	if tlsConfig != nil {
		transport.TLSClientConfig = tlsConfig
	}

	return &http.Client{
		Timeout:   5 * time.Second,
		Transport: transport,
	}, "https://" + host + ":" + port, strings.TrimSpace(string(tokenBytes)), nil
}

// loadClusterTLSConfig loads the Kubernetes service account CA bundle when present.
func loadClusterTLSConfig() (*tls.Config, error) {
	caPath := "/var/run/secrets/kubernetes.io/serviceaccount/ca.crt"
	caBytes, err := os.ReadFile(caPath)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, fmt.Errorf("read kubernetes service account ca: %w", err)
	}

	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(caBytes) {
		return nil, fmt.Errorf("parse kubernetes service account ca")
	}

	return &tls.Config{RootCAs: pool}, nil
}

// parseContainerFromCgroup extracts the first recognizable container ID and runtime from a cgroup file.
func parseContainerFromCgroup(cgroupText string) (string, string) {
	scanner := bufio.NewScanner(strings.NewReader(cgroupText))

	for scanner.Scan() {
		line := scanner.Text()
		parts := strings.SplitN(line, ":", 3)
		if len(parts) != 3 {
			continue
		}

		path := parts[2]
		segments := strings.Split(path, "/")
		for index, segment := range segments {
			containerID, runtime := parseContainerSegment(segment)
			if containerID == "" {
				continue
			}

			if runtime == "" && index > 0 {
				runtime = runtimeFromSegment(segments[index-1])
			}

			return containerID, runtime
		}
	}

	return "", ""
}

// parseContainerSegment extracts a container ID from a single cgroup path segment.
func parseContainerSegment(segment string) (string, string) {
	segment = strings.TrimSpace(segment)
	if segment == "" {
		return "", ""
	}

	if strings.Contains(segment, "://") {
		return normalizeRuntimeContainerID(segment)
	}

	runtime := ""
	for _, prefix := range []struct {
		value   string
		runtime string
	}{
		{value: "docker-", runtime: "docker"},
		{value: "cri-containerd-", runtime: "containerd"},
		{value: "containerd-", runtime: "containerd"},
		{value: "crio-", runtime: "cri-o"},
		{value: "libpod-", runtime: "podman"},
	} {
		if strings.HasPrefix(segment, prefix.value) {
			segment = strings.TrimPrefix(segment, prefix.value)
			runtime = prefix.runtime
			break
		}
	}

	segment = strings.TrimSuffix(segment, ".scope")
	containerID := normalizeContainerID(segment)
	if containerID == "" {
		return "", ""
	}

	return containerID, runtime
}

// normalizeRuntimeContainerID splits runtime-qualified container IDs like containerd://abc123.
func normalizeRuntimeContainerID(value string) (string, string) {
	runtime, containerID, ok := strings.Cut(value, "://")
	if !ok {
		return "", ""
	}

	containerID = normalizeContainerID(containerID)
	if containerID == "" {
		return "", ""
	}

	return containerID, runtime
}

// runtimeFromSegment infers a runtime from parent cgroup path components like /docker/<id>.
func runtimeFromSegment(segment string) string {
	segment = strings.TrimSpace(segment)

	switch {
	case strings.Contains(segment, "docker"):
		return "docker"
	case strings.Contains(segment, "containerd"):
		return "containerd"
	case strings.Contains(segment, "crio"):
		return "cri-o"
	case strings.Contains(segment, "libpod"):
		return "podman"
	default:
		return ""
	}
}

// normalizeContainerID reduces a raw container identifier to its canonical lowercase hex form.
func normalizeContainerID(value string) string {
	value = strings.ToLower(strings.TrimSpace(value))
	if !isHexContainerID(value) {
		return ""
	}

	return value
}

// storePodStatuses stores one pod's container status list into the container lookup cache.
func storePodStatuses(cache map[string]podMetadata, podName string, namespace string, statuses []podContainerStatus) {
	for _, status := range statuses {
		containerID, _ := normalizeRuntimeContainerID(status.ContainerID)
		if containerID == "" {
			continue
		}

		cache[containerID] = podMetadata{
			ContainerName: status.Name,
			PodName:       podName,
			Namespace:     namespace,
		}
	}
}

// hostMetadata returns the default metadata used for processes that are not inside a container.
func hostMetadata(pid uint32) ProcessMetadata {
	return ProcessMetadata{
		PID:       pid,
		PodName:   "host",
		Namespace: "host",
	}
}

// shortContainerID shortens long container IDs for human-readable fallback display.
func shortContainerID(containerID string) string {
	if len(containerID) <= 12 {
		return containerID
	}

	return containerID[:12]
}

// isHexContainerID reports whether a string is entirely made of lowercase hex digits and fits container ID length bounds.
func isHexContainerID(value string) bool {
	if len(value) < 12 || len(value) > 64 {
		return false
	}

	return containerIDPattern.FindString(value) == value
}
