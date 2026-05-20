package sandbox

import (
	"bytes"
	"context"
	"encoding/json"
	"io"

	"github.com/docker/docker/api/types/container"
	"github.com/docker/docker/api/types/filters"
	"github.com/docker/docker/api/types/image"
	"github.com/docker/docker/client"
	"github.com/docker/docker/pkg/stdcopy"
)

const sandboxImage = "python:3.12-slim"

const seccompProfile = `{
  "defaultAction": "SCMP_ACT_ALLOW",
  "syscalls": [
    {
      "names": [
        "ptrace", "mount", "umount2", "unshare",
        "kexec_load", "syslog", "open_by_handle_at",
        "create_module", "init_module", "delete_module",
        "pivot_root", "chroot"
      ],
      "action": "SCMP_ACT_ERRNO"
    }
  ]
}`

const maxOutputBytes = 8000

// ExecResult holds the output of a sandboxed command execution.
type ExecResult struct {
	Stdout   string `json:"stdout"`
	Stderr   string `json:"stderr"`
	ExitCode int    `json:"exit_code"`
}

// Manager manages Docker sandbox containers.
type Manager struct {
	client *client.Client
}

// NewManager creates a Manager using environment-based Docker client config.
func NewManager() (*Manager, error) {
	cli, err := client.NewClientWithOpts(client.FromEnv, client.WithAPIVersionNegotiation())
	if err != nil {
		return nil, err
	}
	return &Manager{client: cli}, nil
}

// Create starts a new hardened sandbox container and returns its short ID.
func (m *Manager) Create(ctx context.Context) (string, error) {
	// Pull image if not present.
	_, _, err := m.client.ImageInspectWithRaw(ctx, sandboxImage)
	if err != nil {
		if client.IsErrNotFound(err) {
			rc, pullErr := m.client.ImagePull(ctx, sandboxImage, image.PullOptions{})
			if pullErr != nil {
				return "", pullErr
			}
			_, _ = io.Copy(io.Discard, rc)
			rc.Close()
		} else {
			return "", err
		}
	}

	tmpfsOpts := map[string]string{
		"/tmp": "size=128m",
	}

	hostCfg := &container.HostConfig{
		ReadonlyRootfs: true,
		Tmpfs:          tmpfsOpts,
		CapDrop:        []string{"ALL"},
		CapAdd:         []string{"DAC_OVERRIDE"},
		SecurityOpt:    []string{"no-new-privileges", "seccomp=" + seccompProfile},
		NetworkMode:    "none",
		Resources: container.Resources{
			Memory:   536_870_912,   // 512 MB
			NanoCPUs: 1_000_000_000, // 1 CPU
		},
		AutoRemove: false,
	}

	cfg := &container.Config{
		Image: sandboxImage,
		Cmd:   []string{"sleep", "infinity"},
		Labels: map[string]string{
			"agentshield.sandbox": "true",
		},
	}

	resp, err := m.client.ContainerCreate(ctx, cfg, hostCfg, nil, nil, "")
	if err != nil {
		return "", err
	}

	if err := m.client.ContainerStart(ctx, resp.ID, container.StartOptions{}); err != nil {
		return "", err
	}

	// Return first 12 characters (short ID).
	id := resp.ID
	if len(id) > 12 {
		id = id[:12]
	}
	return id, nil
}

// Exec runs a shell command inside an existing sandbox container.
func (m *Manager) Exec(ctx context.Context, id, command string) (ExecResult, error) {
	execOpts := container.ExecOptions{
		Cmd:          []string{"/bin/sh", "-c", command},
		AttachStdout: true,
		AttachStderr: true,
	}

	execID, err := m.client.ContainerExecCreate(ctx, id, execOpts)
	if err != nil {
		return ExecResult{}, err
	}

	attachResp, err := m.client.ContainerExecAttach(ctx, execID.ID, container.ExecAttachOptions{})
	if err != nil {
		return ExecResult{}, err
	}
	defer attachResp.Close()

	var stdout, stderr bytes.Buffer
	_, err = stdcopy.StdCopy(&stdout, &stderr, attachResp.Reader)
	if err != nil {
		return ExecResult{}, err
	}

	inspect, err := m.client.ContainerExecInspect(ctx, execID.ID)
	if err != nil {
		return ExecResult{}, err
	}

	outStr := stdout.String()
	errStr := stderr.String()

	combined := outStr + errStr
	if len(combined) > maxOutputBytes {
		if len(outStr) > maxOutputBytes {
			outStr = outStr[:maxOutputBytes]
			errStr = ""
		} else {
			remaining := maxOutputBytes - len(outStr)
			if len(errStr) > remaining {
				errStr = errStr[:remaining]
			}
		}
	}

	return ExecResult{
		Stdout:   outStr,
		Stderr:   errStr,
		ExitCode: inspect.ExitCode,
	}, nil
}

// Destroy stops and removes a sandbox container.
func (m *Manager) Destroy(ctx context.Context, id string) error {
	timeout := 5
	_ = m.client.ContainerStop(ctx, id, container.StopOptions{Timeout: &timeout})

	return m.client.ContainerRemove(ctx, id, container.RemoveOptions{Force: true})
}

// Status returns basic state info for a sandbox container.
func (m *Manager) Status(ctx context.Context, id string) (map[string]any, error) {
	info, err := m.client.ContainerInspect(ctx, id)
	if err != nil {
		return nil, err
	}
	shortID := info.ID
	if len(shortID) > 12 {
		shortID = shortID[:12]
	}
	return map[string]any{
		"id":      shortID,
		"status":  info.State.Status,
		"running": info.State.Running,
	}, nil
}

// List returns short IDs of all agentshield sandbox containers.
func (m *Manager) List(ctx context.Context) ([]string, error) {
	f := filters.NewArgs()
	f.Add("label", "agentshield.sandbox=true")

	containers, err := m.client.ContainerList(ctx, container.ListOptions{
		All:     true,
		Filters: f,
	})
	if err != nil {
		return nil, err
	}

	ids := make([]string, 0, len(containers))
	for _, c := range containers {
		id := c.ID
		if len(id) > 12 {
			id = id[:12]
		}
		ids = append(ids, id)
	}
	return ids, nil
}

// init validates the seccomp profile JSON at startup.
func init() {
	var v any
	if err := json.Unmarshal([]byte(seccompProfile), &v); err != nil {
		panic("invalid seccomp profile JSON: " + err.Error())
	}
}
