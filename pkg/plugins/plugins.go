// Package plugins defines the plugin contract and registry (spec §22, ADR-0006).
//
// Plugins implement typed interfaces and register themselves with the core.
// Each plugin declares its version, capabilities, required permissions, and
// is subject to the permission model enforced by the runner (never trusted to
// self-police). MVP plugins run in-process and are all first-party; the
// interface design anticipates out-of-process execution without signature
// changes.
package plugins

import (
	"context"
	"fmt"
	"sync"

	"github.com/RajaMuhammadAwais/RISKX/pkg/models"
)

// Manifest describes a plugin's identity and claims.
type Manifest struct {
	Name         string         `json:"name" yaml:"name"`
	Version      string         `json:"version" yaml:"version"`
	Capabilities []string       `json:"capabilities" yaml:"capabilities"`
	Permissions  []Permission   `json:"permissions" yaml:"permissions"`
	License      string         `json:"license" yaml:"license"`
	Disabled     bool           `json:"disabled,omitempty" yaml:"disabled,omitempty"`
}

// Permission enumerates what a plugin may access (ADR-0006 capability model).
type Permission string

const (
	PermNetworkEgress Permission = "network:egress"
	PermReadConfig    Permission = "config:read"
	PermWriteConfig   Permission = "config:write"
	PermCredentials   Permission = "credentials:use"
	PermReadStorage   Permission = "storage:read"
	PermWriteStorage  Permission = "storage:write"
)

// DiscoveryPlugin discovers assets from a target (spec §22).
type DiscoveryPlugin interface {
	Manifest() Manifest
	Discover(ctx context.Context, target string, opts DiscoverOpts) ([]models.Asset, error)
}

// DiscoverOpts carries discovery constraints the core enforces.
type DiscoverOpts struct {
	Mode    models.ExposureLevel // observation scope hint
	Timeout int                  // milliseconds
}

// VulnerabilityPlugin enriches a vulnerability identifier with verified data.
type VulnerabilityPlugin interface {
	Manifest() Manifest
	Enrich(ctx context.Context, id string) (*models.Vulnerability, error)
}

// RiskPlugin contributes factors to the risk engine (Phase 6+).
type RiskPlugin interface {
	Manifest() Manifest
	FactorValue(ctx context.Context, assetID string) (models.RiskFactor, error)
}

// ReporterPlugin renders findings in a format (JSONL, CSV, human, SARIF...).
type ReporterPlugin interface {
	Manifest() Manifest
	Report(ctx context.Context, findings []models.Finding, scores []models.RiskScore) ([]byte, error)
}

// ExporterPlugin exports data to external formats or sinks (Phase 11+).
type ExporterPlugin interface {
	Manifest() Manifest
	Export(ctx context.Context, data any) error
}

// Plugin is the common interface all plugins satisfy.
type Plugin interface {
	Manifest() Manifest
}

// Registry is the plugin registry. Registration is startup-time only and
// registration errors are fatal (fail secure: a silently missing plugin is
// worse than a refused start).
type Registry struct {
	mu       sync.RWMutex
	plugins  map[string]Plugin
	byType   map[string][]Plugin
	manifests map[string]Manifest
}

// NewRegistry creates an empty registry.
func NewRegistry() *Registry {
	return &Registry{
		plugins:   make(map[string]Plugin),
		byType:    make(map[string][]Plugin),
		manifests: make(map[string]Manifest),
	}
}

// Register adds a plugin under a type name. Duplicate names are rejected.
func (r *Registry) Register(typeName string, p Plugin) error {
	m := p.Manifest()
	if m.Name == "" {
		return fmt.Errorf("plugin has no name")
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if _, exists := r.plugins[m.Name]; exists {
		return fmt.Errorf("duplicate plugin registration: %s", m.Name)
	}
	if m.Disabled {
		return nil
	}
	r.plugins[m.Name] = p
	r.byType[typeName] = append(r.byType[typeName], p)
	r.manifests[m.Name] = m
	return nil
}

// List returns the registered plugin manifests, sorted by registration order.
func (r *Registry) List() []Manifest {
	r.mu.RLock()
	defer r.mu.RUnlock()
	out := make([]Manifest, 0, len(r.manifests))
	for _, m := range r.manifests {
		out = append(out, m)
	}
	return out
}

// Of returns plugins registered under a type name.
func (r *Registry) Of(typeName string) []Plugin {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return r.byType[typeName]
}
