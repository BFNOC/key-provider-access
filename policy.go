package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"log"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/BurntSushi/toml"
	"gopkg.in/yaml.v3"
)

const maxPolicyFileSize = 2 << 20

type pluginConfig struct {
	Enabled    *bool          `json:"enabled,omitempty" yaml:"enabled,omitempty"`
	Priority   int            `json:"priority,omitempty" yaml:"priority,omitempty"`
	Store      any            `json:"store,omitempty" yaml:"store,omitempty"`
	PolicyFile string         `json:"policy_file,omitempty" yaml:"policy_file,omitempty"`
	Version    int            `json:"version,omitempty" yaml:"version,omitempty"`
	Policies   []policyConfig `json:"policies,omitempty" yaml:"policies,omitempty"`
}

type policyDocument struct {
	Version  int            `json:"version" yaml:"version" toml:"version"`
	Policies []policyConfig `json:"policies" yaml:"policies" toml:"policies"`
}

type policyConfig struct {
	CallerScope   string   `json:"caller_scope" yaml:"caller_scope" toml:"caller_scope"`
	AllowProfiles []string `json:"allow_profiles" yaml:"allow_profiles" toml:"allow_profiles"`
	DenyProfiles  []string `json:"deny_profiles" yaml:"deny_profiles" toml:"deny_profiles"`
}

type runtimePolicy struct {
	AllowProfiles []string
	DenyProfiles  []string
}

type policySnapshot struct {
	ByCallerScope map[string]runtimePolicy
	BlockAll      bool
}

type state struct {
	mu             sync.RWMutex
	config         pluginConfig
	snapshot       policySnapshot
	source         string
	updatedAt      time.Time
	hostSchema     uint32
	hasValidPolicy bool
	lastError      string
	runtimeWarning string
	// runtimeWarningDetail describes the latest denial for operators. It and
	// denials persist until the next policy replace so a rotated or unavailable
	// profile stays visible instead of being cleared by unrelated traffic.
	runtimeWarningDetail string
	denials              map[string]int
	revision             uint64
	pickCursor           map[string]uint64
	legacyAliases        map[string]map[string]string
}

var (
	globalState = state{snapshot: failClosedSnapshot(), pickCursor: make(map[string]uint64), legacyAliases: make(map[string]map[string]string), denials: make(map[string]int)}
	mutationMu  sync.Mutex
)

func failClosedSnapshot() policySnapshot {
	return policySnapshot{ByCallerScope: make(map[string]runtimePolicy), BlockAll: true}
}

func (s *state) clear() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.config = pluginConfig{}
	s.snapshot = failClosedSnapshot()
	s.source = ""
	s.updatedAt = time.Time{}
	s.hostSchema = 0
	s.hasValidPolicy = false
	s.lastError = ""
	s.runtimeWarning = ""
	s.runtimeWarningDetail = ""
	s.denials = make(map[string]int)
	s.revision = 0
	s.pickCursor = make(map[string]uint64)
	s.legacyAliases = make(map[string]map[string]string)
}

func (s *state) current() (pluginConfig, policySnapshot, string, time.Time, uint32, string) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.config, s.snapshot, s.source, s.updatedAt, s.hostSchema, s.lastError
}

func (s *state) currentWithRevision() (pluginConfig, policySnapshot, string, time.Time, uint32, string, uint64) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.config, s.snapshot, s.source, s.updatedAt, s.hostSchema, s.lastError, s.revision
}

func (s *state) replace(cfg pluginConfig, snapshot policySnapshot, source string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.config = cfg
	s.snapshot = snapshot
	s.source = source
	s.updatedAt = time.Now().UTC()
	s.hasValidPolicy = true
	s.lastError = ""
	s.runtimeWarning = ""
	s.runtimeWarningDetail = ""
	s.denials = make(map[string]int)
	s.revision++
	s.legacyAliases = make(map[string]map[string]string)
}

func (s *state) policyRevision() uint64 {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.revision
}

func (s *state) rememberLegacyAlias(scope, current, legacy string) {
	scope = strings.TrimSpace(scope)
	current = strings.TrimSpace(current)
	legacy = strings.TrimSpace(legacy)
	if scope == "" || current == "" {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.legacyAliases == nil {
		s.legacyAliases = make(map[string]map[string]string)
	}
	if s.legacyAliases[scope] == nil {
		s.legacyAliases[scope] = make(map[string]string)
	}
	s.legacyAliases[scope][current] = legacy
}

// legacyAlias reports the legacy ID the scheduler derived for a profile and
// whether the scheduler evaluated that profile for the caller at all.
func (s *state) legacyAlias(scope, current string) (string, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	legacy, evaluated := s.legacyAliases[strings.TrimSpace(scope)][strings.TrimSpace(current)]
	return legacy, evaluated
}

func (s *state) setHostSchema(schema uint32) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.hostSchema = schema
}

func (s *state) recordPolicyError(cause error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.lastError = cause.Error()
}

// maxTrackedDenials bounds denial bookkeeping because model names are caller
// controlled; past the cap new combinations still update the warning but are
// neither counted nor logged until the next policy replace.
const maxTrackedDenials = 1024

func (s *state) recordDenial(code, scope, provider, model string, offered []string) {
	masked := make([]string, 0, len(offered))
	for _, id := range offered {
		masked = append(masked, maskProfileIdentity(strings.TrimSpace(id)))
	}
	model = boundedModel(model)
	key := scope + "\x00" + provider + "\x00" + model
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.denials == nil {
		s.denials = make(map[string]int)
	}
	count, tracked := s.denials[key]
	if tracked || len(s.denials) < maxTrackedDenials {
		count++
		s.denials[key] = count
	}
	s.runtimeWarning = code
	s.runtimeWarningDetail = fmt.Sprintf("key %s · provider %q · model %q · offered [%s] · count %d · last %s",
		scopeFingerprint(scope), provider, model, strings.Join(masked, ", "), count, time.Now().UTC().Format(time.RFC3339))
	if count == 1 {
		log.Printf("%s: %s: %s", pluginID, code, s.runtimeWarningDetail)
	}
}

// scopeFingerprint matches the dashboard's short caller-scope display.
func scopeFingerprint(scope string) string {
	if len(scope) < 16 {
		return scope
	}
	return scope[:10] + "…" + scope[len(scope)-6:]
}

// maskProfileIdentity hides everything between the last ':' and '@' of an
// OAuth profile ID so denial logs carry no account identity.
func maskProfileIdentity(id string) string {
	at := strings.Index(id, "@")
	if at < 0 {
		return id
	}
	start := strings.LastIndex(id[:at], ":") + 1
	return id[:start] + "***" + id[at:]
}

// maxModelKeyLength bounds caller-controlled model names kept in per-model
// maps and logs.
const maxModelKeyLength = 128

func boundedModel(model string) string {
	model = strings.TrimSpace(model)
	if len(model) > maxModelKeyLength {
		return model[:maxModelKeyLength] + "…"
	}
	return model
}

func (s *state) failClosedOrPreserve(cfg pluginConfig, schema uint32, cause error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.hostSchema = schema
	s.lastError = cause.Error()
	if s.hasValidPolicy {
		return
	}
	s.config = cfg
	s.snapshot = failClosedSnapshot()
	s.source = "fail-closed: " + cause.Error()
	s.updatedAt = time.Now().UTC()
	s.revision++
}

func configure(raw []byte) error {
	mutationMu.Lock()
	defer mutationMu.Unlock()

	var req lifecycleRequest
	if err := decodeJSON(raw, &req); err != nil {
		return err
	}
	cfg := pluginConfig{Version: int(schemaVersion)}
	if req.SchemaVersion < schemaVersion {
		globalState.failClosedOrPreserve(cfg, req.SchemaVersion, fmt.Errorf("%s requires CPA plugin RPC schema 2 or newer (CPA v7.2.103+)", pluginID))
		return nil
	}
	if len(req.ConfigYAML) > 0 {
		if err := decodeStrictYAML(req.ConfigYAML, &cfg); err != nil {
			globalState.failClosedOrPreserve(cfg, req.SchemaVersion, fmt.Errorf("decode plugin config: %w", err))
			return nil
		}
	}
	cfg.PolicyFile = strings.TrimSpace(cfg.PolicyFile)

	document := documentFromConfig(cfg)
	source := "inline config"
	if cfg.PolicyFile != "" {
		loaded, err := readPolicyFile(cfg.PolicyFile)
		if err != nil {
			globalState.failClosedOrPreserve(cfg, req.SchemaVersion, err)
			return nil
		}
		document = loaded
		source = cfg.PolicyFile
	}

	snapshot, sanitized, err := compileDocument(document)
	if err != nil {
		globalState.failClosedOrPreserve(cfg, req.SchemaVersion, err)
		return nil
	}
	cfg.Version = sanitized.Version
	cfg.Policies = sanitized.Policies
	globalState.setHostSchema(req.SchemaVersion)
	globalState.replace(cfg, snapshot, source)
	return nil
}

func documentFromConfig(cfg pluginConfig) policyDocument {
	return policyDocument{Version: cfg.Version, Policies: clonePolicyConfigs(cfg.Policies)}
}

func clonePolicyConfigs(policies []policyConfig) []policyConfig {
	cloned := make([]policyConfig, len(policies))
	for index, policy := range policies {
		cloned[index] = policyConfig{
			CallerScope:   policy.CallerScope,
			AllowProfiles: append([]string{}, policy.AllowProfiles...),
			DenyProfiles:  append([]string{}, policy.DenyProfiles...),
		}
	}
	return cloned
}

func readPolicyFile(path string) (policyDocument, error) {
	file, err := os.Open(path)
	if err != nil {
		return policyDocument{}, fmt.Errorf("open policy file %q: %w", path, err)
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil {
		return policyDocument{}, fmt.Errorf("stat policy file %q: %w", path, err)
	}
	if !info.Mode().IsRegular() {
		return policyDocument{}, fmt.Errorf("policy file %q is not a regular file", path)
	}
	raw, err := io.ReadAll(io.LimitReader(file, maxPolicyFileSize+1))
	if err != nil {
		return policyDocument{}, fmt.Errorf("read policy file %q: %w", path, err)
	}
	if len(raw) > maxPolicyFileSize {
		return policyDocument{}, fmt.Errorf("policy file %q exceeds %d bytes", path, maxPolicyFileSize)
	}
	var document policyDocument
	var errDecode error
	if strings.EqualFold(filepath.Ext(path), ".toml") {
		errDecode = decodeStrictTOML(raw, &document)
	} else {
		errDecode = decodeStrictYAML(raw, &document)
	}
	if errDecode != nil {
		return policyDocument{}, fmt.Errorf("decode policy file %q: %w", path, errDecode)
	}
	return document, nil
}

func decodeStrictTOML(raw []byte, target any) error {
	metadata, errDecode := toml.Decode(string(raw), target)
	if errDecode != nil {
		return errDecode
	}
	if undecoded := metadata.Undecoded(); len(undecoded) > 0 {
		keys := make([]string, 0, len(undecoded))
		for _, key := range undecoded {
			keys = append(keys, key.String())
		}
		return fmt.Errorf("unknown TOML fields: %s", strings.Join(keys, ", "))
	}
	return nil
}

func decodeStrictYAML(raw []byte, target any) error {
	decoder := yaml.NewDecoder(bytes.NewReader(raw))
	decoder.KnownFields(true)
	if err := decoder.Decode(target); err != nil {
		return err
	}
	var extra any
	if err := decoder.Decode(&extra); errors.Is(err, io.EOF) {
		return nil
	} else if err != nil {
		return err
	}
	return fmt.Errorf("multiple YAML documents are not allowed")
}

func compileDocument(document policyDocument) (policySnapshot, policyDocument, error) {
	if document.Version != int(schemaVersion) {
		return policySnapshot{}, policyDocument{}, fmt.Errorf("unsupported policy version %d; only version 2 is supported", document.Version)
	}
	if document.Policies == nil {
		document.Policies = []policyConfig{}
	}

	snapshot := policySnapshot{ByCallerScope: make(map[string]runtimePolicy)}
	for index := range document.Policies {
		item := &document.Policies[index]
		item.CallerScope = strings.ToLower(strings.TrimSpace(item.CallerScope))
		if !validSHA256(item.CallerScope) {
			return policySnapshot{}, policyDocument{}, fmt.Errorf("policies[%d].caller_scope must be 64 hexadecimal characters", index)
		}
		if _, exists := snapshot.ByCallerScope[item.CallerScope]; exists {
			return policySnapshot{}, policyDocument{}, fmt.Errorf("duplicate caller_scope at policies[%d]", index)
		}
		var err error
		item.AllowProfiles, err = normalizePatterns(item.AllowProfiles, fmt.Sprintf("policies[%d].allow_profiles", index))
		if err != nil {
			return policySnapshot{}, policyDocument{}, err
		}
		item.DenyProfiles, err = normalizePatterns(item.DenyProfiles, fmt.Sprintf("policies[%d].deny_profiles", index))
		if err != nil {
			return policySnapshot{}, policyDocument{}, err
		}
		snapshot.ByCallerScope[item.CallerScope] = runtimePolicy{
			AllowProfiles: append([]string(nil), item.AllowProfiles...),
			DenyProfiles:  append([]string(nil), item.DenyProfiles...),
		}
	}
	return snapshot, document, nil
}

func normalizePatterns(patterns []string, field string) ([]string, error) {
	seen := make(map[string]struct{}, len(patterns))
	out := make([]string, 0, len(patterns))
	for index, pattern := range patterns {
		pattern = strings.TrimSpace(pattern)
		if pattern == "" {
			return nil, fmt.Errorf("%s[%d] must not be empty", field, index)
		}
		if _, exists := seen[pattern]; exists {
			continue
		}
		seen[pattern] = struct{}{}
		out = append(out, pattern)
	}
	sort.Strings(out)
	return out, nil
}

func validSHA256(value string) bool {
	if len(value) != sha256.Size*2 {
		return false
	}
	_, err := hex.DecodeString(value)
	return err == nil
}

// callerScope mirrors CPA's built-in API-key identity derivation. It is kept
// here for fixed-vector tests and operator tooling; raw keys are never accepted
// by the policy schema or Management API.
func callerScope(rawKey string) string {
	sum := sha256.Sum256([]byte("cli-proxy-api:caller-scope:v1\x00" + strings.TrimSpace(rawKey)))
	return hex.EncodeToString(sum[:])
}

func policyAllows(policy runtimePolicy, profile string) bool {
	return policyAllowsCandidate(policy, profile, "")
}

func policyAllowsCandidate(policy runtimePolicy, profile, provider string) bool {
	return policyAllowsCandidateWithLegacies(policy, profile, provider, nil)
}

func policyAllowsSchedulerCandidate(policy runtimePolicy, candidate schedulerAuthCandidate) bool {
	return policyAllowsCandidateWithLegacies(policy, candidate.ID, candidate.Provider, []string{legacyAPIKeyProfileID(candidate)})
}

func policyAllowsCandidateWithLegacy(policy runtimePolicy, profile, provider, legacyProfile string) bool {
	return policyAllowsCandidateWithLegacies(policy, profile, provider, []string{legacyProfile})
}

func policyAllowsCandidateWithLegacies(policy runtimePolicy, profile, provider string, legacyProfiles []string) bool {
	profile = strings.TrimSpace(profile)
	_ = provider
	matches := func(pattern string) bool {
		if wildcardMatch(pattern, profile) {
			return true
		}
		for _, legacyProfile := range legacyProfiles {
			if legacyProfile != "" && wildcardMatch(pattern, strings.TrimSpace(legacyProfile)) {
				return true
			}
		}
		return false
	}
	for _, pattern := range policy.DenyProfiles {
		if matches(pattern) {
			return false
		}
	}
	if len(policy.AllowProfiles) == 0 {
		return true
	}
	for _, pattern := range policy.AllowProfiles {
		if matches(pattern) {
			return true
		}
	}
	return false
}

// legacyAPIKeyProfileID reproduces the key+base-url ID format used before
// CPA v7.2.146 for every built-in API-key profile whose identity inputs were
// expanded in that release. Candidate credentials remain transient and are
// never persisted or logged.
func legacyAPIKeyProfileID(candidate schedulerAuthCandidate) string {
	profile := strings.TrimSpace(candidate.ID)
	separator := strings.LastIndex(profile, ":")
	if separator <= 0 {
		return ""
	}
	kind := profile[:separator]
	if !legacyCapableKind(kind) {
		return ""
	}
	key := strings.TrimSpace(candidate.Attributes["api_key"])
	base := strings.TrimSpace(candidate.Attributes["base_url"])
	if key == "" && base == "" {
		return ""
	}
	hasher := sha256.New()
	hasher.Write([]byte(kind))
	hasher.Write([]byte{0})
	hasher.Write([]byte(key))
	hasher.Write([]byte{0})
	hasher.Write([]byte(base))
	digest := hex.EncodeToString(hasher.Sum(nil))
	return kind + ":" + digest[:12]
}

func legacyCapableKind(kind string) bool {
	switch kind {
	case "gemini:apikey", "gemini-interactions:apikey", "claude:apikey", "codex:apikey", "xai:apikey":
		return true
	}
	return false
}

// unverifiedLegacyDeny reports whether a profile the scheduler never evaluated
// could be the target of a legacy-format exact deny rule. Without the
// scheduler's transient credential attributes that rule cannot be checked.
func unverifiedLegacyDeny(policy runtimePolicy, profile string) bool {
	separator := strings.LastIndex(profile, ":")
	if separator <= 0 || !legacyCapableKind(profile[:separator]) {
		return false
	}
	prefix := profile[:separator+1]
	for _, rule := range policy.DenyProfiles {
		if rule != profile && strings.HasPrefix(rule, prefix) && !strings.ContainsAny(rule, "*?") {
			return true
		}
	}
	return false
}

func (s *state) nextProfile(scope, provider, model string, candidates []schedulerAuthCandidate) string {
	if len(candidates) == 0 {
		return ""
	}
	key := scope + "\x00" + strings.ToLower(strings.TrimSpace(provider)) + "\x00" + boundedModel(model)
	s.mu.Lock()
	defer s.mu.Unlock()
	// ponytail: resetting all cursors only restarts round-robin positions; switch
	// to an LRU if fair rotation across many distinct models ever matters.
	if s.pickCursor == nil || len(s.pickCursor) >= maxTrackedDenials {
		s.pickCursor = make(map[string]uint64)
	}
	cursor := s.pickCursor[key]
	s.pickCursor[key] = cursor + 1
	return candidates[cursor%uint64(len(candidates))].ID
}

// wildcardMatch supports shell-style '*' and '?' while allowing '*' to cross '/'.
func wildcardMatch(pattern, value string) bool {
	patternRunes, valueRunes := []rune(pattern), []rune(value)
	p, v, star, checkpoint := 0, 0, -1, 0
	for v < len(valueRunes) {
		if p < len(patternRunes) && (patternRunes[p] == '?' || patternRunes[p] == valueRunes[v]) {
			p++
			v++
			continue
		}
		if p < len(patternRunes) && patternRunes[p] == '*' {
			star = p
			p++
			checkpoint = v
			continue
		}
		if star >= 0 {
			p = star + 1
			checkpoint++
			v = checkpoint
			continue
		}
		return false
	}
	for p < len(patternRunes) && patternRunes[p] == '*' {
		p++
	}
	return p == len(patternRunes)
}

func writePolicyFile(path string, document policyDocument) error {
	if strings.TrimSpace(path) == "" {
		return fmt.Errorf("policy_file is not configured")
	}
	var raw []byte
	var err error
	if strings.EqualFold(filepath.Ext(path), ".toml") {
		if len(document.Policies) == 0 {
			raw = []byte("version = 2\npolicies = []\n")
		} else {
			raw, err = toml.Marshal(document)
		}
	} else {
		raw, err = yaml.Marshal(document)
	}
	if err != nil {
		return fmt.Errorf("encode policy file: %w", err)
	}
	dir := filepath.Dir(path)
	if dir != "." {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			return fmt.Errorf("create policy directory: %w", err)
		}
	}
	temporary, err := os.CreateTemp(dir, ".key-provider-acl-*.tmp")
	if err != nil {
		return fmt.Errorf("create temporary policy file: %w", err)
	}
	temporaryName := temporary.Name()
	defer os.Remove(temporaryName)
	if err := temporary.Chmod(0o600); err != nil {
		temporary.Close()
		return fmt.Errorf("secure temporary policy file: %w", err)
	}
	if _, err := temporary.Write(raw); err != nil {
		temporary.Close()
		return fmt.Errorf("write temporary policy file: %w", err)
	}
	if err := temporary.Sync(); err != nil {
		temporary.Close()
		return fmt.Errorf("sync temporary policy file: %w", err)
	}
	if err := temporary.Close(); err != nil {
		return fmt.Errorf("close temporary policy file: %w", err)
	}
	if err := os.Rename(temporaryName, path); err != nil {
		return fmt.Errorf("replace policy file: %w", err)
	}
	if runtime.GOOS != "windows" {
		directory, err := os.Open(dir)
		if err != nil {
			return fmt.Errorf("open policy directory for sync: %w", err)
		}
		errSync := directory.Sync()
		errClose := directory.Close()
		if errSync != nil {
			return fmt.Errorf("sync policy directory: %w", errSync)
		}
		if errClose != nil {
			return fmt.Errorf("close policy directory: %w", errClose)
		}
	}
	return nil
}
