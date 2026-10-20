package config

import (
	"bytes"
	"fmt"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"text/template"
	"time"

	"golang.org/x/net/idna"
	"gopkg.in/yaml.v3"
)

const CurrentVersion = 1

type Config struct {
	Version         int                    `yaml:"version"`
	Email           string                 `yaml:"email"`
	RenewBeforeDays int                    `yaml:"renew_before_days"`
	ACME            ACMEConfig             `yaml:"acme"`
	Storage         StorageConfig          `yaml:"storage"`
	DNSProviders    map[string]DNSProvider `yaml:"dns_providers"`
	Domains         []Domain               `yaml:"domains"`
	Notify          NotifyConfig           `yaml:"notify"`
}

type ACMEConfig struct {
	Directory        string `yaml:"directory"`
	StagingDirectory string `yaml:"staging_directory"`
}

type StorageConfig struct {
	Dir      string `yaml:"dir"`
	StateDir string `yaml:"state_dir"`
	CertMode string `yaml:"cert_mode"`
	KeyMode  string `yaml:"key_mode"`
	Backup   *bool  `yaml:"backup"`
}

type DNSProvider struct {
	Type               string `yaml:"type"`
	AccessKey          string `yaml:"access_key"`
	SecretKey          string `yaml:"secret_key"`
	SecurityToken      string `yaml:"security_token"`
	AccessKeyEnv       string `yaml:"access_key_env"`
	SecretKeyEnv       string `yaml:"secret_key_env"`
	SecurityTokenEnv   string `yaml:"security_token_env"`
	AccessKeyFile      string `yaml:"access_key_file"`
	SecretKeyFile      string `yaml:"secret_key_file"`
	SecurityTokenFile  string `yaml:"security_token_file"`
	RegionID           string `yaml:"region_id"`
	Line               string `yaml:"line"`
	TTL                int    `yaml:"ttl"`
	PropagationTimeout string `yaml:"propagation_timeout"`
	PollingInterval    string `yaml:"polling_interval"`
	HTTPTimeout        string `yaml:"http_timeout"`
}

type Domain struct {
	Name            string   `yaml:"name"`
	AltNames        []string `yaml:"alt_names"`
	DNS             string   `yaml:"dns"`
	KeyType         string   `yaml:"key_type"`
	CertFile        string   `yaml:"cert_file"`
	KeyFile         string   `yaml:"key_file"`
	Reload          []string `yaml:"reload"`
	RenewBeforeDays *int     `yaml:"renew_before_days"`
}

type NotifyConfig struct {
	Timeout        string    `yaml:"timeout"`
	Retries        int       `yaml:"retries"`
	Webhooks       []Webhook `yaml:"webhooks"`
	FailureCommand string    `yaml:"failure_command"`
}

type Webhook struct {
	Name    string            `yaml:"name"`
	URL     string            `yaml:"url"`
	Method  string            `yaml:"method"`
	Headers map[string]string `yaml:"headers"`
	Body    string            `yaml:"body"`
	Events  []string          `yaml:"events"`
}

type Credentials struct {
	Type               string
	AccessKey          string
	SecretKey          string
	SecurityToken      string
	RegionID           string
	Line               string
	TTL                int
	PropagationTimeout time.Duration
	PollingInterval    time.Duration
	HTTPTimeout        time.Duration
}

type ResolvedDomain struct {
	Name            string
	Names           []string
	DNSProvider     string
	KeyType         string
	CertPath        string
	KeyPath         string
	Reload          []string
	RenewBeforeDays int
	Credentials     Credentials
}

func Load(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read config: %w", err)
	}

	var cfg Config
	dec := yaml.NewDecoder(bytes.NewReader(data))
	dec.KnownFields(true)
	if err := dec.Decode(&cfg); err != nil {
		return nil, fmt.Errorf("parse config: %w", err)
	}

	cfg.applyDefaults()
	cfg.applyEnv()
	if err := cfg.Validate(); err != nil {
		return nil, err
	}
	return &cfg, nil
}

func (c *Config) applyDefaults() {
	if c.Version == 0 {
		c.Version = CurrentVersion
	}
	if c.RenewBeforeDays == 0 {
		c.RenewBeforeDays = 30
	}
	if c.ACME.Directory == "" {
		c.ACME.Directory = "https://acme-v02.api.letsencrypt.org/directory"
	}
	if c.ACME.StagingDirectory == "" {
		c.ACME.StagingDirectory = "https://acme-staging-v02.api.letsencrypt.org/directory"
	}
	if c.Storage.Dir == "" {
		c.Storage.Dir = "certs"
	}
	if c.Storage.StateDir == "" {
		c.Storage.StateDir = "data"
	}
	if c.Storage.CertMode == "" {
		c.Storage.CertMode = "0644"
	}
	if c.Storage.KeyMode == "" {
		c.Storage.KeyMode = "0600"
	}
	if c.Storage.Backup == nil {
		v := true
		c.Storage.Backup = &v
	}
	if c.Notify.Timeout == "" {
		c.Notify.Timeout = "10s"
	}
	if c.Notify.Retries == 0 {
		c.Notify.Retries = 3
	}
	for i := range c.DNSProviders {
		p := c.DNSProviders[i]
		if p.Type == "" {
			p.Type = "alidns"
		}
		if p.RegionID == "" {
			p.RegionID = "cn-hangzhou"
		}
		if p.TTL == 0 {
			p.TTL = 600
		}
		if p.PropagationTimeout == "" {
			p.PropagationTimeout = "60s"
		}
		if p.PollingInterval == "" {
			p.PollingInterval = "2s"
		}
		if p.HTTPTimeout == "" {
			p.HTTPTimeout = "10s"
		}
		c.DNSProviders[i] = p
	}
	for i := range c.Domains {
		d := c.Domains[i]
		if d.KeyType == "" {
			d.KeyType = "ec256"
		}
		c.Domains[i] = d
	}
	for i := range c.Notify.Webhooks {
		w := c.Notify.Webhooks[i]
		if w.Method == "" {
			w.Method = "POST"
		}
		if len(w.Events) == 0 {
			w.Events = []string{"failure", "renewed"}
		}
		c.Notify.Webhooks[i] = w
	}
}

func (c *Config) applyEnv() {
	if v := os.Getenv("CERTKEEPER_EMAIL"); v != "" {
		c.Email = v
	}
	if v := os.Getenv("CERTKEEPER_CERT_DIR"); v != "" {
		c.Storage.Dir = v
	}
	if v := os.Getenv("CERTKEEPER_STATE_DIR"); v != "" {
		c.Storage.StateDir = v
	}
	if v := os.Getenv("CERTKEEPER_RENEW_BEFORE_DAYS"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 {
			c.RenewBeforeDays = n
		}
	}
}

func (c *Config) Validate() error {
	if c.Version != CurrentVersion {
		return fmt.Errorf("unsupported config version %d (expected %d)", c.Version, CurrentVersion)
	}
	if strings.TrimSpace(c.Email) == "" {
		return fmt.Errorf("email is required")
	}
	if c.RenewBeforeDays <= 0 {
		return fmt.Errorf("renew_before_days must be greater than zero")
	}
	if _, err := time.ParseDuration(c.Notify.Timeout); err != nil {
		return fmt.Errorf("notify.timeout: %w", err)
	}
	if c.Notify.Retries < 0 {
		return fmt.Errorf("notify.retries cannot be negative")
	}
	if len(c.Domains) == 0 {
		return fmt.Errorf("at least one domain is required")
	}
	if _, err := parseMode(c.Storage.CertMode, 0o644); err != nil {
		return fmt.Errorf("storage.cert_mode: %w", err)
	}
	if _, err := parseMode(c.Storage.KeyMode, 0o600); err != nil {
		return fmt.Errorf("storage.key_mode: %w", err)
	}
	if len(c.DNSProviders) == 0 {
		return fmt.Errorf("at least one dns_providers entry is required")
	}
	seen := map[string]struct{}{}
	for i, d := range c.Domains {
		if strings.TrimSpace(d.Name) == "" {
			return fmt.Errorf("domains[%d].name is required", i)
		}
		name, err := NormalizeDomain(d.Name)
		if err != nil {
			return fmt.Errorf("domains[%d].name: %w", i, err)
		}
		if _, ok := seen[name]; ok {
			return fmt.Errorf("duplicate domain %q", name)
		}
		seen[name] = struct{}{}
		for _, alt := range d.AltNames {
			altName, err := NormalizeDomain(alt)
			if err != nil {
				return fmt.Errorf("domains[%d].alt_names: %w", i, err)
			}
			if _, ok := seen[altName]; ok {
				return fmt.Errorf("duplicate domain or alt name %q", altName)
			}
			seen[altName] = struct{}{}
		}
		dnsName := d.DNS
		if dnsName == "" {
			dnsName = "default"
		}
		if _, ok := c.DNSProviders[dnsName]; !ok {
			return fmt.Errorf("domains[%d]: dns provider %q not found", i, dnsName)
		}
		if _, err := KeyType(d.KeyType); err != nil {
			return fmt.Errorf("domains[%d].key_type: %w", i, err)
		}
	}
	for name, p := range c.DNSProviders {
		if p.Type != "alidns" {
			return fmt.Errorf("dns_providers.%s: unsupported type %q (only alidns)", name, p.Type)
		}
		if _, err := resolveSecret(p.AccessKey, p.AccessKeyEnv, p.AccessKeyFile); err != nil {
			return fmt.Errorf("dns_providers.%s.access_key: %w", name, err)
		}
		if _, err := resolveSecret(p.SecretKey, p.SecretKeyEnv, p.SecretKeyFile); err != nil {
			return fmt.Errorf("dns_providers.%s.secret_key: %w", name, err)
		}
		if p.SecurityToken != "" || p.SecurityTokenEnv != "" || p.SecurityTokenFile != "" {
			if _, err := resolveSecret(p.SecurityToken, p.SecurityTokenEnv, p.SecurityTokenFile); err != nil {
				return fmt.Errorf("dns_providers.%s.security_token: %w", name, err)
			}
		}
		if _, err := time.ParseDuration(p.PropagationTimeout); err != nil {
			return fmt.Errorf("dns_providers.%s.propagation_timeout: %w", name, err)
		}
		if _, err := time.ParseDuration(p.PollingInterval); err != nil {
			return fmt.Errorf("dns_providers.%s.polling_interval: %w", name, err)
		}
		if _, err := time.ParseDuration(p.HTTPTimeout); err != nil {
			return fmt.Errorf("dns_providers.%s.http_timeout: %w", name, err)
		}
	}
	for i, w := range c.Notify.Webhooks {
		if w.URL == "" {
			return fmt.Errorf("notify.webhooks[%d].url is required", i)
		}
		u, err := url.Parse(w.URL)
		if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
			return fmt.Errorf("notify.webhooks[%d].url is invalid", i)
		}
		switch strings.ToUpper(w.Method) {
		case "GET", "POST", "PUT", "PATCH", "DELETE":
		default:
			return fmt.Errorf("notify.webhooks[%d].method %q is not supported", i, w.Method)
		}
		for _, e := range w.Events {
			switch e {
			case "failure", "renewed", "skipped":
			default:
				return fmt.Errorf("notify.webhooks[%d].events: unknown event %q", i, e)
			}
		}
		if strings.TrimSpace(w.Body) != "" {
			if _, err := template.New("webhook").Parse(w.Body); err != nil {
				return fmt.Errorf("notify.webhooks[%d].body: %w", i, err)
			}
		}
	}
	return nil
}

func (c *Config) ResolveDomains() ([]ResolvedDomain, error) {
	out := make([]ResolvedDomain, 0, len(c.Domains))
	seenPaths := map[string]string{}
	for i, d := range c.Domains {
		name, err := NormalizeDomain(d.Name)
		if err != nil {
			return nil, fmt.Errorf("domains[%d].name: %w", i, err)
		}
		names := []string{name}
		for _, alt := range d.AltNames {
			altName, err := NormalizeDomain(alt)
			if err != nil {
				return nil, fmt.Errorf("domains[%d].alt_names: %w", i, err)
			}
			if !contains(names, altName) {
				names = append(names, altName)
			}
		}
		dnsName := d.DNS
		if dnsName == "" {
			dnsName = "default"
		}
		provider, ok := c.DNSProviders[dnsName]
		if !ok {
			return nil, fmt.Errorf("domains[%d]: dns provider %q not found", i, dnsName)
		}
		credentials, err := resolveCredentials(provider)
		if err != nil {
			return nil, fmt.Errorf("domains[%d] (%s): %w", i, name, err)
		}
		certPath, err := resolveOutputPath(c.Storage.Dir, d.CertFile, safeName(name)+".crt")
		if err != nil {
			return nil, fmt.Errorf("domains[%d].cert_file: %w", i, err)
		}
		keyPath, err := resolveOutputPath(c.Storage.Dir, d.KeyFile, safeName(name)+".key")
		if err != nil {
			return nil, fmt.Errorf("domains[%d].key_file: %w", i, err)
		}
		for _, p := range []string{certPath, keyPath} {
			if other, ok := seenPaths[p]; ok {
				return nil, fmt.Errorf("domains[%d]: output path %s is already used by %s", i, p, other)
			}
			seenPaths[p] = name
		}
		renewDays := c.RenewBeforeDays
		if d.RenewBeforeDays != nil {
			renewDays = *d.RenewBeforeDays
		}
		out = append(out, ResolvedDomain{
			Name:            name,
			Names:           names,
			DNSProvider:     dnsName,
			KeyType:         d.KeyType,
			CertPath:        certPath,
			KeyPath:         keyPath,
			Reload:          append([]string(nil), d.Reload...),
			RenewBeforeDays: renewDays,
			Credentials:     credentials,
		})
	}
	return out, nil
}

func (c *Config) ACMEDirectory(staging bool) string {
	if staging {
		return c.ACME.StagingDirectory
	}
	return c.ACME.Directory
}

func NormalizeDomain(name string) (string, error) {
	name = strings.TrimSpace(strings.ToLower(name))
	name = strings.TrimSuffix(name, ".")
	if name == "" {
		return "", fmt.Errorf("domain is empty")
	}
	wildcard := false
	if strings.HasPrefix(name, "*.") {
		wildcard = true
		name = strings.TrimPrefix(name, "*.")
	}
	if net.ParseIP(name) != nil {
		return "", fmt.Errorf("%q is an IP address, not a domain", name)
	}
	ascii, err := idna.Lookup.ToASCII(name)
	if err != nil {
		return "", fmt.Errorf("invalid domain %q: %w", name, err)
	}
	if ascii == "" || len(ascii) > 253 {
		return "", fmt.Errorf("invalid domain %q", name)
	}
	labels := strings.Split(ascii, ".")
	if len(labels) < 2 {
		return "", fmt.Errorf("invalid domain %q", name)
	}
	for _, label := range labels {
		if label == "" || len(label) > 63 || strings.HasPrefix(label, "-") || strings.HasSuffix(label, "-") {
			return "", fmt.Errorf("invalid domain %q", name)
		}
		for _, r := range label {
			if (r < 'a' || r > 'z') && (r < '0' || r > '9') && r != '-' {
				return "", fmt.Errorf("invalid domain %q", name)
			}
		}
	}
	if wildcard {
		ascii = "*." + ascii
	}
	return ascii, nil
}

func KeyType(name string) (string, error) {
	switch strings.ToLower(strings.TrimSpace(name)) {
	case "", "ec256", "ecdsa256":
		return "ec256", nil
	case "ec384", "ecdsa384":
		return "ec384", nil
	case "rsa2048":
		return "rsa2048", nil
	case "rsa4096":
		return "rsa4096", nil
	default:
		return "", fmt.Errorf("unsupported key type %q", name)
	}
}

func resolveCredentials(p DNSProvider) (Credentials, error) {
	accessKey, err := resolveSecret(p.AccessKey, p.AccessKeyEnv, p.AccessKeyFile)
	if err != nil {
		return Credentials{}, fmt.Errorf("access_key: %w", err)
	}
	secretKey, err := resolveSecret(p.SecretKey, p.SecretKeyEnv, p.SecretKeyFile)
	if err != nil {
		return Credentials{}, fmt.Errorf("secret_key: %w", err)
	}
	securityToken := ""
	if p.SecurityToken != "" || p.SecurityTokenEnv != "" || p.SecurityTokenFile != "" {
		securityToken, err = resolveSecret(p.SecurityToken, p.SecurityTokenEnv, p.SecurityTokenFile)
		if err != nil {
			return Credentials{}, fmt.Errorf("security_token: %w", err)
		}
	}
	propagation, err := time.ParseDuration(p.PropagationTimeout)
	if err != nil {
		return Credentials{}, fmt.Errorf("propagation_timeout: %w", err)
	}
	polling, err := time.ParseDuration(p.PollingInterval)
	if err != nil {
		return Credentials{}, fmt.Errorf("polling_interval: %w", err)
	}
	httpTimeout, err := time.ParseDuration(p.HTTPTimeout)
	if err != nil {
		return Credentials{}, fmt.Errorf("http_timeout: %w", err)
	}
	return Credentials{
		Type:               p.Type,
		AccessKey:          accessKey,
		SecretKey:          secretKey,
		SecurityToken:      securityToken,
		RegionID:           p.RegionID,
		Line:               p.Line,
		TTL:                p.TTL,
		PropagationTimeout: propagation,
		PollingInterval:    polling,
		HTTPTimeout:        httpTimeout,
	}, nil
}

func resolveSecret(value, envName, fileName string) (string, error) {
	if value != "" {
		return value, nil
	}
	if envName != "" {
		if v := os.Getenv(envName); v != "" {
			return v, nil
		}
		return "", fmt.Errorf("environment variable %s is empty", envName)
	}
	if fileName != "" {
		b, err := os.ReadFile(fileName)
		if err != nil {
			return "", fmt.Errorf("read %s: %w", fileName, err)
		}
		v := strings.TrimSpace(string(b))
		if v == "" {
			return "", fmt.Errorf("%s is empty", fileName)
		}
		return v, nil
	}
	return "", fmt.Errorf("no credential source configured")
}

func resolveOutputPath(base, value, defaultValue string) (string, error) {
	if value == "" {
		value = defaultValue
	}
	if filepath.IsAbs(value) {
		return filepath.Clean(value), nil
	}
	clean := filepath.Clean(value)
	if clean == ".." || strings.HasPrefix(clean, ".."+string(filepath.Separator)) {
		return "", fmt.Errorf("path escapes storage dir: %s", value)
	}
	return filepath.Join(base, clean), nil
}

func safeName(name string) string {
	return strings.ReplaceAll(name, "*", "_")
}

func parseMode(value string, defaultValue os.FileMode) (os.FileMode, error) {
	if value == "" {
		return defaultValue, nil
	}
	n, err := strconv.ParseUint(strings.TrimPrefix(value, "0o"), 8, 32)
	if err != nil {
		return 0, fmt.Errorf("invalid file mode %q", value)
	}
	return os.FileMode(n), nil
}

func contains(items []string, value string) bool {
	for _, item := range items {
		if item == value {
			return true
		}
	}
	return false
}
