package config

import (
	"os"
	"path/filepath"
	"testing"
)

func writeConfig(t *testing.T, body string) string {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "config.yaml")
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestLoadAndResolve(t *testing.T) {
	path := writeConfig(t, `
version: 1
email: test@example.com
dns_providers:
  main:
    type: alidns
    access_key: ak1
    secret_key: sk1
  secondary:
    type: alidns
    access_key: ak2
    secret_key: sk2
domains:
  - name: Example.COM
    dns: main
  - name: "*.hait.wang"
    alt_names: [hait.wang]
    dns: secondary
    key_type: rsa2048
    reload: ["echo ok"]
`)
	cfg, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Version != 1 || cfg.RenewBeforeDays != 30 {
		t.Fatalf("unexpected defaults: %+v", cfg)
	}
	domains, err := cfg.ResolveDomains()
	if err != nil {
		t.Fatal(err)
	}
	if len(domains) != 2 {
		t.Fatalf("got %d domains", len(domains))
	}
	if domains[0].Name != "example.com" {
		t.Fatalf("domain not normalized: %s", domains[0].Name)
	}
	if domains[0].CertPath != filepath.Join("certs", "example.com.crt") {
		t.Fatalf("unexpected cert path: %s", domains[0].CertPath)
	}
	if domains[0].Credentials.AccessKey != "ak1" {
		t.Fatalf("wrong access key: %s", domains[0].Credentials.AccessKey)
	}
	if len(domains[1].Names) != 2 || domains[1].Names[0] != "*.hait.wang" || domains[1].Names[1] != "hait.wang" {
		t.Fatalf("unexpected names: %#v", domains[1].Names)
	}
	if domains[1].CertPath != filepath.Join("certs", "_.hait.wang.crt") {
		t.Fatalf("unexpected wildcard cert path: %s", domains[1].CertPath)
	}
	if domains[1].KeyType != "rsa2048" {
		t.Fatalf("unexpected key type: %s", domains[1].KeyType)
	}
	if domains[1].Credentials.AccessKey != "ak2" {
		t.Fatalf("per-domain credentials not applied: %s", domains[1].Credentials.AccessKey)
	}
}

func TestCredentialsFromEnvAndFile(t *testing.T) {
	t.Setenv("TESTACCESS", "ak-from-env")
	dir := t.TempDir()
	secretFile := filepath.Join(dir, "secret")
	if err := os.WriteFile(secretFile, []byte("sk-from-file\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	path := writeConfig(t, `
version: 1
email: test@example.com
dns_providers:
  main:
    type: alidns
    access_key_env: TESTACCESS
    secret_key_file: `+secretFile+`
domains:
  - name: example.com
    dns: main
`)
	cfg, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	domains, err := cfg.ResolveDomains()
	if err != nil {
		t.Fatal(err)
	}
	if domains[0].Credentials.AccessKey != "ak-from-env" {
		t.Fatalf("wrong env access key: %s", domains[0].Credentials.AccessKey)
	}
	if domains[0].Credentials.SecretKey != "sk-from-file" {
		t.Fatalf("wrong file secret: %s", domains[0].Credentials.SecretKey)
	}
}

func TestMissingCredentials(t *testing.T) {
	path := writeConfig(t, `
version: 1
email: test@example.com
dns_providers:
  main:
    type: alidns
    access_key: ak
domains:
  - name: example.com
    dns: main
`)
	if _, err := Load(path); err == nil {
		t.Fatal("expected missing secret error")
	}
}

func TestUnknownField(t *testing.T) {
	path := writeConfig(t, `
version: 1
email: test@example.com
unknown: true
dns_providers:
  main:
    type: alidns
    access_key: ak
    secret_key: sk
domains:
  - name: example.com
    dns: main
`)
	if _, err := Load(path); err == nil {
		t.Fatal("expected unknown field error")
	}
}

func TestDuplicateDomain(t *testing.T) {
	path := writeConfig(t, `
version: 1
email: test@example.com
dns_providers:
  main:
    type: alidns
    access_key: ak
    secret_key: sk
domains:
  - name: example.com
    dns: main
  - name: EXAMPLE.com
    dns: main
`)
	if _, err := Load(path); err == nil {
		t.Fatal("expected duplicate domain error")
	}
}

func TestMissingDNSProvider(t *testing.T) {
	path := writeConfig(t, `
version: 1
email: test@example.com
dns_providers:
  main:
    type: alidns
    access_key: ak
    secret_key: sk
domains:
  - name: example.com
    dns: missing
`)
	if _, err := Load(path); err == nil {
		t.Fatal("expected missing provider error")
	}
}

func TestPathTraversal(t *testing.T) {
	path := writeConfig(t, `
version: 1
email: test@example.com
dns_providers:
  main:
    type: alidns
    access_key: ak
    secret_key: sk
domains:
  - name: example.com
    dns: main
    cert_file: ../../escape.crt
`)
	cfg, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := cfg.ResolveDomains(); err == nil {
		t.Fatal("expected path traversal error")
	}
}

func TestNormalizeDomain(t *testing.T) {
	valid := map[string]string{
		"Example.COM":     "example.com",
		"*.Hait.Wang.":    "*.hait.wang",
		"a.b.example.com": "a.b.example.com",
	}
	for input, want := range valid {
		got, err := NormalizeDomain(input)
		if err != nil {
			t.Fatalf("%q: %v", input, err)
		}
		if got != want {
			t.Fatalf("%q: got %q want %q", input, got, want)
		}
	}
	for _, input := range []string{"", "localhost", "127.0.0.1", "-bad.com", "bad-.com", "a..b.com", "bad_domain.com"} {
		if _, err := NormalizeDomain(input); err == nil {
			t.Fatalf("%q: expected error", input)
		}
	}
}

func TestKeyType(t *testing.T) {
	for _, value := range []string{"", "ec256", "ec384", "rsa2048", "rsa4096"} {
		if _, err := KeyType(value); err != nil {
			t.Fatalf("%q: %v", value, err)
		}
	}
	if _, err := KeyType("dsa"); err == nil {
		t.Fatal("expected error for unsupported key type")
	}
}
