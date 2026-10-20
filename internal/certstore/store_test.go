package certstore

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func makeCert(t *testing.T, names []string, notAfter time.Time) (certPEM, keyPEM []byte) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: names[0]},
		DNSNames:     names,
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     notAfter,
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, key.Public(), key)
	if err != nil {
		t.Fatal(err)
	}
	certPEM = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	keyPEM = pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})
	return certPEM, keyPEM
}

func TestVerifyAndRenewDecision(t *testing.T) {
	now := time.Now()
	certPEM, keyPEM := makeCert(t, []string{"example.com", "*.hait.wang"}, now.Add(60*24*time.Hour))
	if _, err := Verify(certPEM, keyPEM, []string{"example.com", "*.hait.wang"}, now); err != nil {
		t.Fatal(err)
	}
	if _, err := Verify(certPEM, keyPEM, []string{"other.com"}, now); err == nil {
		t.Fatal("expected SAN mismatch")
	}
	otherCert, otherKey := makeCert(t, []string{"other.com"}, now.Add(60*24*time.Hour))
	if _, err := Verify(certPEM, otherKey, nil, now); err == nil {
		t.Fatal("expected key mismatch")
	}

	existing := &Existing{CertPEM: certPEM, KeyPEM: keyPEM}
	needs, reason, err := NeedsRenew(existing, []string{"example.com"}, 30, now)
	if err != nil {
		t.Fatal(err)
	}
	if needs {
		t.Fatalf("expected no renewal, got %s", reason)
	}

	soonPEM, soonKey := makeCert(t, []string{"example.com"}, now.Add(10*24*time.Hour))
	needs, _, err = NeedsRenew(&Existing{CertPEM: soonPEM, KeyPEM: soonKey}, []string{"example.com"}, 30, now)
	if err != nil {
		t.Fatal(err)
	}
	if !needs {
		t.Fatal("expected renewal for expiring certificate")
	}

	if _, err := Verify(otherCert, otherKey, []string{"other.com"}, now.Add(90*24*time.Hour)); err == nil {
		t.Fatal("expected expired certificate error")
	}
}

func TestStoreWriteLoadBackup(t *testing.T) {
	dir := t.TempDir()
	certPath := filepath.Join(dir, "certs", "example.com.crt")
	keyPath := filepath.Join(dir, "certs", "example.com.key")
	store := Store{CertMode: 0o644, KeyMode: 0o600, Backup: true}
	now := time.Now()
	certPEM, keyPEM := makeCert(t, []string{"example.com"}, now.Add(60*24*time.Hour))

	if err := store.Write(certPath, keyPath, certPEM, keyPEM); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(keyPath)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("key mode = %o", info.Mode().Perm())
	}
	info, err = os.Stat(certPath)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o644 {
		t.Fatalf("cert mode = %o", info.Mode().Perm())
	}

	existing, err := store.Load(certPath, keyPath)
	if err != nil {
		t.Fatal(err)
	}
	if existing == nil || existing.DaysLeft < 59 {
		t.Fatalf("unexpected existing cert: %+v", existing)
	}

	certPEM2, keyPEM2 := makeCert(t, []string{"example.com"}, now.Add(90*24*time.Hour))
	if err := store.Write(certPath, keyPath, certPEM2, keyPEM2); err != nil {
		t.Fatal(err)
	}
	backups, err := filepath.Glob(filepath.Join(dir, "certs", "*.bak.*"))
	if err != nil {
		t.Fatal(err)
	}
	if len(backups) != 2 {
		t.Fatalf("expected 2 backups, got %v", backups)
	}
}

func TestLoadMissing(t *testing.T) {
	store := Store{}
	existing, err := store.Load(filepath.Join(t.TempDir(), "missing.crt"), filepath.Join(t.TempDir(), "missing.key"))
	if err != nil {
		t.Fatal(err)
	}
	if existing != nil {
		t.Fatal("expected nil existing certificate")
	}
}

func TestLoadInvalid(t *testing.T) {
	dir := t.TempDir()
	certPath := filepath.Join(dir, "bad.crt")
	keyPath := filepath.Join(dir, "bad.key")
	if err := os.WriteFile(certPath, []byte("not a cert"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(keyPath, []byte("not a key"), 0o600); err != nil {
		t.Fatal(err)
	}
	store := Store{}
	if _, err := store.Load(certPath, keyPath); err == nil {
		t.Fatal("expected invalid certificate error")
	}
}
