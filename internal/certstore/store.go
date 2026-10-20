package certstore

import (
	"bytes"
	"crypto"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"
)

type Store struct {
	CertMode os.FileMode
	KeyMode  os.FileMode
	Backup   bool
}

type Existing struct {
	CertPath string
	KeyPath  string
	CertPEM  []byte
	KeyPEM   []byte
	Cert     *x509.Certificate
	DaysLeft int
}

func (s Store) Load(certPath, keyPath string) (*Existing, error) {
	certPEM, certErr := os.ReadFile(certPath)
	keyPEM, keyErr := os.ReadFile(keyPath)
	if os.IsNotExist(certErr) || os.IsNotExist(keyErr) {
		return nil, nil
	}
	if certErr != nil {
		return nil, fmt.Errorf("read certificate %s: %w", certPath, certErr)
	}
	if keyErr != nil {
		return nil, fmt.Errorf("read private key %s: %w", keyPath, keyErr)
	}
	cert, err := Verify(certPEM, keyPEM, nil, time.Now())
	if err != nil {
		return nil, fmt.Errorf("validate existing certificate: %w", err)
	}
	return &Existing{
		CertPath: certPath,
		KeyPath:  keyPath,
		CertPEM:  certPEM,
		KeyPEM:   keyPEM,
		Cert:     cert,
		DaysLeft: daysLeft(cert.NotAfter, time.Now()),
	}, nil
}

func NeedsRenew(existing *Existing, names []string, renewBeforeDays int, now time.Time) (bool, string, error) {
	if existing == nil {
		return true, "certificate missing", nil
	}
	cert, err := Verify(existing.CertPEM, existing.KeyPEM, names, now)
	if err != nil {
		return true, err.Error(), nil
	}
	left := daysLeft(cert.NotAfter, now)
	if left <= renewBeforeDays {
		return true, fmt.Sprintf("expires in %d days", left), nil
	}
	return false, fmt.Sprintf("valid for %d more days", left), nil
}

func (s Store) Write(certPath, keyPath string, certPEM, keyPEM []byte) error {
	if _, err := Verify(certPEM, keyPEM, nil, time.Now()); err != nil {
		return fmt.Errorf("refuse to write invalid certificate: %w", err)
	}
	if err := os.MkdirAll(filepath.Dir(certPath), 0o755); err != nil {
		return fmt.Errorf("create certificate directory: %w", err)
	}
	if err := os.MkdirAll(filepath.Dir(keyPath), 0o755); err != nil {
		return fmt.Errorf("create key directory: %w", err)
	}
	if s.Backup {
		if err := backupFile(certPath); err != nil {
			return err
		}
		if err := backupFile(keyPath); err != nil {
			return err
		}
	}
	if err := atomicWrite(keyPath, keyPEM, s.KeyMode); err != nil {
		return fmt.Errorf("write private key: %w", err)
	}
	if err := atomicWrite(certPath, certPEM, s.CertMode); err != nil {
		return fmt.Errorf("write certificate: %w", err)
	}
	return nil
}

func Verify(certPEM, keyPEM []byte, names []string, now time.Time) (*x509.Certificate, error) {
	cert, err := parseCertificate(certPEM)
	if err != nil {
		return nil, err
	}
	if now.Before(cert.NotBefore) {
		return nil, fmt.Errorf("certificate is not valid before %s", cert.NotBefore.Format(time.RFC3339))
	}
	if now.After(cert.NotAfter) {
		return nil, fmt.Errorf("certificate expired at %s", cert.NotAfter.Format(time.RFC3339))
	}
	key, err := parsePrivateKey(keyPEM)
	if err != nil {
		return nil, err
	}
	certPub, err := x509.MarshalPKIXPublicKey(cert.PublicKey)
	if err != nil {
		return nil, fmt.Errorf("marshal certificate public key: %w", err)
	}
	keyPub, err := x509.MarshalPKIXPublicKey(key.Public())
	if err != nil {
		return nil, fmt.Errorf("marshal private key public key: %w", err)
	}
	if !bytes.Equal(certPub, keyPub) {
		return nil, fmt.Errorf("certificate and private key do not match")
	}
	for _, name := range names {
		if !certificateHasName(cert, name) {
			return nil, fmt.Errorf("certificate does not cover %s", name)
		}
	}
	return cert, nil
}

func parseCertificate(data []byte) (*x509.Certificate, error) {
	for {
		block, rest := pem.Decode(data)
		if block == nil {
			break
		}
		if block.Type == "CERTIFICATE" {
			cert, err := x509.ParseCertificate(block.Bytes)
			if err != nil {
				return nil, fmt.Errorf("parse certificate: %w", err)
			}
			return cert, nil
		}
		data = rest
	}
	return nil, fmt.Errorf("no certificate PEM block found")
}

func parsePrivateKey(data []byte) (crypto.Signer, error) {
	block, _ := pem.Decode(data)
	if block == nil {
		return nil, fmt.Errorf("no private key PEM block found")
	}
	switch block.Type {
	case "EC PRIVATE KEY":
		key, err := x509.ParseECPrivateKey(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("parse EC private key: %w", err)
		}
		return key, nil
	case "RSA PRIVATE KEY":
		key, err := x509.ParsePKCS1PrivateKey(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("parse RSA private key: %w", err)
		}
		return key, nil
	case "PRIVATE KEY":
		key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("parse PKCS#8 private key: %w", err)
		}
		signer, ok := key.(crypto.Signer)
		if !ok {
			return nil, fmt.Errorf("unsupported private key type")
		}
		return signer, nil
	default:
		return nil, fmt.Errorf("unsupported private key PEM block %q", block.Type)
	}
}

func certificateHasName(cert *x509.Certificate, name string) bool {
	name = strings.ToLower(strings.TrimSuffix(name, "."))
	for _, candidate := range cert.DNSNames {
		if strings.ToLower(strings.TrimSuffix(candidate, ".")) == name {
			return true
		}
	}
	return strings.ToLower(strings.TrimSuffix(cert.Subject.CommonName, ".")) == name
}

func daysLeft(notAfter, now time.Time) int {
	return int(notAfter.Sub(now).Hours() / 24)
}

func atomicWrite(path string, data []byte, mode os.FileMode) error {
	if mode == 0 {
		mode = 0o600
	}
	dir := filepath.Dir(path)
	tmp, err := os.CreateTemp(dir, "."+filepath.Base(path)+".tmp-*")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	defer os.Remove(tmpName)
	if err := tmp.Chmod(mode); err != nil {
		_ = tmp.Close()
		return err
	}
	if _, err := tmp.Write(data); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if err := os.Rename(tmpName, path); err != nil {
		return err
	}
	if dirFile, err := os.Open(dir); err == nil {
		_ = dirFile.Sync()
		_ = dirFile.Close()
	}
	return nil
}

func backupFile(path string) error {
	data, err := os.ReadFile(path)
	if os.IsNotExist(err) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("read %s for backup: %w", path, err)
	}
	info, err := os.Stat(path)
	if err != nil {
		return fmt.Errorf("stat %s for backup: %w", path, err)
	}
	target := fmt.Sprintf("%s.bak.%s", path, time.Now().UTC().Format("20060102T150405Z"))
	if err := os.WriteFile(target, data, info.Mode().Perm()); err != nil {
		return fmt.Errorf("backup %s: %w", path, err)
	}
	return nil
}
