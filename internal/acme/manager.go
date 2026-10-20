package acme

import (
	"context"
	"crypto"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"time"

	"github.com/go-acme/lego/v4/certcrypto"
	"github.com/go-acme/lego/v4/certificate"
	"github.com/go-acme/lego/v4/lego"
	"github.com/go-acme/lego/v4/providers/dns/alidns"
	"github.com/go-acme/lego/v4/registration"
	"github.com/rj9676564/certkeeper/internal/config"
)

type Manager struct {
	Directory string
	Email     string
	StateDir  string
	Logger    *slog.Logger
}

type IssueRequest struct {
	Domains        []string
	KeyType        string
	Credentials    config.Credentials
	ExistingKeyPEM []byte
}

type Result struct {
	CertificatePEM []byte
	PrivateKeyPEM  []byte
}

type accountUser struct {
	email string
	key   crypto.PrivateKey
	reg   *registration.Resource
}

func (u *accountUser) GetEmail() string                        { return u.email }
func (u *accountUser) GetRegistration() *registration.Resource { return u.reg }
func (u *accountUser) GetPrivateKey() crypto.PrivateKey        { return u.key }

func (m *Manager) Issue(ctx context.Context, req IssueRequest) (*Result, error) {
	keyType, err := config.KeyType(req.KeyType)
	if err != nil {
		return nil, err
	}
	certKey, err := loadOrGenerateCertKey(req.ExistingKeyPEM, keyType)
	if err != nil {
		return nil, err
	}

	stateDir := filepath.Join(m.StateDir, "acme", hashString(m.Directory))
	user, err := loadOrCreateUser(stateDir, m.Email)
	if err != nil {
		return nil, err
	}

	cfg := lego.NewConfig(user)
	cfg.CADirURL = m.Directory
	cfg.Certificate.KeyType = legoKeyType(keyType)
	cfg.Certificate.Timeout = 3 * time.Minute

	client, err := lego.NewClient(cfg)
	if err != nil {
		return nil, fmt.Errorf("create acme client: %w", err)
	}
	if user.reg == nil {
		reg, err := client.Registration.Register(registration.RegisterOptions{TermsOfServiceAgreed: true})
		if err != nil {
			resolved, resolveErr := client.Registration.ResolveAccountByKey()
			if resolveErr != nil {
				return nil, fmt.Errorf("register acme account: %w", err)
			}
			reg = resolved
		}
		user.reg = reg
		if err := saveRegistration(stateDir, reg); err != nil {
			return nil, err
		}
	}

	provider, err := newDNSProvider(req.Credentials)
	if err != nil {
		return nil, err
	}
	if err := client.Challenge.SetDNS01Provider(provider); err != nil {
		return nil, fmt.Errorf("configure dns-01 provider: %w", err)
	}

	if m.Logger != nil {
		m.Logger.Info("requesting certificate", "domains", req.Domains, "directory", m.Directory)
	}
	resource, err := client.Certificate.Obtain(certificate.ObtainRequest{
		Domains:    req.Domains,
		PrivateKey: certKey,
		Bundle:     true,
	})
	if err != nil {
		return nil, fmt.Errorf("obtain certificate: %w", err)
	}
	if len(resource.Certificate) == 0 || len(resource.PrivateKey) == 0 {
		return nil, fmt.Errorf("acme returned an empty certificate or private key")
	}
	return &Result{CertificatePEM: resource.Certificate, PrivateKeyPEM: resource.PrivateKey}, nil
}

func newDNSProvider(credentials config.Credentials) (*alidns.DNSProvider, error) {
	if credentials.Type != "" && credentials.Type != "alidns" {
		return nil, fmt.Errorf("unsupported dns provider type %q", credentials.Type)
	}
	cfg := alidns.NewDefaultConfig()
	cfg.APIKey = credentials.AccessKey
	cfg.SecretKey = credentials.SecretKey
	cfg.SecurityToken = credentials.SecurityToken
	cfg.RegionID = credentials.RegionID
	cfg.Line = credentials.Line
	if credentials.TTL > 0 {
		cfg.TTL = credentials.TTL
	}
	if credentials.PropagationTimeout > 0 {
		cfg.PropagationTimeout = credentials.PropagationTimeout
	}
	if credentials.PollingInterval > 0 {
		cfg.PollingInterval = credentials.PollingInterval
	}
	if credentials.HTTPTimeout > 0 {
		cfg.HTTPTimeout = credentials.HTTPTimeout
	}
	return alidns.NewDNSProviderConfig(cfg)
}

func loadOrGenerateCertKey(existingPEM []byte, keyType string) (crypto.PrivateKey, error) {
	if len(existingPEM) > 0 {
		if key, err := certcrypto.ParsePEMPrivateKey(existingPEM); err == nil {
			return key, nil
		}
	}
	key, err := certcrypto.GeneratePrivateKey(legoKeyType(keyType))
	if err != nil {
		return nil, fmt.Errorf("generate certificate key: %w", err)
	}
	return key, nil
}

func loadOrCreateUser(stateDir, email string) (*accountUser, error) {
	if err := os.MkdirAll(stateDir, 0o700); err != nil {
		return nil, fmt.Errorf("create acme state dir: %w", err)
	}
	keyPath := filepath.Join(stateDir, "account.key")
	regPath := filepath.Join(stateDir, "account.json")

	var key crypto.PrivateKey
	if data, err := os.ReadFile(keyPath); err == nil {
		key, err = certcrypto.ParsePEMPrivateKey(data)
		if err != nil {
			return nil, fmt.Errorf("parse account key: %w", err)
		}
	} else if !os.IsNotExist(err) {
		return nil, fmt.Errorf("read account key: %w", err)
	} else {
		generated, err := certcrypto.GeneratePrivateKey(certcrypto.EC256)
		if err != nil {
			return nil, fmt.Errorf("generate account key: %w", err)
		}
		key = generated
		if err := writeFile(keyPath, certcrypto.PEMEncode(key), 0o600); err != nil {
			return nil, fmt.Errorf("write account key: %w", err)
		}
	}

	user := &accountUser{email: email, key: key}
	if data, err := os.ReadFile(regPath); err == nil {
		var reg registration.Resource
		if err := json.Unmarshal(data, &reg); err != nil {
			return nil, fmt.Errorf("parse account registration: %w", err)
		}
		user.reg = &reg
	} else if !os.IsNotExist(err) {
		return nil, fmt.Errorf("read account registration: %w", err)
	}
	return user, nil
}

func saveRegistration(stateDir string, reg *registration.Resource) error {
	data, err := json.MarshalIndent(reg, "", "  ")
	if err != nil {
		return fmt.Errorf("encode account registration: %w", err)
	}
	if err := writeFile(filepath.Join(stateDir, "account.json"), data, 0o600); err != nil {
		return fmt.Errorf("write account registration: %w", err)
	}
	return nil
}

func writeFile(path string, data []byte, mode os.FileMode) error {
	tmp, err := os.CreateTemp(filepath.Dir(path), "."+filepath.Base(path)+".tmp-*")
	if err != nil {
		return err
	}
	name := tmp.Name()
	defer os.Remove(name)
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
	return os.Rename(name, path)
}

func legoKeyType(keyType string) certcrypto.KeyType {
	switch keyType {
	case "ec384":
		return certcrypto.EC384
	case "rsa2048":
		return certcrypto.RSA2048
	case "rsa4096":
		return certcrypto.RSA4096
	default:
		return certcrypto.EC256
	}
}

func hashString(value string) string {
	sum := sha256.Sum256([]byte(value))
	return hex.EncodeToString(sum[:])[:16]
}
