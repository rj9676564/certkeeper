package lock

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/gofrs/flock"
)

type Locker struct {
	file *flock.Flock
}

func New(stateDir string) (*Locker, error) {
	if err := os.MkdirAll(stateDir, 0o700); err != nil {
		return nil, fmt.Errorf("create state dir: %w", err)
	}
	return &Locker{file: flock.New(filepath.Join(stateDir, ".certkeeper.lock"))}, nil
}

func (l *Locker) Lock(ctx context.Context) error {
	ok, err := l.file.TryLockContext(ctx, 500*time.Millisecond)
	if err != nil {
		return fmt.Errorf("acquire lock: %w", err)
	}
	if !ok {
		return fmt.Errorf("another certkeeper run is in progress")
	}
	return nil
}

func (l *Locker) Unlock() error {
	return l.file.Unlock()
}
