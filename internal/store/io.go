package store

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
)

// readJSON best-effort reads path into out; a missing file is not an error.
func readJSON(path string, out any) error {
	b, err := readFile(path)
	if err != nil {
		return err
	}
	if b == nil { // file didn’t exist
		return nil
	}
	return json.Unmarshal(b, out)
}

// readFile reads the file at path into b; a missing file is not an error.
func readFile(path string) ([]byte, error) {
	b, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return b, nil
}

// writeJSON writes JSON via a temp file then rename.
func writeJSON(path string, v any, mode os.FileMode) error {
	b, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return err
	}
	return writeFile(path, b, mode)
}

// writeFile writes bytes via a temp file, then atomically replaces the target.
func writeFile(path string, b []byte, mode os.FileMode) error {
	dir := filepath.Dir(path)
	base := filepath.Base(path)

	f, err := os.CreateTemp(dir, base+".tmp-*")
	if err != nil {
		return err
	}
	tmp := f.Name()

	// Best-effort cleanup if anything fails before rename.
	defer func() { _ = os.Remove(tmp) }()

	if _, err := f.Write(b); err != nil {
		_ = f.Close()
		return err
	}
	if err := f.Chmod(mode); err != nil {
		_ = f.Close()
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}

	return os.Rename(tmp, path)
}
