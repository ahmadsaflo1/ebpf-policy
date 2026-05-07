package config

import (
	"os"
	"path/filepath"
)

func New(configFile string) (*Settings, error) {
	settings := &Settings{}

	// get our base directory
	if dir, err := os.Executable(); err == nil {
		settings.AppDir = filepath.Dir(dir)
	}

	if err := Load(configFile, settings, true); err != nil {
		return nil, err
	}

	if settings.TmpDir == "" {
		settings.TmpDir = os.TempDir()
	}

	return settings, nil
}
