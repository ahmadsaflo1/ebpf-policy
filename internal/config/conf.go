package config

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"strings"

	"github.com/BurntSushi/toml"
)

// Load read configuration settings using;
// 1. a configuration file (optional).
// 2. container secrets when present
// 3. default values
// 4. env variable overrides
func Load(configFile string, settings *Settings, checkUnmatchedKeys bool) error {

	if configFile != "" {
		if !filepath.IsAbs(configFile) {
			configFile = filepath.Join(settings.AppDir, configFile)
		}
		if s, err := os.Stat(configFile); err != nil || !s.Mode().IsRegular() {
			return fmt.Errorf("failed to locate config: %s", configFile)
		}
		if err := processFile(configFile, settings, checkUnmatchedKeys); err != nil {
			return errors.Join(err, errors.New(configFile))
		}
	}

	// in a container we apply '/run/secrets/settings'
	if s, err := os.Stat("/run/secrets/settings"); err == nil && !s.IsDir() {
		if err := processFile("/run/secrets/settings", settings, false); err != nil {
			return errors.Join(err, fmt.Errorf("failed to parse container secrets"))
		}
	}

	if err := processDefault(settings); err != nil {
		return errors.Join(err, fmt.Errorf("failed to process config defaults"))
	}

	// override settings using env tags
	if err := processEnv(settings); err != nil {
		return errors.Join(err, fmt.Errorf("failed to process config env vars"))
	}

	return nil
}

// UnmatchedKeyError if config contains undefined settings/keys
type UnmatchedKeysError struct {
	Keys []toml.Key
}

func (e *UnmatchedKeysError) Error() string {
	return fmt.Sprintf("keys %v, not defined in settings", e.Keys)
}

func processFile(file string, settings any, errorOnUnmatchedKeys bool) error {
	data, err := os.ReadFile(file)
	if err != nil {
		return err
	}
	err = unmarshalToml(data, settings, errorOnUnmatchedKeys)
	if err != nil {
		return errors.Join(err, errors.New("unmarshalToml"))
	}
	return nil
}

func unmarshalToml(data []byte, settings any, errorOnUnmatchedKeys bool) error {
	metadata, err := toml.Decode(string(data), settings)
	if err == nil && len(metadata.Undecoded()) > 0 && errorOnUnmatchedKeys {
		return &UnmatchedKeysError{Keys: metadata.Undecoded()}
	}
	return err
}

func getPrefixForStruct(prefixes []string, fieldStruct *reflect.StructField) []string {
	if fieldStruct.Anonymous && fieldStruct.Tag.Get("anonymous") == "true" {
		return prefixes
	}
	return append(prefixes, fieldStruct.Name)
}

func processDefault(settings any) error {
	configValue := reflect.Indirect(reflect.ValueOf(settings))

	if configValue.Kind() != reflect.Struct {
		if configValue.Type().Name() == "" {
			return nil
		}
		return errors.New("invalid config '" + configValue.Type().Name() + "' should be struct")
	}

	configType := configValue.Type()
	for i := range configType.NumField() {
		var (
			fieldStruct = configType.Field(i)
			field       = configValue.Field(i)
		)

		if !field.CanAddr() || !field.CanInterface() {
			continue
		}

		// set a default value on any zero value setting.
		// Note that for booleans the zero value is false.
		if field.Kind() != reflect.Bool {
			if isBlank := reflect.DeepEqual(field.Interface(), reflect.Zero(field.Type()).Interface()); isBlank {
				// Set default configuration if blank
				if value := fieldStruct.Tag.Get("default"); value != "" {
					if err := json.Unmarshal([]byte(value), field.Addr().Interface()); err != nil {
						if field.CanSet() {
							field.SetString(value)
						} else {
							return errors.Join(err, fmt.Errorf("value: %v", value))
						}
					}
				}
			}
		}

		for field.Kind() == reflect.Pointer {
			field = field.Elem()
		}

		switch field.Kind() {
		case reflect.Struct:
			if err := processDefault(field.Addr().Interface()); err != nil {
				return err
			}
		case reflect.Slice:
			for i := 0; i < field.Len(); i++ {
				if reflect.Indirect(field.Index(i)).Kind() == reflect.Struct {
					if err := processDefault(field.Index(i).Addr().Interface()); err != nil {
						return err
					}
				}
			}
		}
	}

	return nil
}

func processEnv(settings any, prefixes ...string) error {

	configValue := reflect.Indirect(reflect.ValueOf(settings))
	if configValue.Kind() != reflect.Struct {
		return nil
	}

	configType := configValue.Type()
	for i := 0; i < configType.NumField(); i++ {
		var (
			envNames    []string
			fieldStruct = configType.Field(i)
			field       = configValue.Field(i)
		)

		if !field.CanAddr() || !field.CanInterface() {
			continue
		}

		if name := fieldStruct.Tag.Get("env"); name != "" {
			envNames = append(envNames, name)
		}

		// Getenv settings
		for _, env := range envNames {
			if value := os.Getenv(env); value != "" {
				switch reflect.Indirect(field).Kind() {
				case reflect.Bool:
					switch strings.ToLower(value) {
					case "", "0", "f", "false", "FALSE":
						field.Set(reflect.ValueOf(false))
					case "1", "t", "true", "TRUE":
						field.Set(reflect.ValueOf(true))
					}
				case reflect.String:
					field.Set(reflect.ValueOf(value))
				default:
					if err := json.Unmarshal([]byte(value), field.Addr().Interface()); err != nil {
						return errors.Join(err, fmt.Errorf("env: %s", env))
					}
				}
				break
			}
		}

		if isBlank := reflect.DeepEqual(field.Interface(), reflect.Zero(field.Type()).Interface()); isBlank && fieldStruct.Tag.Get("required") == "true" {
			// returns error if setting is required but set to zero-value
			return errors.New(fieldStruct.Name + " is required but not set")
		}

		for field.Kind() == reflect.Pointer {
			field = field.Elem()
		}

		if field.Kind() == reflect.Struct {
			if err := processEnv(field.Addr().Interface(), getPrefixForStruct(prefixes, &fieldStruct)...); err != nil {
				return err
			}
		}

		if field.Kind() == reflect.Slice {
			if arrLen := field.Len(); arrLen > 0 {
				for i := range arrLen {
					if reflect.Indirect(field.Index(i)).Kind() == reflect.Struct {
						err := processEnv(field.Index(i).Addr().Interface(),
							append(getPrefixForStruct(prefixes, &fieldStruct), fmt.Sprint(i))...)

						if err != nil {
							return err
						}
					}
				}
			} else {
				defer func(field reflect.Value, fieldStruct reflect.StructField) error {
					if !configValue.IsZero() {
						// load slice from env
						newVal := reflect.New(field.Type().Elem()).Elem()
						if newVal.Kind() == reflect.Struct {
							idx := 0
							for {
								newVal = reflect.New(field.Type().Elem()).Elem()
								err := processEnv(newVal.Addr().Interface(),
									append(getPrefixForStruct(prefixes, &fieldStruct), fmt.Sprint(idx))...)

								if err != nil {
									return err
								}

								if reflect.DeepEqual(newVal.Interface(), reflect.New(field.Type().Elem()).Elem().Interface()) {
									break
								}

								idx++
								field.Set(reflect.Append(field, newVal))
							}
						}
					}
					return nil
				}(field, fieldStruct)
			}
		}
	}
	return nil
}
