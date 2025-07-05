package env

import (
	"bufio"
	"fmt"
	"log/slog"
	"os"
	"reflect"
	"strconv"
	"strings"
)

// Load reads environment variables from the specified envFile and sets them in the process environment.
// Each line in the file should be in the format KEY=VALUE. Lines that are empty or start with '#' are ignored as comments.
// Inline comments (after a '#') are also removed. Values surrounded by double quotes will have the quotes stripped.
// If a line is not in the correct format, a warning is logged and the line is skipped.
// Returns an error if the file cannot be opened, if setting an environment variable fails, or if a scanning error occurs.
func Load(envFile string) error {
	slog.Info("Loading environment file", "file", envFile)

	file, err := os.Open(envFile)
	if err != nil {
		return fmt.Errorf("open env file %s: %w", envFile, err)
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	lineNum := 0

	for scanner.Scan() {
		lineNum++
		line := scanner.Text()

		// Skip empty lines and comments
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		// Remove inline comments
		if commentIdx := strings.Index(line, "#"); commentIdx != -1 {
			line = line[:commentIdx]
		}

		// Split the line into key and value
		parts := strings.SplitN(line, "=", 2)
		if len(parts) != 2 {
			slog.Warn("Invalid line format", "file", envFile, "line", lineNum)
			continue
		}

		key := strings.TrimSpace(parts[0])
		value := strings.TrimSpace(parts[1])

		// Remove quotes around value if present
		if len(value) > 1 && value[0] == '"' && value[len(value)-1] == '"' {
			value = value[1 : len(value)-1]
		}

		// Set the environment variable
		if err := os.Setenv(key, value); err != nil {
			return fmt.Errorf("os setenv: %w", err)
		}
	}

	if err := scanner.Err(); err != nil {
		return fmt.Errorf("scanner: %w", err)
	}

	slog.Info("Environment file loaded successfully", "file", envFile)
	return nil
}

// OverrideStruct populates the struct fields with values from environment variables
// based on the 'env' custom tag, recursively handling nested structs.
func OverrideStruct(v any) error {
	val := reflect.ValueOf(v)
	val = dereferencePointer(val)
	if val.Kind() != reflect.Struct {
		return fmt.Errorf("LoadFromEnv expects a struct or a pointer to a struct, got %T (%s)", v, val.Kind())
	}
	typ := val.Type()
	for i := 0; i < typ.NumField(); i++ {
		field := typ.Field(i)
		fieldValue := val.Field(i)
		if handled, err := handleNestedStruct(&field, &fieldValue); handled {
			if err != nil {
				return err
			}
			continue
		}
		if err := setFieldFromEnv(&field, &fieldValue); err != nil {
			return err
		}
	}
	return nil
}

func dereferencePointer(val reflect.Value) reflect.Value {
	if val.Kind() == reflect.Ptr {
		if val.IsNil() {
			newVal := reflect.New(val.Type().Elem())
			val.Set(newVal)
			val = newVal
		}
		val = val.Elem()
	}
	return val
}

func handleNestedStruct(field *reflect.StructField, fieldValue *reflect.Value) (bool, error) {
	if fieldValue.Kind() == reflect.Struct {
		if fieldValue.CanAddr() {
			if err := OverrideStruct(fieldValue.Addr().Interface()); err != nil {
				return true, fmt.Errorf("error loading nested struct %s: %w", field.Name, err)
			}
		} else {
			slog.Warn("Warning: Cannot address nested struct field for recursive loading.", "field", field.Name)
		}
		return true, nil
	}
	if fieldValue.Kind() == reflect.Ptr && fieldValue.Type().Elem().Kind() == reflect.Struct {
		if fieldValue.IsNil() {
			fieldValue.Set(reflect.New(fieldValue.Type().Elem()))
		}
		if err := OverrideStruct(fieldValue.Interface()); err != nil {
			return true, fmt.Errorf("error loading nested pointer struct %s: %w", field.Name, err)
		}
		return true, nil
	}
	return false, nil
}

func setFieldFromEnv(field *reflect.StructField, fieldValue *reflect.Value) error {
	envVarName := field.Tag.Get("env")
	if envVarName == "" {
		return nil
	}
	envVarValue := os.Getenv(envVarName)
	if envVarValue == "" {
		slog.Warn("Environment variable not set for field", "env", envVarName, "field", field.Name)
		return nil
	}
	if !fieldValue.CanSet() {
		slog.Warn("Field cannot be set directly (e.g., unexported, complex type not handled).", "field", field.Name)
		return nil
	}
	switch fieldValue.Kind() {
	case reflect.String:
		fieldValue.SetString(envVarValue)
	case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64:
		intValue, err := strconv.ParseInt(envVarValue, 10, 64)
		if err != nil {
			return fmt.Errorf("failed to parse int for field %s from env var %s: %w", field.Name, envVarName, err)
		}
		fieldValue.SetInt(intValue)
	case reflect.Bool:
		boolValue, err := strconv.ParseBool(envVarValue)
		if err != nil {
			return fmt.Errorf("failed to parse bool for field %s from env var %s: %w", field.Name, envVarName, err)
		}
		fieldValue.SetBool(boolValue)
	// Add more cases for other types (float, uint, etc.) as needed
	default:
		return fmt.Errorf("unsupported field type %s for field %s (env var: %s)", fieldValue.Kind(), field.Name, envVarName)
	}
	return nil
}

// Env returns the value of the environment variable named by the key.
// If the variable is not present in the environment, it returns the provided fallback value.
func Env(key, fallback string) string {
	if val, ok := os.LookupEnv(key); ok {
		return val
	}
	return fallback
}
