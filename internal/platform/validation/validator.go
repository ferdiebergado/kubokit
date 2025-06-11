package validation

// Validator defines the interface that needs to be implemented by all validation strategies.
type Validator interface {
	ValidateStruct(s any) map[string]string
}
