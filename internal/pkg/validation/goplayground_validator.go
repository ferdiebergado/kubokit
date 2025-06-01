package validation

import (
	"errors"
	"fmt"
	"reflect"
	"strings"

	"github.com/go-playground/validator/v10"
)

type GoPlaygroundValidator struct {
	v *validator.Validate
}

func NewGoPlaygroundValidator() *GoPlaygroundValidator {
	v := validator.New()

	// register function to get tag name from json tags.
	v.RegisterTagNameFunc(func(fld reflect.StructField) string {
		name := strings.SplitN(fld.Tag.Get("json"), ",", 2)[0]
		if name == "-" {
			return ""
		}
		return name
	})

	return &GoPlaygroundValidator{
		v: v,
	}
}

func (va *GoPlaygroundValidator) ValidateStruct(s any) map[string]string {
	err := va.v.Struct(s)
	if err == nil {
		return nil
	}

	var valErrs validator.ValidationErrors
	if !errors.As(err, &valErrs) {
		return nil
	}

	errMap := make(map[string]string, len(valErrs))
	for _, e := range valErrs {
		errMap[e.Field()] = validationMessage(e)
	}

	return errMap
}

func validationMessage(e validator.FieldError) string {
	switch e.Tag() {
	case "required":
		return fmt.Sprintf("%s is required", e.Field())
	case "email":
		return fmt.Sprintf("%s must be a valid email address", e.Field())
	case "min":
		return fmt.Sprintf("%s must be at least %s characters long", e.Field(), e.Param())
	case "max":
		return fmt.Sprintf("%s must be at most %s characters long", e.Field(), e.Param())
	case "len":
		return fmt.Sprintf("%s must be exactly %s characters long", e.Field(), e.Param())
	case "gte":
		return fmt.Sprintf("%s must be greater than or equal to %s", e.Field(), e.Param())
	case "lte":
		return fmt.Sprintf("%s must be less than or equal to %s", e.Field(), e.Param())
	case "numeric":
		return fmt.Sprintf("%s must be a number", e.Field())
	case "alpha":
		return fmt.Sprintf("%s must contain only letters", e.Field())
	case "alphanum":
		return fmt.Sprintf("%s must contain only letters and numbers", e.Field())
	case "eqfield":
		return fmt.Sprintf("%s should match %s", e.Field(), e.Param())
	default:
		return fmt.Sprintf("%s is invalid", e.Field())
	}
}
