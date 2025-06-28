package validation_test

import (
	"testing"

	"github.com/ferdiebergado/kubokit/internal/platform/validation"
)

func TestGoplaygroundValidator_ValidateStruct(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		given    any
		field    string
		hasError bool
		errMsg   string
	}{
		{"Required field is present", struct {
			Name string `validate:"required"`
		}{Name: "Antonio"}, "Name", false, ""},
		{"Required field is missing", struct {
			Name string `validate:"required"`
		}{}, "Name", true, "Name is required"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			v := validation.NewGoPlaygroundValidator()

			errs := v.ValidateStruct(tc.given)
			if errs != nil && !tc.hasError {
				t.Errorf("v.ValidateStruct(%v) = %+v, want: %+v", tc.given, errs, nil)
			}

			gotMsg, wantMsg := errs[tc.field], tc.errMsg
			if gotMsg != wantMsg {
				t.Errorf("errs[%q] = %q, want: %q", tc.field, wantMsg, gotMsg)
			}
		})
	}
}
