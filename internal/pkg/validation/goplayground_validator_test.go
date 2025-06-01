package validation_test

import (
	"testing"

	"github.com/ferdiebergado/kubokit/internal/pkg/validation"
)

func TestGoplaygroundValidator_ValidateStruct(t *testing.T) {
	var tests = []struct {
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
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			v := validation.NewGoPlaygroundValidator()

			errs := v.ValidateStruct(tt.given)
			if errs != nil && !tt.hasError {
				t.Errorf("\ngot: %v\nwant: nil", errs)
			}

			gotMsg, wantMsg := errs[tt.field], tt.errMsg
			if gotMsg != wantMsg {
				t.Errorf("\ngot: %s\n want: %s", wantMsg, gotMsg)
			}
		})
	}
}
