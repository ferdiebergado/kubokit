package error

import (
	"context"
	"errors"
)

func IsContextError(err error) bool {
	ctxErrs := []error{context.Canceled, context.DeadlineExceeded}
	for _, ctxErr := range ctxErrs {
		if errors.Is(err, ctxErr) {
			return true
		}
	}

	return false
}
