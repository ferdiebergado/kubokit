package validation

type StubValidator struct {
	ValidateStructFunc func(any) map[string]string
}

func (s *StubValidator) ValidateStruct(st any) map[string]string {
	if s.ValidateStructFunc == nil {
		panic("ValidateStruct not implemented by stub")
	}
	return s.ValidateStructFunc(st)
}
