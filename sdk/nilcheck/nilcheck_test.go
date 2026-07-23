package nilcheck

import "testing"

type testInterface interface {
	testMarker()
}

func TestInterface(t *testing.T) {
	var nilInterface testInterface
	tests := []struct {
		name  string
		value any
		want  bool
	}{
		{name: "nil", value: nil, want: true},
		{name: "typed nil pointer", value: (*int)(nil), want: true},
		{name: "typed nil map", value: map[string]string(nil), want: true},
		{name: "typed nil slice", value: []string(nil), want: true},
		{name: "typed nil func", value: (func())(nil), want: true},
		{name: "typed nil interface", value: nilInterface, want: true},
		{name: "ordinary value", value: 1, want: false},
		{name: "non-nil pointer", value: new(int), want: false},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if got := Interface(test.value); got != test.want {
				t.Fatalf("Interface(%T) = %v; want %v", test.value, got, test.want)
			}
		})
	}
}
