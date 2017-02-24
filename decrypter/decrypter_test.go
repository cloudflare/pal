package decrypter

import "testing"

func TestSplitPALValue(t *testing.T) {
	for line, expected := range map[string]struct {
		decrypterType string
		binary        bool
		value         string
	}{
		"asd":           {"", false, ""},
		"ro:asd":        {"ro", false, "asd"},
		"ro+base64:asd": {"ro", true, "asd"},
		"rotbase64:asd": {"rotbase64", false, "asd"},
	} {
		decrypterType, binary, value := SplitPALValue(line)
		if decrypterType != expected.decrypterType ||
			binary != expected.binary ||
			value != expected.value {
			t.Errorf("expected %+v, got type=%s, binary=%v, value=%v", expected,
				decrypterType, binary, value)
		}
	}
}
