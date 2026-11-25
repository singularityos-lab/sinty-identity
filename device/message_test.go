package device

import "testing"

func TestActs(t *testing.T) {
	cases := []struct {
		name string
		msg  []byte
		acts bool
	}{
		{"poll", PollMessage("https://id", "dev", 1), false},
		{"refusal", ApproveMessage("https://id", "a", "n", "it", "42", false), false},
		{"approval", ApproveMessage("https://id", "a", "n", "it", "42", true), true},
		{"enroll", EnrollMessage("https://id", "e", "dev"), true},
		{"revoke", RevokeMessage("https://id", "dev", 1), true},
		{"client name carrying a refusal", ApproveMessage("https://id", "a", "n", "it\ndeny", "42", true), true},
		{"poll with an extra line", append(PollMessage("https://id", "dev", 1), []byte("\nallow")...), true},
		{"not a message", []byte("hello"), true},
	}
	for _, c := range cases {
		if got := Acts(c.msg); got != c.acts {
			t.Errorf("%s: Acts = %v", c.name, got)
		}
	}
	if _, _, ok := Parse([]byte("sinty-identity poll v2\na\nb\nc")); ok {
		t.Error("another version parsed")
	}
}
