package plugin

import "testing"

// The panel shows a credential's label; without an alias that label is the key
// masked as first4...last4 (the same rule the Qwen plugin uses).
func TestMaskAPIKeyFormat(t *testing.T) {
	cases := map[string]string{
		"":                    "",
		"a":                   "...",
		"ab":                  "a...b",
		"dummy-a":             "d...a",
		"dummy-key":           "du...ey",
		"sk-oc-abc":           "sk...bc",
		"dummy-panel-key":     "dumm...-key",
		"sk-oc-0123456789abc": "sk-o...9abc",
	}
	for in, want := range cases {
		if got := maskAPIKey(in); got != want {
			t.Fatalf("maskAPIKey(%q) = %q, want %q", in, got, want)
		}
	}
	if masked := maskAPIKey("sk-oc-0123456789abcdefghij"); len(masked) > 11 {
		t.Fatalf("mask too long: %q", masked)
	}
}

// A masked label must not leak into the auth file name.
func TestFileNameAliasKeepsKeyOutOfName(t *testing.T) {
	key := "sk-oc-personal-0123456789"
	if got := fileNameAlias(maskAPIKey(key), key); got != "OpenCode Go" {
		t.Fatalf("masked label should use the plugin prefix: %q", got)
	}
	if got := fileNameAlias("Personal", key); got != "Personal" {
		t.Fatalf("alias should name the file: %q", got)
	}
}
