package h3dgram

import "testing"

// The same bytes as rust/trunk/src/h3dgram.rs
// the_token_is_hkdf_of_the_trunk_key, for the bench's key.
func TestTheTokenIsHKDFOfTheTrunkKey(t *testing.T) {
	tok, err := Token("bench-trunk-key-0123456789abcdef")
	if err != nil {
		t.Fatal(err)
	}
	const want = "Bearer 9b5a7e3dfd075ac568f49f6d67340c6271c816050041def9ae8bfdddf2e036d8"
	if got := Authorization(tok); got != want {
		t.Fatalf("authorization %s, want %s", got, want)
	}
}
