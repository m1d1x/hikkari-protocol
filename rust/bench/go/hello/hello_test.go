package hello

import (
	"bytes"
	"os"
	"testing"
)

// The hk the client's release test recorded for these hellos
// (hikkari-client diagnostics testdata/hello/reference.json): the copy
// names a hello as the original does.
func TestTheCopyNamesHellosAsTheClientDoes(t *testing.T) {
	for file, want := range map[string]string{"tls-chrome": "h1e431ec7444af069a", "tls-go": "h11c409d9ffa0e9507"} {
		msg, err := os.ReadFile("testdata/" + file + ".bin")
		if err != nil {
			t.Fatal(err)
		}
		hk, _, err := Names(msg)
		if err != nil || hk != want {
			t.Errorf("%s: hk %s (%v), the client's %s", file, hk, err, want)
		}
	}
}

// A hello split over two records reads back whole.
func TestReadJoinsAHelloSplitOverRecords(t *testing.T) {
	msg, err := os.ReadFile("testdata/tls-chrome.bin")
	if err != nil {
		t.Fatal(err)
	}
	var wire bytes.Buffer
	for _, part := range [][]byte{msg[:100], msg[100:]} {
		wire.Write([]byte{22, 3, 1, byte(len(part) >> 8), byte(len(part))})
		wire.Write(part)
	}
	got, err := Read(&wire)
	if err != nil || !bytes.Equal(got, msg) {
		t.Fatalf("read %d bytes (%v), sent %d", len(got), err, len(msg))
	}
}
