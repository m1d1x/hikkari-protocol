//go:build !with_purego

package chromium

// Load is nothing to do: libcronet is linked in.
func Load() error { return nil }
