//go:build with_purego

package chromium

import "github.com/sagernet/cronet-go"

// Load finds and loads libcronet (the executable's directory, then
// LD_LIBRARY_PATH, /usr/local/lib, /usr/lib). Call it before the first Dial:
// without it a missing library is a panic inside cronet, not an error.
func Load() error { return cronet.LoadLibrary("") }
