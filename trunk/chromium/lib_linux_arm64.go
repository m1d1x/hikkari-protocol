//go:build linux && arm64 && !android

package chromium

import lib "github.com/sagernet/cronet-go/lib/linux_arm64"

const chromiumVersion = lib.Version
