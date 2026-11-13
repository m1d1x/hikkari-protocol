module github.com/m1d1x/hikkari-protocol/rust/bench/go

go 1.26.0

require github.com/m1d1x/hikkari-protocol/trunk v0.0.0

replace github.com/m1d1x/hikkari-protocol/trunk => ../../../trunk

require (
	github.com/m1d1x/hikkari-protocol/trunk/chromium v0.0.0
	github.com/sagernet/quic-go v0.61.0-sing-box-mod.9
)

require (
	github.com/andybalholm/brotli v1.0.6 // indirect
	github.com/ebitengine/purego v0.10.0 // indirect
	github.com/klauspost/compress v1.17.9 // indirect
	github.com/metacubex/utls v1.8.7 // indirect
	github.com/miekg/dns v1.1.72 // indirect
	github.com/quic-go/qpack v0.6.0 // indirect
	github.com/sagernet/cronet-go v0.0.0-20260912104727-0d28acc44093 // indirect
	github.com/sagernet/cronet-go/lib/darwin_arm64 v0.0.0-20260912104006-c10c03c318db // indirect
	github.com/sagernet/cronet-go/lib/linux_amd64 v0.0.0-20260912104006-c10c03c318db // indirect
	github.com/sagernet/cronet-go/lib/linux_arm64 v0.0.0-20260912104006-c10c03c318db // indirect
	github.com/sagernet/sing v0.8.9 // indirect
	golang.org/x/crypto v0.54.0 // indirect
	golang.org/x/exp v0.0.0-20240904232852-e7e105dedf7e // indirect
	golang.org/x/mod v0.37.0 // indirect
	golang.org/x/net v0.56.0 // indirect
	golang.org/x/sync v0.22.0 // indirect
	golang.org/x/sys v0.47.0 // indirect
	golang.org/x/text v0.40.0 // indirect
	golang.org/x/tools v0.47.0 // indirect
)

replace github.com/m1d1x/hikkari-protocol/trunk/chromium => ../../../trunk/chromium
