module github.com/m1d1x/hikkari-protocol/trunk/quicwire

go 1.26.0

require (
	github.com/m1d1x/hikkari-protocol v0.0.0
	github.com/m1d1x/hikkari-protocol/trunk v0.0.0
	github.com/sagernet/sing v0.9.7-0.20260929150544-0ad23b637bd4
)

require (
	github.com/andybalholm/brotli v1.0.6 // indirect
	github.com/klauspost/compress v1.19.1 // indirect
	github.com/metacubex/utls v1.8.7 // indirect
	github.com/quic-go/qpack v0.6.0 // indirect
	github.com/sagernet/quic-go v0.61.0-sing-box-mod.9 // indirect
	github.com/sagernet/sing-quic v0.7.2-0.20261002084117-75c3ac4fa12b // indirect
	golang.org/x/crypto v0.54.0 // indirect
	golang.org/x/exp v0.0.0-20260410095643-746e56fc9e2f // indirect
	golang.org/x/net v0.57.0 // indirect
	golang.org/x/sys v0.47.0 // indirect
	golang.org/x/text v0.40.0 // indirect
)

// Built from this repository until both are tagged together; a consumer
// pins them by pseudo-version.
replace (
	github.com/m1d1x/hikkari-protocol => ../..
	github.com/m1d1x/hikkari-protocol/trunk => ..
)
