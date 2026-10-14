package constant

// MaccSalt is the build-time injected salt for the macc outbound protocol.
//
// Inject at build time (recommended):
//
//	go build -ldflags '-X "github.com/metacubex/mihomo/constant.MaccSalt=your-salt"'
//
// Evidence: identical mechanism observed in Mielink MaccCore (go1.24) and
// FlClashCore (go1.26) — error string "MaccSalt not set, please set
// MIHOMO_MACC_SALT at build time (recommended) or compile with -ldflags ...".
//
// The salt value itself is a per-build secret; it was NOT extracted from any
// binary during analysis (runtime-only, memory-wiped after reassembly in the
// Mielink variant).
var MaccSalt = ""
