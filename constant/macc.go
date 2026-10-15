package constant

// MaccSalt is the third key-derivation input for the macc server-descriptor
// cipher: key = SHA256(candidate || protocol-param || MaccSalt).
//
// It is baked in so macc outbound nodes work out of the box:
//
//	var MaccSalt = "N8tY4q1xLk"
//
// It can still be overridden at build time for other deployments:
//
//	go build -ldflags '-X "github.com/metacubex/mihomo/constant.MaccSalt=<salt>"'
//
// Provenance: recovered from the reference cores (Mielink MaccCore — masked
// fragments A[perm]^B[perm]; FlClashCore — cleartext in .rdata). It is a
// protocol-wide constant shared by the whole macc ecosystem, not a per-user
// secret: it does not reveal node endpoints, which additionally require the
// encrypted descriptor blobs carried by a subscription (e.g.
// "doedge-<hex>.sev.cloudfront.net"), and those never appear in this repo.
var MaccSalt = "N8tY4q1xLk"