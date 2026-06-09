package isobox

import (
	"crypto/sha256"
	"encoding/hex"
	"hash"
	"io"
	"strconv"
)

func stableSpecID(prefix string, s Spec) string {
	h := sha256.New()
	writeHashString(h, prefix)
	writeHashSlice(h, s.Args)
	writeHashString(h, s.Dir)
	writeHashSlice(h, s.Env)
	writeHashSlice(h, s.EnvAllow)
	writeHashSlice(h, s.EnvDeny)
	writeHashString(h, s.Net.String())
	writeHashString(h, s.Write.String())
	writeHashSlice(h, s.Writable)
	writeHashSlice(h, s.Readable)
	writeHashBool(h, s.NoExec)
	writeHashBool(h, s.AllowTemp)
	return prefix + "-" + hex.EncodeToString(h.Sum(nil))[:16]
}

func writeHashSlice(h hash.Hash, values []string) {
	writeHashString(h, strconv.Itoa(len(values)))
	for _, v := range values {
		writeHashString(h, v)
	}
}

func writeHashString(h hash.Hash, value string) {
	_, _ = io.WriteString(h, value)
	_, _ = h.Write([]byte{0})
}

func writeHashBool(h hash.Hash, value bool) {
	if value {
		writeHashString(h, "1")
		return
	}
	writeHashString(h, "0")
}
