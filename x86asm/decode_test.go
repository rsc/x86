// Copyright 2014 The Go Authors.  All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package x86asm

import (
	"encoding/hex"
	"io/ioutil"
	"strings"
	"testing"
)

func TestDecode(t *testing.T) {
	data, err := ioutil.ReadFile("testdata/decode.txt")
	if err != nil {
		t.Fatal(err)
	}
	all := string(data)
	for strings.Contains(all, "\t\t") {
		all = strings.Replace(all, "\t\t", "\t", -1)
	}
	for _, line := range strings.Split(all, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		f := strings.SplitN(line, "\t", 3)
		i := strings.Index(f[0], "|")
		if i < 0 {
			t.Errorf("parsing %q: missing | separator", f[0])
			continue
		}
		if i%2 != 0 {
			t.Errorf("parsing %q: misaligned | separator", f[0])
		}
		size := i / 2
		code, err := hex.DecodeString(f[0][:i] + f[0][i+1:])
		if err != nil {
			t.Errorf("parsing %q: %v", f[0], err)
			continue
		}
		syntax, asm := f[1], f[2]
		inst, instSize, err := Decode(code, 32)
		var out string
		if err != nil {
			out = "error: " + err.Error()
		} else {
			switch syntax {
			case "gnu":
				out = GNUSyntax(inst)
			case "intel":
				out = IntelSyntax(inst)
			default:
				t.Errorf("unknown syntax %q", syntax)
				continue
			}
		}
		if out != asm || instSize != size {
			t.Errorf("Decode(%s) [%s] = %s, %d, want %s, %d", f[0], syntax, out, instSize, asm, size)
		}
	}
}
