package wireguard

import (
	"encoding/json"
	"fmt"
	"strings"
)

// AWGParams are the AmneziaWG obfuscation settings stored in hosts.params
// (RFC §3.4a): they live in [Interface] of every config of the host —
// berg side, proxer and consumer — and must match on all three.
type AWGParams struct {
	Jc          int    `json:"jc"`
	Jmin        int    `json:"jmin"`
	Jmax        int    `json:"jmax"`
	S1          int    `json:"s1"`
	S2          int    `json:"s2"`
	S3          int    `json:"s3"`
	H1          uint32 `json:"h1"`
	H2          uint32 `json:"h2"`
	H3          uint32 `json:"h3"`
	H4          uint32 `json:"h4"`
}

// DefaultAWGParams returns the fallback obfuscation applied when the
// owner creates an amneziawg host without explicit params. Values follow
// the upstream amnezia client defaults (jc=4, jmin=40, jmax=70, mixed
// junk/special/header bytes) so tunnels interop out of the box.
func DefaultAWGParams() AWGParams {
	return AWGParams{Jc: 4, Jmin: 40, Jmax: 70,
		S1: 88, S2: 21, S3: 171, H1: 5325, H2: 23, H3: 17, H4: 41}
}

// ParseAWGParams decodes hosts.params jsonb into AWGParams, filling
// every zero field with its default (partial overrides allowed) and
// validating the result. Empty/absent input = pure defaults.
func ParseAWGParams(raw []byte) (AWGParams, error) {
	p := DefaultAWGParams()
	if len(raw) == 0 || string(raw) == "{}" || string(raw) == "null" {
		return p, nil
	}
	var in AWGParams
	if err := json.Unmarshal(raw, &in); err != nil {
		return p, fmt.Errorf("awg params: %w", err)
	}
	// partial override: every zero field falls back to its default
	if in.Jc != 0 {
		p.Jc = in.Jc
	}
	if in.Jmin != 0 {
		p.Jmin = in.Jmin
	}
	if in.Jmax != 0 {
		p.Jmax = in.Jmax
	}
	if in.S1 != 0 {
		p.S1 = in.S1
	}
	if in.S2 != 0 {
		p.S2 = in.S2
	}
	if in.S3 != 0 {
		p.S3 = in.S3
	}
	if in.H1 != 0 {
		p.H1 = in.H1
	}
	if in.H2 != 0 {
		p.H2 = in.H2
	}
	if in.H3 != 0 {
		p.H3 = in.H3
	}
	if in.H4 != 0 {
		p.H4 = in.H4
	}
	if err := p.Validate(); err != nil {
		return AWGParams{}, err
	}
	return p, nil
}

// Validate checks the upstream amneziawg ranges: junk packet count,
// size window, special markers and header magic must stay inside the
// parser's limits or the kernel/userspace tool rejects the config.
func (p AWGParams) Validate() error {
	if p.Jc < 0 || p.Jc > 128 {
		return fmt.Errorf("jc must be 0..128")
	}
	if p.Jc > 0 { // obfuscation on: the whole window must be sane
		if p.Jmin < 40 || p.Jmin > 1280 {
			return fmt.Errorf("jmin must be 40..1280")
		}
		if p.Jmax < 50 || p.Jmax > 1280 {
			return fmt.Errorf("jmax must be 50..1280")
		}
		if p.Jmin >= p.Jmax {
			return fmt.Errorf("jmin must be < jmax")
		}
		for _, s := range []int{p.S1, p.S2, p.S3} {
			if s < 15 || s > 240 {
				return fmt.Errorf("s1/s2/s3 must be 15..240")
			}
		}
	}
	for _, h := range []uint32{p.H1, p.H2, p.H3, p.H4} {
		if h < 5 || h > 2147483647 {
			return fmt.Errorf("h1..h4 must be 5..2147483647")
		}
	}
	return nil
}

// Render emits the AWG [Interface] lines (Jc = ..., H4 = ...). Empty
// string when obfuscation is off (Jc = 0 degrades to plain wireguard
// crypto on the same binary), so configs stay valid wg-quick files.
func (p AWGParams) Render() string {
	var b strings.Builder
	fmt.Fprintf(&b, "Jc = %d\n", p.Jc)
	if p.Jc > 0 {
		fmt.Fprintf(&b, "Jmin = %d\nJmax = %d\n", p.Jmin, p.Jmax)
		fmt.Fprintf(&b, "S1 = %d\nS2 = %d\nS3 = %d\n", p.S1, p.S2, p.S3)
	}
	fmt.Fprintf(&b, "H1 = %d\nH2 = %d\nH3 = %d\nH4 = %d\n", p.H1, p.H2, p.H3, p.H4)
	return b.String()
}

// ToolName picks the userspace binary for a transport: amneziawg is a
// wireguard fork, so `awg` mirrors `wg` syntax 1:1 (setconf, syncconf,
// show) and awg-quick reuses the wg-quick layout.
func ToolName(transport string) string {
	if transport == "amneziawg" {
		return "awg"
	}
	return "wg"
}

// LinkType is the kernel interface type used at bring-up: the amnezia
// fork registers its own rtnl link kind (needs the amneziawg-dkms
// module; userspace amneziawg-go only exists on client sides).
func LinkType(transport string) string {
	if transport == "amneziawg" {
		return "amneziawg"
	}
	return "wireguard"
}