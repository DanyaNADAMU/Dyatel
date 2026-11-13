package wireguard

import (
	"strings"
	"testing"
)

func TestParseAWGParamsDefaults(t *testing.T) {
	for _, raw := range [][]byte{nil, []byte(`{}`), []byte(`null`)} {
		p, err := ParseAWGParams(raw)
		if err != nil {
			t.Fatalf("ParseAWGParams(%q): %v", raw, err)
		}
		if p.Jc != 4 || p.Jmin != 40 || p.Jmax != 70 {
			t.Fatalf("defaults wrong: %+v", p)
		}
	}
}

func TestParseAWGParamsPartialOverride(t *testing.T) {
	// only Jc overridden: the rest fall back to defaults
	p, err := ParseAWGParams([]byte(`{"jc":8}`))
	if err != nil {
		t.Fatal(err)
	}
	if p.Jc != 8 || p.Jmin != 40 || p.H4 != 41 {
		t.Fatalf("partial override wrong: %+v", p)
	}
}

func TestParseAWGParamsFullOverride(t *testing.T) {
	raw := `{"jc":10,"jmin":50,"jmax":100,"s1":100,"s2":101,"s3":102,"h1":9,"h2":10,"h3":11,"h4":12}`
	p, err := ParseAWGParams([]byte(raw))
	if err != nil {
		t.Fatal(err)
	}
	if p.Jc != 10 || p.H1 != 9 || p.S3 != 102 {
		t.Fatalf("full override wrong: %+v", p)
	}
}

func TestParseAWGParamsInvalid(t *testing.T) {
	for name, raw := range map[string]string{
		"bad json":     `{jc:4}`,
		"jc too big":   `{"jc":1000}`,
		"jmin window":  `{"jc":4,"jmin":10}`,
		"jmin>=jmax":   `{"jc":4,"jmin":80,"jmax":70}`,
		"s out of rng": `{"jc":4,"s1":5}`,
		"h too small":  `{"h1":1}`,
		"wrong type":   `{"jc":"four"}`,
	} {
		if _, err := ParseAWGParams([]byte(raw)); err == nil {
			t.Errorf("%s: expected error for %s", name, raw)
		}
	}
}

func TestAWGParamsRenderOff(t *testing.T) {
	// Jc = 0 degrades to plain wireguard crypto: no junk-size lines
	p := AWGParams{Jc: 0, H1: 5, H2: 6, H3: 7, H4: 8}
	out := p.Render()
	if strings.Contains(out, "Jmin") || strings.Contains(out, "S1") {
		t.Fatalf("obfuscation off must not render junk/special lines: %q", out)
	}
	if !strings.Contains(out, "H1 = 5") {
		t.Fatalf("header magic must survive: %q", out)
	}
}

func TestAWGParamsRenderOn(t *testing.T) {
	out := DefaultAWGParams().Render()
	for _, want := range []string{
		"Jc = 4", "Jmin = 40", "Jmax = 70",
		"S1 = 88", "S2 = 21", "S3 = 171",
		"H1 = 5325", "H2 = 23", "H3 = 17", "H4 = 41",
	} {
		if !strings.Contains(out, want) {
			t.Fatalf("missing %q in:\n%s", want, out)
		}
	}
}

func TestToolNameAndLinkType(t *testing.T) {
	if ToolName("amneziawg") != "awg" || ToolName("wireguard") != "wg" {
		t.Fatal("ToolName dispatch wrong")
	}
	if LinkType("amneziawg") != "amneziawg" || LinkType("wireguard") != "wireguard" {
		t.Fatal("LinkType dispatch wrong")
	}
}
