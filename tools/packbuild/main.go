// Command packbuild assembles, validates, signs, and verifies assessment rule
// packs from the files in this repository.
//
//	go run ./tools/packbuild build  [-out dist/rules-pack.json]
//	go run ./tools/packbuild sign   [-in dist/rules-pack.json]   (key in RULES_SIGNING_KEY)
//	go run ./tools/packbuild verify [-in dist/rules-pack.json] -pub <base64 public key>
//	go run ./tools/packbuild diff   -old previous.json -new dist/rules-pack.json
//	go run ./tools/packbuild version
package main

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"
)

// pack mirrors the application's schema 1. The application validates again
// when it loads a pack; this catches mistakes before a release.
type pack struct {
	Manifest          manifest              `json:"manifest"`
	VSphere           []json.RawMessage     `json:"vsphere_lifecycle"`
	GuestOS           guestOS               `json:"guest_os_lifecycle"`
	CPUGenerations    []cpuGen              `json:"cpu_generations"`
	CPUSupport        cpuSupport            `json:"cpu_support"`
	Advisories        []advisory            `json:"firmware_advisories"`
	HardwareLifecycle []json.RawMessage     `json:"hardware_lifecycle"`
	Thresholds        map[string]float64    `json:"thresholds"`
	Rules             map[string]ruleConfig `json:"rules"`
	Changelog         string                `json:"changelog,omitempty"`
}

type manifest struct {
	Version     string `json:"version"`
	Schema      int    `json:"schema"`
	MinApp      string `json:"min_app,omitempty"`
	Published   string `json:"published"`
	Description string `json:"description,omitempty"`
}

type guestOS struct {
	Exclude []string `json:"exclude"`
	Entries []struct {
		Label        string `json:"label"`
		Pattern      string `json:"pattern"`
		EndOfSupport string `json:"end_of_support"`
		Source       string `json:"source,omitempty"`
	} `json:"entries"`
}

type cpuGen struct {
	Code   string `json:"code"`
	Name   string `json:"name"`
	Vendor string `json:"vendor"`
	Launch int    `json:"launch"`
}

type cpuSupport struct {
	UnsupportedESXi8 []string `json:"unsupported_esxi8"`
	Deprecated       []string `json:"deprecated"`
}

type advisory struct {
	ID        string   `json:"id"`
	Name      string   `json:"name"`
	CVEs      []string `json:"cves"`
	Note      string   `json:"note,omitempty"`
	Families  []string `json:"families,omitempty"`
	Disclosed string   `json:"disclosed"`
	URL       string   `json:"url,omitempty"`
}

type ruleConfig struct {
	Name           string `json:"name"`
	Category       string `json:"category,omitempty"`
	Enabled        *bool  `json:"enabled,omitempty"`
	Severity       string `json:"severity,omitempty"`
	Horizon        string `json:"horizon,omitempty"`
	Title          string `json:"title,omitempty"`
	Impact         string `json:"impact,omitempty"`
	Recommendation string `json:"recommendation,omitempty"`
}

var (
	reVersion = regexp.MustCompile(`^R(\d{4})\.(\d{2})\.(\d{2})\.(\d+)$`)
	reCVE     = regexp.MustCompile(`^CVE-\d{4}-\d{4,}$`)
	reAppVer  = regexp.MustCompile(`^\d{2}\.\d{1,2}\.\d{3}$`)
	required  = []string{
		"vcpu_per_core_warn", "vcpu_per_core_high", "mem_alloc_warn_pct", "host_cpu_hot_pct", "host_mem_hot_pct",
		"ds_warn_pct", "ds_crit_pct", "ds_overprov_pct", "snap_age_warn_days", "snap_age_high_days",
		"snap_size_high_gib", "min_hw_version", "guest_free_warn_pct", "rightsize_active_pct", "rightsize_min_mem_gib",
	}
)

func main() {
	if len(os.Args) < 2 {
		fail("usage: packbuild build|sign|verify|diff|version [flags]")
	}
	cmd, args := os.Args[1], os.Args[2:]
	fs := flag.NewFlagSet(cmd, flag.ExitOnError)
	out := fs.String("out", "dist/rules-pack.json", "output pack")
	in := fs.String("in", "dist/rules-pack.json", "input pack")
	pub := fs.String("pub", "", "base64 ed25519 public key")
	oldPath := fs.String("old", "", "previous pack")
	newPath := fs.String("new", "dist/rules-pack.json", "new pack")
	fs.Parse(args)
	switch cmd {
	case "build":
		build(*out)
	case "sign":
		sign(*in)
	case "verify":
		verify(*in, *pub)
	case "diff":
		diff(*oldPath, *newPath)
	case "version":
		var m manifest
		readJSON("manifest.json", &m)
		fmt.Println(m.Version)
	default:
		fail("unknown command " + cmd)
	}
}

func fail(msg string) {
	fmt.Fprintln(os.Stderr, "packbuild:", msg)
	os.Exit(1)
}

func readJSON(path string, v any) {
	b, err := os.ReadFile(path)
	if err != nil {
		fail(err.Error())
	}
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.DisallowUnknownFields()
	if err := dec.Decode(v); err != nil {
		fail(path + ": " + err.Error())
	}
}

func build(out string) {
	var p pack
	readJSON("manifest.json", &p.Manifest)
	readJSON("data/vsphere-lifecycle.json", &p.VSphere)
	readJSON("data/guest-os-lifecycle.json", &p.GuestOS)
	readJSON("data/cpu-generations.json", &p.CPUGenerations)
	readJSON("data/cpu-support.json", &p.CPUSupport)
	readJSON("data/firmware-advisories.json", &p.Advisories)
	readJSON("data/hardware-lifecycle.json", &p.HardwareLifecycle)
	readJSON("thresholds.json", &p.Thresholds)
	readJSON("rules.json", &p.Rules)
	if p.HardwareLifecycle == nil {
		p.HardwareLifecycle = []json.RawMessage{}
	}
	cl, err := os.ReadFile("RULES-CHANGELOG.md")
	if err != nil {
		fail(err.Error())
	}
	p.Changelog = strings.ReplaceAll(string(cl), "\r\n", "\n")
	if errs := validate(&p); len(errs) > 0 {
		for _, e := range errs {
			fmt.Fprintln(os.Stderr, "  -", e)
		}
		fail(fmt.Sprintf("%d problem(s); the pack was not built", len(errs)))
	}
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	enc.SetIndent("", " ")
	if err := enc.Encode(p); err != nil {
		fail(err.Error())
	}
	if err := os.MkdirAll(filepath.Dir(out), 0o755); err != nil {
		fail(err.Error())
	}
	if err := os.WriteFile(out, buf.Bytes(), 0o644); err != nil {
		fail(err.Error())
	}
	sum := sha256.Sum256(buf.Bytes())
	fmt.Printf("built %s: %s, %d rules, %d firmware advisories, %d guest OS entries, sha256 %s\n",
		out, p.Manifest.Version, len(p.Rules), len(p.Advisories), len(p.GuestOS.Entries), hex.EncodeToString(sum[:]))
}

func validate(p *pack) []string {
	var errs []string
	add := func(f string, a ...any) { errs = append(errs, fmt.Sprintf(f, a...)) }
	date := func(what, s string) {
		if _, err := time.Parse("2006-01-02", s); err != nil {
			add("%s: date %q must be YYYY-MM-DD", what, s)
		}
	}
	m := p.Manifest
	if !reVersion.MatchString(m.Version) {
		add("manifest.version %q must look like R2026.10.06.1", m.Version)
	}
	if m.Schema != 1 {
		add("manifest.schema must be 1 (this tool builds schema 1)")
	}
	if m.MinApp != "" && !reAppVer.MatchString(m.MinApp) {
		add("manifest.min_app %q must look like 26.10.001", m.MinApp)
	}
	date("manifest.published", m.Published)
	for _, raw := range p.VSphere {
		var v struct {
			Version string `json:"version"`
			EOGS    string `json:"end_of_general_support"`
		}
		json.Unmarshal(raw, &v)
		if v.Version == "" {
			add("vsphere_lifecycle: entry without a version")
		}
		date("vsphere_lifecycle "+v.Version, v.EOGS)
	}
	for _, e := range p.GuestOS.Entries {
		if _, err := regexp.Compile(e.Pattern); err != nil {
			add("guest OS %q: pattern: %v", e.Label, err)
		}
		if e.Pattern != strings.ToLower(e.Pattern) {
			add("guest OS %q: patterns match lowercased names, so write them in lowercase", e.Label)
		}
		date("guest OS "+e.Label, e.EndOfSupport)
	}
	codes := map[string]bool{}
	for _, c := range p.CPUGenerations {
		if c.Code == "" || c.Name == "" || c.Launch < 1990 {
			add("cpu_generations: %q needs a code, name, and launch year", c.Code)
		}
		codes[c.Code] = true
	}
	for _, c := range append(append([]string{}, p.CPUSupport.UnsupportedESXi8...), p.CPUSupport.Deprecated...) {
		if !codes[c] {
			add("cpu_support: unknown CPU generation %q", c)
		}
	}
	ids := map[string]bool{}
	for _, a := range p.Advisories {
		if a.ID == "" || a.Name == "" {
			add("firmware advisory %q needs an id and name", a.ID)
		}
		if ids[a.ID] {
			add("firmware advisory %q is listed twice", a.ID)
		}
		ids[a.ID] = true
		if len(a.CVEs) == 0 {
			add("firmware advisory %q has no CVEs", a.ID)
		}
		for _, c := range a.CVEs {
			if !reCVE.MatchString(c) {
				add("firmware advisory %q: %q is not a CVE ID", a.ID, c)
			}
		}
		for _, f := range a.Families {
			if !codes[f] {
				add("firmware advisory %q: unknown CPU generation %q", a.ID, f)
			}
		}
		date("firmware advisory "+a.ID, a.Disclosed)
	}
	for _, raw := range p.HardwareLifecycle {
		var h struct {
			Model, EndOfSale, EndOfSupport string
		}
		var hh map[string]string
		json.Unmarshal(raw, &hh)
		h.Model, h.EndOfSale, h.EndOfSupport = hh["model"], hh["end_of_sale"], hh["end_of_support"]
		if h.Model == "" {
			add("hardware_lifecycle: entry without a model")
		}
		if h.EndOfSale != "" {
			date("hardware_lifecycle "+h.Model, h.EndOfSale)
		}
		if h.EndOfSupport != "" {
			date("hardware_lifecycle "+h.Model, h.EndOfSupport)
		}
	}
	for _, k := range required {
		if _, ok := p.Thresholds[k]; !ok {
			add("thresholds: %q is required", k)
		}
	}
	sev := map[string]bool{"": true, "Info": true, "Low": true, "Medium": true, "High": true, "Critical": true}
	hz := map[string]bool{"": true, "immediate": true, "near-term": true, "strategic": true}
	for id, r := range p.Rules {
		if r.Name == "" {
			add("rules.%s: name is required", id)
		}
		if !sev[r.Severity] {
			add("rules.%s: severity %q must be Info, Low, Medium, High, or Critical", id, r.Severity)
		}
		if !hz[r.Horizon] {
			add("rules.%s: horizon %q must be immediate, near-term, or strategic", id, r.Horizon)
		}
	}
	if !strings.Contains(p.Changelog, "## "+m.Version) {
		add("RULES-CHANGELOG.md has no \"## %s\" entry", m.Version)
	}
	sort.Strings(errs)
	return errs
}

func sign(in string) {
	seed, err := base64.StdEncoding.DecodeString(strings.TrimSpace(os.Getenv("RULES_SIGNING_KEY")))
	if err != nil || len(seed) != ed25519.SeedSize {
		fail("RULES_SIGNING_KEY must hold the base64 ed25519 seed")
	}
	priv := ed25519.NewKeyFromSeed(seed)
	data, err := os.ReadFile(in)
	if err != nil {
		fail(err.Error())
	}
	pub := priv.Public().(ed25519.PublicKey)
	sum := sha256.Sum256(pub)
	sig := "ed25519:" + hex.EncodeToString(sum[:8]) + ":" + base64.StdEncoding.EncodeToString(ed25519.Sign(priv, data)) + "\n"
	if err := os.WriteFile(in+".sig", []byte(sig), 0o644); err != nil {
		fail(err.Error())
	}
	fmt.Printf("signed %s with key %s\n", in, hex.EncodeToString(sum[:8]))
}

func verify(in, pubB64 string) {
	pub, err := base64.StdEncoding.DecodeString(pubB64)
	if err != nil || len(pub) != ed25519.PublicKeySize {
		fail("-pub must be a base64 ed25519 public key")
	}
	data, err := os.ReadFile(in)
	if err != nil {
		fail(err.Error())
	}
	sigFile, err := os.ReadFile(in + ".sig")
	if err != nil {
		fail(err.Error())
	}
	parts := strings.Split(strings.TrimSpace(string(sigFile)), ":")
	if len(parts) != 3 {
		fail("malformed signature file")
	}
	sig, err := base64.StdEncoding.DecodeString(parts[2])
	if err != nil || !ed25519.Verify(pub, data, sig) {
		fail("signature does not verify")
	}
	fmt.Println("signature OK, key", parts[1])
}

// diff summarizes what changed between two packs, for pull requests and
// release notes.
func diff(oldPath, newPath string) {
	load := func(path string) pack {
		var p pack
		b, err := os.ReadFile(path)
		if err != nil {
			fail(err.Error())
		}
		if err := json.Unmarshal(b, &p); err != nil {
			fail(path + ": " + err.Error())
		}
		return p
	}
	o, n := load(oldPath), load(newPath)
	fmt.Printf("### %s → %s\n\n", o.Manifest.Version, n.Manifest.Version)
	section := func(title string, lines []string) {
		if len(lines) == 0 {
			return
		}
		sort.Strings(lines)
		fmt.Printf("**%s**\n", title)
		for _, l := range lines {
			fmt.Println("- " + l)
		}
		fmt.Println()
	}
	var adv []string
	oa := map[string]advisory{}
	for _, a := range o.Advisories {
		oa[a.ID] = a
	}
	for _, a := range n.Advisories {
		if prev, ok := oa[a.ID]; !ok {
			adv = append(adv, fmt.Sprintf("added %s (%s, disclosed %s)", a.Name, strings.Join(a.CVEs, ", "), a.Disclosed))
		} else if !sameJSON(prev, a) {
			adv = append(adv, "changed "+a.Name)
		}
		delete(oa, a.ID)
	}
	for _, a := range oa {
		adv = append(adv, "removed "+a.Name)
	}
	section("Firmware advisories", adv)
	var th []string
	for k, v := range n.Thresholds {
		if ov, ok := o.Thresholds[k]; !ok || ov != v {
			th = append(th, fmt.Sprintf("%s: %v → %v", k, o.Thresholds[k], v))
		}
	}
	section("Thresholds", th)
	var rl []string
	for id, r := range n.Rules {
		prev, ok := o.Rules[id]
		switch {
		case !ok:
			rl = append(rl, "added "+id)
		case !sameJSON(prev, r):
			rl = append(rl, "changed "+id)
		}
	}
	for id := range o.Rules {
		if _, ok := n.Rules[id]; !ok {
			rl = append(rl, "removed "+id)
		}
	}
	section("Rules", rl)
	var gs []string
	og := map[string]string{}
	for _, e := range o.GuestOS.Entries {
		og[e.Label] = e.EndOfSupport
	}
	for _, e := range n.GuestOS.Entries {
		if d, ok := og[e.Label]; !ok {
			gs = append(gs, fmt.Sprintf("added %s (end of support %s)", e.Label, e.EndOfSupport))
		} else if d != e.EndOfSupport {
			gs = append(gs, fmt.Sprintf("%s: end of support %s → %s", e.Label, d, e.EndOfSupport))
		}
	}
	section("Guest OS lifecycle", gs)
	if len(adv)+len(th)+len(rl)+len(gs) == 0 {
		fmt.Println("No changes to advisories, thresholds, rules, or guest OS dates.")
	}
}

// sameJSON compares values by their JSON form (pointer fields such as
// "enabled" would otherwise compare by address).
func sameJSON(a, b any) bool {
	x, _ := json.Marshal(a)
	y, _ := json.Marshal(b)
	return bytes.Equal(x, y)
}
