package updater

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/sigstore/sigstore-go/pkg/testing/ca"
	"github.com/sigstore/sigstore-go/pkg/verify"
)

const testTag = "v9.9.9"

// provenanceStatement builds an in-toto statement shaped like the one
// actions/attest produces from SHA256SUMS.txt.
func provenanceStatement(t *testing.T, predicateType string, subjects map[string]string) []byte {
	t.Helper()
	type subject struct {
		Name   string            `json:"name"`
		Digest map[string]string `json:"digest"`
	}
	statement := struct {
		Type          string    `json:"_type"`
		Subject       []subject `json:"subject"`
		PredicateType string    `json:"predicateType"`
		Predicate     any       `json:"predicate"`
	}{
		Type:          "https://in-toto.io/Statement/v1",
		PredicateType: predicateType,
		Predicate:     map[string]any{"buildDefinition": map[string]any{"buildType": "https://actions.github.io/buildtypes/workflow/v1"}},
	}
	for name, digest := range subjects {
		statement.Subject = append(statement.Subject, subject{Name: name, Digest: map[string]string{"sha256": digest}})
	}
	data, err := json.Marshal(statement)
	if err != nil {
		t.Fatal(err)
	}
	return data
}

func virtualVerifier(t *testing.T) (*ca.VirtualSigstore, *provenanceVerifier) {
	t.Helper()
	vs, err := ca.NewVirtualSigstore()
	if err != nil {
		t.Fatal(err)
	}
	// The virtual CA issues no SCTs; every other public-good requirement stays.
	return vs, &provenanceVerifier{
		trusted: vs,
		options: []verify.VerifierOption{verify.WithTransparencyLog(1), verify.WithObserverTimestamps(1)},
	}
}

func TestVerifyAsset(t *testing.T) {
	const asset = "mcp-flowsentinel-linux-amd64"
	digest := testChecksum([]byte("release binary"))
	otherDigest := testChecksum([]byte("tampered binary"))
	sbomDigest := testChecksum([]byte("sbom"))

	vs, verifier := virtualVerifier(t)

	tests := []struct {
		name      string
		identity  string
		issuer    string
		predicate string
		subjects  map[string]string
		wantErr   string
	}{
		{
			name:      "valid signature",
			identity:  releaseSignerIdentity(testTag),
			issuer:    githubOIDCIssuer,
			predicate: slsaProvenanceV1,
			subjects:  map[string]string{asset: digest, "sbom.spdx.json": sbomDigest},
		},
		{
			name:      "wrong repository",
			identity:  "https://github.com/attacker/MCP-FlowSentinel/.github/workflows/release.yml@refs/tags/" + testTag,
			issuer:    githubOIDCIssuer,
			predicate: slsaProvenanceV1,
			subjects:  map[string]string{asset: digest},
			wantErr:   "no valid provenance",
		},
		{
			name:      "wrong workflow",
			identity:  "https://github.com/" + repo + "/.github/workflows/ci.yml@refs/tags/" + testTag,
			issuer:    githubOIDCIssuer,
			predicate: slsaProvenanceV1,
			subjects:  map[string]string{asset: digest},
			wantErr:   "no valid provenance",
		},
		{
			name:      "older tag replayed",
			identity:  releaseSignerIdentity("v0.1.0"),
			issuer:    githubOIDCIssuer,
			predicate: slsaProvenanceV1,
			subjects:  map[string]string{asset: digest},
			wantErr:   "no valid provenance",
		},
		{
			name:      "branch instead of tag",
			identity:  "https://github.com/" + repo + "/" + releaseWorkflowPath + "@refs/heads/main",
			issuer:    githubOIDCIssuer,
			predicate: slsaProvenanceV1,
			subjects:  map[string]string{asset: digest},
			wantErr:   "no valid provenance",
		},
		{
			name:      "wrong OIDC issuer",
			identity:  releaseSignerIdentity(testTag),
			issuer:    "https://accounts.google.com",
			predicate: slsaProvenanceV1,
			subjects:  map[string]string{asset: digest},
			wantErr:   "no valid provenance",
		},
		{
			name:      "altered checksum",
			identity:  releaseSignerIdentity(testTag),
			issuer:    githubOIDCIssuer,
			predicate: slsaProvenanceV1,
			subjects:  map[string]string{asset: otherDigest},
			wantErr:   "no valid provenance",
		},
		{
			name:      "digest attested under another asset name",
			identity:  releaseSignerIdentity(testTag),
			issuer:    githubOIDCIssuer,
			predicate: slsaProvenanceV1,
			subjects:  map[string]string{"mcp-flowsentinel-darwin-arm64": digest},
			wantErr:   "does not list " + asset,
		},
		{
			name:      "unexpected predicate type",
			identity:  releaseSignerIdentity(testTag),
			issuer:    githubOIDCIssuer,
			predicate: "https://example.com/custom/v1",
			subjects:  map[string]string{asset: digest},
			wantErr:   "unexpected predicate type",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			entity, err := vs.Attest(tc.identity, tc.issuer, provenanceStatement(t, tc.predicate, tc.subjects))
			if err != nil {
				t.Fatal(err)
			}
			err = verifier.verifyAsset([]verify.SignedEntity{entity}, testTag, asset, digest)
			if tc.wantErr == "" {
				if err != nil {
					t.Fatalf("verifyAsset() = %v, want nil", err)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
				t.Fatalf("verifyAsset() = %v, want error containing %q", err, tc.wantErr)
			}
		})
	}
}

func TestVerifyAsset_UntrustedAuthorityRejected(t *testing.T) {
	const asset = "mcp-flowsentinel-linux-amd64"
	digest := testChecksum([]byte("release binary"))

	rogue, _ := virtualVerifier(t)
	_, verifier := virtualVerifier(t)
	entity, err := rogue.Attest(releaseSignerIdentity(testTag), githubOIDCIssuer,
		provenanceStatement(t, slsaProvenanceV1, map[string]string{asset: digest}))
	if err != nil {
		t.Fatal(err)
	}
	if err := verifier.verifyAsset([]verify.SignedEntity{entity}, testTag, asset, digest); err == nil {
		t.Fatal("attestation from an untrusted Sigstore instance was accepted")
	}
}

func TestVerifyAsset_AcceptsAnyValidEntity(t *testing.T) {
	const asset = "mcp-flowsentinel-linux-amd64"
	digest := testChecksum([]byte("release binary"))
	vs, verifier := virtualVerifier(t)

	bad, err := vs.Attest(releaseSignerIdentity("v0.0.1"), githubOIDCIssuer,
		provenanceStatement(t, slsaProvenanceV1, map[string]string{asset: digest}))
	if err != nil {
		t.Fatal(err)
	}
	good, err := vs.Attest(releaseSignerIdentity(testTag), githubOIDCIssuer,
		provenanceStatement(t, slsaProvenanceV1, map[string]string{asset: digest}))
	if err != nil {
		t.Fatal(err)
	}
	if err := verifier.verifyAsset([]verify.SignedEntity{bad, good}, testTag, asset, digest); err != nil {
		t.Fatalf("verifyAsset() = %v, want nil", err)
	}
}

func TestVerifyAsset_InvalidDigest(t *testing.T) {
	_, verifier := virtualVerifier(t)
	if err := verifier.verifyAsset(nil, testTag, "asset", "not-hex"); err == nil {
		t.Fatal("expected error for malformed digest")
	}
}

func TestParseProvenance_RejectsEmptyAndMalformed(t *testing.T) {
	for name, input := range map[string]string{
		"empty":     "",
		"blank":     "\n \n",
		"not json":  "not a bundle",
		"bad jsonl": "{}\nnot a bundle\n",
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := parseProvenance([]byte(input)); err == nil {
				t.Fatal("expected error")
			}
		})
	}
}

func TestReleaseSignerIdentity(t *testing.T) {
	want := "https://github.com/ClementG91/MCP-FlowSentinel/.github/workflows/release.yml@refs/tags/v1.2.3"
	if got := releaseSignerIdentity("v1.2.3"); got != want {
		t.Fatalf("releaseSignerIdentity() = %q, want %q", got, want)
	}
}

// releaseServer serves a release whose binary and SHA256SUMS.txt are
// consistent, plus an optional provenance body. It counts binary downloads.
func releaseServer(t *testing.T, provenance *string) (*int32, func()) {
	t.Helper()
	assetName := assetForPlatform()
	if assetName == "" {
		t.Skip("unsupported platform")
	}
	const payload = "fake binary content"
	var downloads int32
	mux := http.NewServeMux()
	srv := httptest.NewServer(mux)
	assets := []Asset{
		{Name: assetName, BrowserDownloadURL: srv.URL + "/bin"},
		{Name: "SHA256SUMS.txt", BrowserDownloadURL: srv.URL + "/sums"},
	}
	if provenance != nil {
		assets = append(assets, Asset{Name: provenanceAssetName, BrowserDownloadURL: srv.URL + "/provenance"})
	}
	mux.HandleFunc("/repos/"+repo+"/releases/latest", func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(Release{TagName: testTag, Assets: assets})
	})
	mux.HandleFunc("/sums", func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(testChecksum([]byte(payload)) + "  " + assetName + "\n"))
	})
	mux.HandleFunc("/provenance", func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(*provenance))
	})
	mux.HandleFunc("/bin", func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&downloads, 1)
		_, _ = w.Write([]byte(payload))
	})
	restore := withAPIBase(t, srv.URL)
	return &downloads, func() { restore(); srv.Close() }
}

func TestCheckAndUpdate_MissingProvenanceRefusesUpdate(t *testing.T) {
	downloads, cleanup := releaseServer(t, nil)
	defer cleanup()

	err := CheckAndUpdate("v1.0.0")
	if err == nil || !strings.Contains(err.Error(), provenanceAssetName) {
		t.Fatalf("CheckAndUpdate() = %v, want missing provenance error", err)
	}
	if n := atomic.LoadInt32(downloads); n != 0 {
		t.Fatalf("binary downloaded %d times despite missing provenance", n)
	}
}

func TestCheckAndUpdate_MalformedProvenanceRefusesUpdate(t *testing.T) {
	body := "garbage"
	downloads, cleanup := releaseServer(t, &body)
	defer cleanup()

	err := CheckAndUpdate("v1.0.0")
	if err == nil || !strings.Contains(err.Error(), "refusing unauthenticated update") {
		t.Fatalf("CheckAndUpdate() = %v, want refusal", err)
	}
	if n := atomic.LoadInt32(downloads); n != 0 {
		t.Fatalf("binary downloaded %d times despite malformed provenance", n)
	}
}
