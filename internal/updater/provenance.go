package updater

import (
	"bytes"
	"context"
	"encoding/hex"
	"errors"
	"fmt"

	"github.com/sigstore/sigstore-go/pkg/bundle"
	"github.com/sigstore/sigstore-go/pkg/root"
	"github.com/sigstore/sigstore-go/pkg/tuf"
	"github.com/sigstore/sigstore-go/pkg/verify"
)

const (
	// provenanceAssetName is the Sigstore bundle published by release.yml. It
	// holds the SLSA provenance attestation whose subjects are every file
	// listed in SHA256SUMS.txt.
	provenanceAssetName = "attestation.sigstore.json"
	maxProvenanceSize   = 4 << 20

	githubOIDCIssuer    = "https://token.actions.githubusercontent.com"
	releaseWorkflowPath = ".github/workflows/release.yml"
	slsaProvenanceV1    = "https://slsa.dev/provenance/v1"
)

// provenanceVerifier checks that a release asset digest was attested by the
// release workflow of this repository for a given tag.
type provenanceVerifier struct {
	trusted root.TrustedMaterial
	options []verify.VerifierOption
}

// newProvenanceVerifier is a var so tests can inject an offline trust root.
var newProvenanceVerifier = newPublicGoodVerifier

// newPublicGoodVerifier fetches the Sigstore public-good trust root through
// TUF and requires the same evidence as `gh attestation verify`: an embedded
// SCT, a Rekor transparency-log entry and an observer timestamp.
func newPublicGoodVerifier(ctx context.Context) (*provenanceVerifier, error) {
	trusted, err := root.FetchTrustedRootWithOptions(tuf.DefaultOptions().WithContext(ctx))
	if err != nil {
		return nil, fmt.Errorf("fetch Sigstore trust root: %w", err)
	}
	return &provenanceVerifier{
		trusted: trusted,
		options: []verify.VerifierOption{
			verify.WithSignedCertificateTimestamps(1),
			verify.WithTransparencyLog(1),
			verify.WithObserverTimestamps(1),
		},
	}, nil
}

// releaseSignerIdentity is the certificate SAN GitHub issues to release.yml
// when it runs for tag.
func releaseSignerIdentity(tag string) string {
	return fmt.Sprintf("https://github.com/%s/%s@refs/tags/%s", repo, releaseWorkflowPath, tag)
}

// parseProvenance decodes a Sigstore bundle. It accepts a single JSON bundle
// or JSON Lines holding one bundle per line.
func parseProvenance(data []byte) ([]verify.SignedEntity, error) {
	var entities []verify.SignedEntity
	for _, line := range bytes.Split(bytes.TrimSpace(data), []byte("\n")) {
		line = bytes.TrimSpace(line)
		if len(line) == 0 {
			continue
		}
		var b bundle.Bundle
		if err := b.UnmarshalJSON(line); err != nil {
			if len(entities) == 0 {
				// Not JSON Lines: try the whole document as one bundle.
				var whole bundle.Bundle
				if wholeErr := whole.UnmarshalJSON(data); wholeErr == nil {
					return []verify.SignedEntity{&whole}, nil
				}
			}
			return nil, fmt.Errorf("malformed Sigstore bundle: %w", err)
		}
		entities = append(entities, &b)
	}
	if len(entities) == 0 {
		return nil, errors.New("empty Sigstore bundle")
	}
	return entities, nil
}

// verifyAsset succeeds when one of entities is a SLSA provenance statement
// signed by release.yml at tag and lists assetName with the given digest.
func (p *provenanceVerifier) verifyAsset(entities []verify.SignedEntity, tag, assetName, sha256Hex string) error {
	digest, err := hex.DecodeString(sha256Hex)
	if err != nil {
		return fmt.Errorf("invalid digest for %s: %w", assetName, err)
	}
	verifier, err := verify.NewVerifier(p.trusted, p.options...)
	if err != nil {
		return fmt.Errorf("configure verifier: %w", err)
	}
	identity, err := verify.NewShortCertificateIdentity(githubOIDCIssuer, "", releaseSignerIdentity(tag), "")
	if err != nil {
		return fmt.Errorf("configure signer identity: %w", err)
	}
	policy := verify.NewPolicy(verify.WithArtifactDigest("sha256", digest), verify.WithCertificateIdentity(identity))

	var errs []error
	for _, entity := range entities {
		result, err := verifier.Verify(entity, policy)
		if err != nil {
			errs = append(errs, err)
			continue
		}
		if err := checkStatement(result, assetName, sha256Hex); err != nil {
			errs = append(errs, err)
			continue
		}
		return nil
	}
	return fmt.Errorf("no valid provenance for %s signed by %s: %w", assetName, releaseSignerIdentity(tag), errors.Join(errs...))
}

func checkStatement(result *verify.VerificationResult, assetName, sha256Hex string) error {
	statement := result.Statement
	if statement == nil {
		return errors.New("bundle carries no in-toto statement")
	}
	if statement.GetPredicateType() != slsaProvenanceV1 {
		return fmt.Errorf("unexpected predicate type %q", statement.GetPredicateType())
	}
	for _, subject := range statement.GetSubject() {
		if subject.GetName() == assetName && subject.GetDigest()["sha256"] == sha256Hex {
			return nil
		}
	}
	return fmt.Errorf("statement does not list %s with sha256 %s", assetName, sha256Hex)
}
