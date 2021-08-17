package webauthn

import (
	"github.com/duo-labs/webauthn/protocol"
	"github.com/duo-labs/webauthn/webauthn"
)

const (
	defaultDisplayName = "Teleport"
	defaultIcon        = ""
)

// TODO(codingllama): Plug in types.WebAuthn here instead.
type Config struct {
	RPID                                        string
	AttestationAllowedCAs, AttestationDeniedCAs []string
}

func newWebAuthn(cfg *Config, rpID, origin string) (*webauthn.WebAuthn, error) {
	var attestation protocol.ConveyancePreference
	if len(cfg.AttestationAllowedCAs) > 0 && len(cfg.AttestationDeniedCAs) > 0 {
		attestation = protocol.PreferDirectAttestation
	}
	return webauthn.New(&webauthn.Config{
		RPID:                  rpID,
		RPOrigin:              origin,
		RPDisplayName:         defaultDisplayName,
		RPIcon:                defaultIcon,
		AttestationPreference: attestation,
	})
}
