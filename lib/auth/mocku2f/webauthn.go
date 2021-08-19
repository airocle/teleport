package mocku2f

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"

	"github.com/duo-labs/webauthn/protocol"
	"github.com/gravitational/teleport/lib/auth/webauthn"
	"github.com/gravitational/trace"
)

type collectedClientData struct {
	Type      string `json:"type"`
	Challenge string `json:"challenge"`
	Origin    string `json:"origin"`
}

func (muk *Key) SignAssertion(origin string, assertion *webauthn.CredentialAssertion) (*webauthn.CredentialAssertionResponse, error) {
	// Is our credential allowed?
	ok := false
	for _, c := range assertion.Response.AllowedCredentials {
		if bytes.Equal(c.CredentialID, muk.KeyHandle) {
			ok = true
			break
		}
	}
	if !ok {
		return nil, trace.Errorf("device not allowed")
	}

	// Is the U2F app ID present?
	appID := assertion.Response.Extensions["appid"].(string)
	if appID == "" {
		return nil, trace.Errorf("missing u2f app ID")
	}
	appIDHash := sha256.Sum256([]byte(appID))

	// CollectedClientData is what gets signed in place of the challenge.
	// https://fidoalliance.org/specs/fido-v2.1-ps-20210615/fido-client-to-authenticator-protocol-v2.1-ps-20210615.html#u2f-authenticatorGetAssertion-interoperability
	ccd, err := json.Marshal(&collectedClientData{
		Type:      "webauthn.get",
		Challenge: base64.RawURLEncoding.EncodeToString(assertion.Response.Challenge),
		Origin:    origin,
	})
	if err != nil {
		return nil, trace.Wrap(err)
	}
	ccdHash := sha256.Sum256(ccd)

	signData, err := muk.signAuthentication(appIDHash[:], ccdHash[:])
	if err != nil {
		return nil, trace.Wrap(err)
	}

	// Assemble authenticator data.
	// https://fidoalliance.org/specs/fido-v2.1-ps-20210615/fido-client-to-authenticator-protocol-v2.1-ps-20210615.html#u2f-authenticatorGetAssertion-interoperability
	authData := &bytes.Buffer{}
	authData.Write(appIDHash[:])
	authData.WriteByte(signData[0]) // User Presence
	authData.Write(signData[1:5])   // Counter
	signature := signData[5:]       // Signature

	return &webauthn.CredentialAssertionResponse{
		PublicKeyCredential: protocol.PublicKeyCredential{
			Credential: protocol.Credential{
				ID:   base64.RawURLEncoding.EncodeToString(muk.KeyHandle),
				Type: "public-key",
			},
			RawID: muk.KeyHandle,
			Extensions: protocol.AuthenticationExtensionsClientOutputs{
				"appid": true, // U2F App ID used.
			},
		},
		AssertionResponse: protocol.AuthenticatorAssertionResponse{
			AuthenticatorResponse: protocol.AuthenticatorResponse{
				ClientDataJSON: ccd,
			},
			AuthenticatorData: authData.Bytes(),
			Signature:         signature,
		},
	}, nil
}
