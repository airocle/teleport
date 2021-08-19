package webauthn

import (
	"github.com/duo-labs/webauthn/webauthn"
	"github.com/gravitational/teleport/api/types"
)

// webUser implements a WebAuthn protocol user.
// It is used to provide user information to WebAuthn APIs, but has no direct
// counterpart in storage nor in other packages.
type webUser struct {
	credentials []webauthn.Credential
	user        types.User
}

func newWebUser(user types.User, idOnly bool, devices []*types.MFADevice) *webUser {
	var credentials []webauthn.Credential
	for _, dev := range devices {
		c, ok := deviceToCredential(dev, idOnly)
		if ok {
			credentials = append(credentials, c)
		}
	}
	return &webUser{
		credentials: credentials,
		user:        user,
	}
}

func (w *webUser) WebAuthnID() []byte {
	// TODO(codingllama): Create and initialize WebAuthn ID
	return []byte(w.user.GetName())
}

func (w *webUser) WebAuthnName() string {
	return w.user.GetName()
}

func (w *webUser) WebAuthnDisplayName() string {
	return w.user.GetName()
}

func (w *webUser) WebAuthnIcon() string {
	return ""
}

func (w *webUser) WebAuthnCredentials() []webauthn.Credential {
	return w.credentials
}
