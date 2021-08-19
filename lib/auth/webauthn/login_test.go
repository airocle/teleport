package webauthn_test

import (
	"context"
	"crypto/x509"
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/gravitational/teleport/api/types"
	"github.com/gravitational/teleport/lib/auth/mocku2f"
	"github.com/gravitational/teleport/lib/auth/webauthn"
	"github.com/stretchr/testify/require"
)

const (
	initialCounter = 10
)

func TestLoginFlow_LoginSuccessful_u2f(t *testing.T) {
	// Let's simulate a pre-existing U2F device.
	dev, err := mocku2f.Create()
	require.NoError(t, err)
	dev.SetCounter(initialCounter)
	mfaDev, err := keyToMFADevice(dev, initialCounter)
	require.NoError(t, err)

	user := &types.UserV2{
		Metadata: types.Metadata{
			Name: "llama",
		},
		Spec: types.UserSpecV2{
			LocalAuth: &types.LocalAuthSecrets{
				MFA: []*types.MFADevice{mfaDev},
			},
		},
	}
	identity := &fakeIdentity{
		User:        user,
		SessionData: make(map[string]*webauthn.SessionData),
	}

	webLogin := webauthn.LoginFlow{
		U2F:      &types.U2F{AppID: "https://example.com:3080"},
		Webauthn: &webauthn.Config{RPID: "example.com"},
		Identity: identity,
	}

	ctx := context.Background()
	assertion, err := webLogin.Begin(ctx, user.GetName())
	require.NoError(t, err)

	// TODO(codingllama): Assert assertion.

	assertionResp, err := dev.SignAssertion("https://example.com:3080" /* origin */, assertion)
	require.NoError(t, err)

	loginDevice, err := webLogin.Finish(ctx, user.GetName(), assertionResp)
	require.NoError(t, err)
	require.NotNil(t, loginDevice)

	// TODO(codingllama): Assert login device.
}

func keyToMFADevice(dev *mocku2f.Key, counter uint32) (*types.MFADevice, error) {
	pubKeyDER, err := x509.MarshalPKIXPublicKey(&dev.PrivateKey.PublicKey)
	if err != nil {
		return nil, err
	}
	return &types.MFADevice{
		AddedAt:  time.Now().Add(5 * time.Minute),
		LastUsed: time.Now().Add(5 * time.Minute),
		Device: &types.MFADevice_U2F{
			U2F: &types.U2FDevice{
				KeyHandle: dev.KeyHandle,
				PubKey:    pubKeyDER,
				Counter:   counter,
			},
		},
	}, nil
}

type fakeIdentity struct {
	User           *types.UserV2
	UpdatedDevices []*types.MFADevice
	SessionData    map[string]*webauthn.SessionData
}

func (f *fakeIdentity) GetUser(user string, withSecrets bool) (types.User, error) {
	return f.User, nil
}

func (f *fakeIdentity) GetMFADevices(ctx context.Context, user string) ([]*types.MFADevice, error) {
	return f.User.GetLocalAuth().MFA, nil
}

func (f *fakeIdentity) UpsertMFADevice(ctx context.Context, user string, d *types.MFADevice) error {
	f.UpdatedDevices = append(f.UpdatedDevices, d)
	return nil
}

func (f *fakeIdentity) UpsertWebAuthnSessionData(user, sessionID string, sd *webauthn.SessionData) error {
	f.SessionData[sessionDataKey(user, sessionID)] = sd
	return nil
}

func (f *fakeIdentity) GetWebAuthnSessionData(user, sessionID string) (*webauthn.SessionData, error) {
	sd, ok := f.SessionData[sessionDataKey(user, sessionID)]
	if !ok {
		return nil, errors.New("not found")
	}
	return sd, nil
}

func (f *fakeIdentity) DeleteWebAuthnSessionData(user, sessionID string) error {
	delete(f.SessionData, sessionDataKey(user, sessionID))
	return nil
}

func sessionDataKey(user string, sessionID string) string {
	return fmt.Sprintf("%v/%v", user, sessionID)
}
