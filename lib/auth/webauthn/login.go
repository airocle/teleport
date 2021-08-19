package webauthn

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/duo-labs/webauthn/protocol"
	"github.com/duo-labs/webauthn/webauthn"
	"github.com/gravitational/teleport/api/types"
	"github.com/gravitational/trace"

	log "github.com/sirupsen/logrus"
)

// CredentialAssertion is the payload sent to authenticators to initiate login.
type CredentialAssertion = protocol.CredentialAssertion

// CredentialAssertionResponse is the reply from authenticators to complete
// login.
type CredentialAssertionResponse = protocol.CredentialAssertionResponse

type SessionData = webauthn.SessionData

const (
	loginSessionID = "login"
)

// loginIdentity represents the subset of Identity methods used by LoginFlow.
type loginIdentity interface {
	GetUser(userID string, withSecrets bool) (types.User, error)
	GetMFADevices(ctx context.Context, userID string) ([]*types.MFADevice, error)
	UpsertMFADevice(ctx context.Context, user string, d *types.MFADevice) error
	UpsertWebAuthnSessionData(userID, sessionID string, sd *SessionData) error
	GetWebAuthnSessionData(userID, sessionID string) (*SessionData, error)
	DeleteWebAuthnSessionData(userID, sessionID string) error
}

type loginIdentityWithDevices struct {
	loginIdentity
	devices []*types.MFADevice
}

func (l *loginIdentityWithDevices) GetMFADevices(_ context.Context, _ string) ([]*types.MFADevice, error) {
	return l.devices, nil
}

// WithDevices attributes a fixed set of devices to a loginIdentity instance.
// Useful for callers that read and sort devices prior to beginning login.
func WithDevices(devs []*types.MFADevice, l loginIdentity) loginIdentity {
	return &loginIdentityWithDevices{
		loginIdentity: l,
		devices:       devs,
	}
}

// LoginFlow represents the WebAuthn login procedure.
type LoginFlow struct {
	U2F      *types.U2F
	Webauthn *Config
	// Identity is typically an implementation of the Identity service, ie, an
	// object with access to user, device and MFA storage.
	Identity loginIdentity
}

func (f *LoginFlow) Begin(ctx context.Context, userID string) (*CredentialAssertion, error) {
	// Fetch existing user devices. We need the devices both to set the allowed
	// credentials for the user (webUser.credentials) and to determine if the U2F
	// appid extension is necessary.
	devices, err := f.Identity.GetMFADevices(ctx, userID)
	if err != nil {
		return nil, trace.Wrap(err)
	}
	var opts []webauthn.LoginOption
	if f.U2F != nil && f.U2F.AppID != "" {
		// See https://www.w3.org/TR/webauthn-2/#sctn-appid-extension.
		opts = append(opts, webauthn.WithAssertionExtensions(protocol.AuthenticationExtensions{
			"appid": f.U2F.AppID,
		}))
	}

	// Fetch the user with secrets, their WebAuthn ID is inside.
	user, err := f.Identity.GetUser(userID, true /* withSecrets */)
	if err != nil {
		return nil, trace.Wrap(err)
	}

	// TODO(codingllama): Create user WebAuthn ID if necessary.
	u := newWebUser(user, true /* idOnly */, devices)

	// Create the WebAuthn object and create a new challenge.
	web, err := newWebAuthn(f.Webauthn, f.Webauthn.RPID, "" /* origin */)
	if err != nil {
		return nil, trace.Wrap(err)
	}
	assertion, sessionData, err := web.BeginLogin(u, opts...)
	if err != nil {
		return nil, trace.Wrap(err)
	}

	// Store SessionData - it's checked against the user response by
	// LoginFlow.Finish().
	if err := f.Identity.UpsertWebAuthnSessionData(userID, loginSessionID, sessionData); err != nil {
		return nil, trace.Wrap(err)
	}

	return assertion, nil
}

func (f *LoginFlow) Finish(ctx context.Context, resp *CredentialAssertionResponse, userID string) (*types.MFADevice, error) {
	parsedResp, err := parseCredentialResponse(resp)
	if err != nil {
		return nil, trace.Wrap(err)
	}

	// If the appid extension is present, then we must set RPID = AppID and ensure
	// the credential comes from an U2F device.
	rpID := f.Webauthn.RPID
	var usingAppID bool
	appidExt, ok := parsedResp.Extensions["appid"]
	if ok {
		// Let's try and be as lenient as we can with what comes here.
		var err error
		usingAppID, err = strconv.ParseBool(strings.ToLower(fmt.Sprint(appidExt)))
		switch {
		case err != nil:
			log.Warnf("WebAuthn: failed to parse appid extension (%v)", appidExt)
		case usingAppID && (f.U2F == nil || f.U2F.AppID == ""):
			return nil, trace.Errorf("appid extension provided but U2F app_id not configured")
		case usingAppID:
			rpID = f.U2F.AppID // Allow RPID = AppID for legacy devices
		}
	}

	origin := parsedResp.Response.CollectedClientData.Origin
	if err := validateOrigin(origin, f.Webauthn.RPID); err != nil {
		return nil, trace.Wrap(err)
	}

	// Find the device used to sign the credentials. It must be a previously
	// registered device.
	devices, err := f.Identity.GetMFADevices(ctx, userID)
	if err != nil {
		return nil, trace.Wrap(err)
	}
	dev, ok := findDeviceByID(devices, parsedResp.RawID)
	switch {
	case !ok:
		return nil, trace.Errorf(
			"unknown device credential: %q", base64.RawURLEncoding.EncodeToString(parsedResp.RawID))
	case usingAppID && dev.GetU2F() == nil:
		return nil, trace.Errorf(
			"appid extension is true, but credential is not for an U2F device: %q", base64.RawURLEncoding.EncodeToString(parsedResp.RawID))
	}

	// Fetch the user with secrets, their WebAuthn ID is inside.
	user, err := f.Identity.GetUser(userID, true /* withSecrets */)
	if err != nil {
		return nil, trace.Wrap(err)
	}
	u := newWebUser(user, false /* idOnly */, []*types.MFADevice{dev})

	// Fetch the previously-stored SessionData, so it's checked against the user
	// response.
	sessionData, err := f.Identity.GetWebAuthnSessionData(userID, loginSessionID)
	if err != nil {
		return nil, trace.Wrap(err)
	}

	// Create a WebAuthn matching the expected RPID and Origin, then verify the
	// signed challenge.
	web, err := newWebAuthn(f.Webauthn, rpID, origin)
	if err != nil {
		return nil, trace.Wrap(err)
	}
	credential, err := web.ValidateLogin(u, *sessionData, parsedResp)
	if err != nil {
		return nil, trace.Wrap(err)
	}

	// Update last used timestamp and device counter.
	if err := setCounterAndTimestamps(dev, credential); err != nil {
		return nil, trace.Wrap(err)
	}
	if err := f.Identity.UpsertMFADevice(ctx, userID, dev); err != nil {
		return nil, trace.Wrap(err)
	}

	// The user just solved this challenge, so let's make sure it won't be used
	// again.
	if err := f.Identity.DeleteWebAuthnSessionData(userID, loginSessionID); err != nil {
		log.Warnf("WebAuthn: failed to delete SessionData for user %v", userID)
	}

	return dev, nil
}

func parseCredentialResponse(resp *CredentialAssertionResponse) (*protocol.ParsedCredentialAssertionData, error) {
	// This is a roundabout way of getting resp validated, but unfortunately the
	// APIs don't provide a better method (and it seems better than duplicating
	// library code here).
	body, err := json.Marshal(resp)
	if err != nil {
		return nil, trace.Wrap(err)
	}
	return protocol.ParseCredentialRequestResponseBody(bytes.NewReader(body))
}

func validateOrigin(origin, rpID string) error {
	// TODO(codingllama): Check if origin matches the _actual_ RPID.
	// TODO(codingllama): Check origin against the public addresses of Proxies and
	//  Auth Servers
	return nil
}

func findDeviceByID(devices []*types.MFADevice, id []byte) (*types.MFADevice, bool) {
	for _, dev := range devices {
		if innerDev, ok := dev.Device.(*types.MFADevice_U2F); ok {
			if bytes.Equal(innerDev.U2F.KeyHandle, id) {
				return dev, true
			}
		}
	}
	return nil, false
}

func setCounterAndTimestamps(dev *types.MFADevice, credential *webauthn.Credential) error {
	u2f := dev.GetU2F()
	if u2f == nil {
		return fmt.Errorf("webauthn only implemented for U2F devices, got %T", dev.Device)
	}

	dev.LastUsed = time.Now()
	u2f.Counter = credential.Authenticator.SignCount
	return nil
}
