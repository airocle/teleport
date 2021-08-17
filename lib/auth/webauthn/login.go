package webauthn

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strconv"
	"strings"

	"github.com/duo-labs/webauthn/protocol"
	"github.com/duo-labs/webauthn/webauthn"
	"github.com/gravitational/teleport/api/types"
	"github.com/gravitational/teleport/lib/services"
	"github.com/gravitational/trace"
	log "github.com/sirupsen/logrus"
)

// CredentialAssertion is the payload sent to authenticators to initiate login.
type CredentialAssertion = protocol.CredentialAssertion

// CredentialAssertionResponse is the reply from authenticators to complete
// login.
type CredentialAssertionResponse = protocol.CredentialAssertionResponse

// LoginFlow represents the WebAuthn login procedure.
type LoginFlow struct {
	U2F      *types.U2F
	Webauthn *Config
	Identity services.Identity
}

func (f *LoginFlow) Begin(ctx context.Context, userID string) (*CredentialAssertion, error) {
	web, err := newWebAuthn(f.Webauthn, f.Webauthn.RPID, "" /* origin */)
	if err != nil {
		return nil, trace.Wrap(err)
	}

	user, err := f.Identity.GetUser(userID, true /* withSecrets */)
	if err != nil {
		return nil, trace.Wrap(err)
	}
	devices, err := f.Identity.GetMFADevices(ctx, userID)
	if err != nil {
		return nil, trace.Wrap(err)
	}
	u := newWebUser(user, true /* idOnly */, devices)

	var opts []webauthn.LoginOption
	if f.U2F != nil && f.U2F.AppID != "" {
		opts = append(opts, webauthn.WithAssertionExtensions(protocol.AuthenticationExtensions{
			"appid": f.U2F.AppID,
		}))
	}

	assertion, sessionData, err := web.BeginLogin(u, opts...)
	if err != nil {
		return nil, trace.Wrap(err)
	}

	// TODO(codingllama): Store session data.
	_ = sessionData

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
		usingAppID, err := strconv.ParseBool(strings.ToLower(fmt.Sprint(appidExt)))
		switch {
		case err != nil:
			log.Warnf("WebAuthn: failed to parse appid extension (%v)", appidExt)
		case usingAppID && (f.U2F == nil || f.U2F.AppID == ""):
			return nil, trace.Errorf("appid extension provided but U2F app_id not configured")
		case usingAppID:
			rpID = f.U2F.AppID // Allow RPID = AppID for legacy devices
			usingAppID = true
		}
	}

	origin := parsedResp.Response.CollectedClientData.Origin
	if err := validateOrigin(origin, f.Webauthn.RPID); err != nil {
		return nil, trace.Wrap(err)
	}

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

	user, err := f.Identity.GetUser(userID, true /* withSecrets */)
	if err != nil {
		return nil, trace.Wrap(err)
	}
	u := newWebUser(user, false /* idOnly */, []*types.MFADevice{dev})

	// TODO(codingllama): Fetch SessionData from storage.
	sessionData := &webauthn.SessionData{}

	web, err := newWebAuthn(f.Webauthn, rpID, origin)
	if err != nil {
		return nil, trace.Wrap(err)
	}

	credential, err := web.ValidateLogin(u, *sessionData, parsedResp)
	if err != nil {
		return nil, trace.Wrap(err)
	}

	// TODO(codingllama): Update device in storage?

	// TODO(codingllama): Credential to device
	_ = credential

	return &types.MFADevice{}, nil
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

// TODO(codingllama): Move somewhere else?
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
