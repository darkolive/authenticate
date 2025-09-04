package main

import (
	charonotp "backend/agents/auth/CharonOTP"
	hecateregister "backend/agents/auth/HecateRegister"
	cerberus "backend/agents/auth/CerberusMFA"
	webauthn "backend/agents/auth/WebAuthn"
	sessions "backend/agents/sessions/ChronosSession"
	profile "backend/agents/users/Profile"
	"context"
)

// SendOTP is the API entrypoint (called by generated glue) and delegates to the CharonOTP agent.
func SendOTP(req *charonotp.OTPRequest) charonotp.OTPResponse {
    if req == nil {
        r := charonotp.OTPRequest{}
        resp, err := charonotp.SendOTP(context.Background(), r)
        if err != nil {
            return charonotp.OTPResponse{Verified: false, Message: err.Error()}
        }
        return resp
    }
    resp, err := charonotp.SendOTP(context.Background(), *req)
    if err != nil {
        return charonotp.OTPResponse{Verified: false, Message: err.Error(), Channel: req.Channel}
    }
    return resp
}

// UpdateUserProfile persists basic profile fields (name/displayName) for the user.
func UpdateUserProfile(req *profile.UpdateProfileRequest) profile.UpdateProfileResponse {
    if req == nil {
        r := profile.UpdateProfileRequest{}
        resp, err := profile.UpdateUserProfile(context.Background(), r)
        if err != nil {
            return profile.UpdateProfileResponse{Success: false, Message: err.Error()}
        }
        return resp
    }
    resp, err := profile.UpdateUserProfile(context.Background(), *req)
    if err != nil {
        return profile.UpdateProfileResponse{Success: false, Message: err.Error()}
    }
    return resp
}

// IsProfileComplete returns whether the user's profile has the minimum required fields.
func IsProfileComplete(req *profile.ProfileCompleteRequest) profile.ProfileCompleteResponse {
    if req == nil {
        r := profile.ProfileCompleteRequest{}
        resp, err := profile.IsProfileComplete(r)
        if err != nil {
            return profile.ProfileCompleteResponse{Complete: false, Message: err.Error()}
        }
        return resp
    }
    resp, err := profile.IsProfileComplete(*req)
    if err != nil {
        return profile.ProfileCompleteResponse{Complete: false, Message: err.Error()}
    }
    return resp
}

// VerifyOTP validates a code via the CharonOTP agent.
func VerifyOTP(req *charonotp.VerifyOTPRequest) charonotp.VerifyOTPResponse {
    if req == nil {
        r := charonotp.VerifyOTPRequest{}
        resp, err := charonotp.VerifyOTP(r)
        if err != nil {
            return charonotp.VerifyOTPResponse{Verified: false, Message: err.Error()}
        }
        return resp
    }
    resp, err := charonotp.VerifyOTP(*req)
    if err != nil {
        return charonotp.VerifyOTPResponse{Verified: false, Message: err.Error()}
    }
    return resp
}

// RegisterUser completes registration via the HecateRegister agent.
func RegisterUser(req *hecateregister.UserRegistrationRequest) hecateregister.UserRegistrationResponse {
    if req == nil {
        r := hecateregister.UserRegistrationRequest{}
        resp, err := hecateregister.RegisterUser(context.Background(), r)
        if err != nil {
            return hecateregister.UserRegistrationResponse{Success: false, Message: err.Error()}
        }
        return resp
    }
    resp, err := hecateregister.RegisterUser(context.Background(), *req)
    if err != nil {
        return hecateregister.UserRegistrationResponse{Success: false, Message: err.Error()}
    }
    return resp
}

// CerberusGate evaluates post-OTP next steps (signin vs register) and advertised methods.
func CerberusGate(req *cerberus.CerberusMFARequest) cerberus.CerberusMFAResponse {
    if req == nil {
        r := cerberus.CerberusMFARequest{}
        resp, err := cerberus.Evaluate(r)
        if err != nil {
            return cerberus.CerberusMFAResponse{UserExists: false, Action: "register", Message: err.Error(), AvailableMethods: []string{"passwordless"}, NextStep: "Complete user registration"}
        }
        return resp
    }
    resp, err := cerberus.Evaluate(*req)
    if err != nil {
        return cerberus.CerberusMFAResponse{UserExists: false, Action: "register", Message: err.Error(), AvailableMethods: []string{"passwordless"}, NextStep: "Complete user registration"}
    }
    return resp
}

// ValidateSession verifies a session token using the ChronosSession agent.
func ValidateSession(req *sessions.ValidationRequest) sessions.ValidationResponse {
    cs, ierr := sessions.Initialize()
    if ierr != nil {
        return sessions.ValidationResponse{Valid: false, Message: ierr.Error()}
    }
    // Guard against nil request
    if req == nil {
        return sessions.ValidationResponse{Valid: false, Message: "token is required"}
    }
    vresp, err := cs.ValidateSession(context.Background(), req)
    if err != nil {
        return sessions.ValidationResponse{Valid: false, Message: err.Error()}
    }
    if vresp == nil {
        return sessions.ValidationResponse{Valid: false, Message: "no validation response"}
    }
    return *vresp
}

// BeginWebAuthnRegistration starts WebAuthn credential creation by returning options and a challenge.
func BeginWebAuthnRegistration(req *webauthn.BeginRegistrationRequest) webauthn.BeginRegistrationResponse {
    if req == nil {
        r := webauthn.BeginRegistrationRequest{}
        resp, err := webauthn.BeginRegistration(r)
        if err != nil {
            return webauthn.BeginRegistrationResponse{}
        }
        return resp
    }
    resp, err := webauthn.BeginRegistration(*req)
    if err != nil {
        return webauthn.BeginRegistrationResponse{}
    }
    return resp
}

// FinishWebAuthnRegistration completes credential creation and stores the credential record.
func FinishWebAuthnRegistration(req *webauthn.FinishRegistrationRequest) webauthn.FinishRegistrationResponse {
    if req == nil {
        r := webauthn.FinishRegistrationRequest{}
        resp, err := webauthn.FinishRegistration(r)
        if err != nil {
            return webauthn.FinishRegistrationResponse{Success: false, Message: err.Error()}
        }
        return resp
    }
    resp, err := webauthn.FinishRegistration(*req)
    if err != nil {
        return webauthn.FinishRegistrationResponse{Success: false, Message: err.Error()}
    }
    return resp
}

// BeginWebAuthnLogin starts an assertion by returning request options and a challenge.
func BeginWebAuthnLogin(req *webauthn.BeginLoginRequest) webauthn.BeginLoginResponse {
    if req == nil {
        r := webauthn.BeginLoginRequest{}
        resp, err := webauthn.BeginLogin(r)
        if err != nil {
            return webauthn.BeginLoginResponse{}
        }
        return resp
    }
    resp, err := webauthn.BeginLogin(*req)
    if err != nil {
        return webauthn.BeginLoginResponse{}
    }
    return resp
}

// FinishWebAuthnLogin finishes assertion verification (skeleton) and returns success status.
func FinishWebAuthnLogin(req *webauthn.FinishLoginRequest) webauthn.FinishLoginResponse {
    if req == nil {
        r := webauthn.FinishLoginRequest{}
        resp, err := webauthn.FinishLogin(r)
        if err != nil {
            return webauthn.FinishLoginResponse{Success: false, Message: err.Error()}
        }
        return resp
    }
    resp, err := webauthn.FinishLogin(*req)
    if err != nil {
        return webauthn.FinishLoginResponse{Success: false, Message: err.Error()}
    }
    return resp
}
