package main

import (
	cerberus "backend/agents/auth/CerberusMFA"
	charonotp "backend/agents/auth/CharonOTP"
	hecateregister "backend/agents/auth/HecateRegister"
	janusface "backend/agents/auth/JanusFace"
	persona "backend/agents/profile/Persona"
	sessions "backend/agents/sessions/ChronosSession"
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

// UpdateUserpersona persists basic persona fields (name/displayName) for the user.
func UpdateUserpersona(req *persona.UpdatepersonaRequest) persona.UpdatepersonaResponse {
    if req == nil {
        r := persona.UpdatepersonaRequest{}
        resp, err := persona.UpdateUserpersona(context.Background(), r)
        if err != nil {
            return persona.UpdatepersonaResponse{Success: false, Message: err.Error()}
        }
        return resp
    }
    resp, err := persona.UpdateUserpersona(context.Background(), *req)
    if err != nil {
        return persona.UpdatepersonaResponse{Success: false, Message: err.Error()}
    }
    return resp
}

// IspersonaComplete returns whether the user's persona has the minimum required fields.
func IspersonaComplete(req *persona.CompletepersonaRequest) persona.CompletepersonaResponse {
    if req == nil {
        r := persona.CompletepersonaRequest{}
        resp, err := persona.IspersonaComplete(r)
        if err != nil {
            return persona.CompletepersonaResponse{Complete: false, Message: err.Error()}
        }
        return resp
    }
    resp, err := persona.IspersonaComplete(*req)
    if err != nil {
        return persona.CompletepersonaResponse{Complete: false, Message: err.Error()}
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

// BeginjanusfaceRegistration starts janusface credential creation by returning options and a challenge.
func BeginjanusfaceRegistration(req *janusface.BeginRegistrationRequest) janusface.BeginRegistrationResponse {
    if req == nil {
        r := janusface.BeginRegistrationRequest{}
        resp, err := janusface.BeginRegistration(r)
        if err != nil {
            return janusface.BeginRegistrationResponse{}
        }
        return resp
    }
    resp, err := janusface.BeginRegistration(*req)
    if err != nil {
        return janusface.BeginRegistrationResponse{}
    }
    return resp
}

// FinishjanusfaceRegistration completes credential creation and stores the credential record.
func FinishjanusfaceRegistration(req *janusface.FinishRegistrationRequest) janusface.FinishRegistrationResponse {
    if req == nil {
        r := janusface.FinishRegistrationRequest{}
        resp, err := janusface.FinishRegistration(r)
        if err != nil {
            return janusface.FinishRegistrationResponse{Success: false, Message: err.Error()}
        }
        return resp
    }
    resp, err := janusface.FinishRegistration(*req)
    if err != nil {
        return janusface.FinishRegistrationResponse{Success: false, Message: err.Error()}
    }
    return resp
}

// BeginjanusfaceLogin starts an assertion by returning request options and a challenge.
func BeginjanusfaceLogin(req *janusface.BeginLoginRequest) janusface.BeginLoginResponse {
    if req == nil {
        r := janusface.BeginLoginRequest{}
        resp, err := janusface.BeginLogin(r)
        if err != nil {
            return janusface.BeginLoginResponse{}
        }
        return resp
    }
    resp, err := janusface.BeginLogin(*req)
    if err != nil {
        return janusface.BeginLoginResponse{}
    }
    return resp
}

// FinishjanusfaceLogin finishes assertion verification (skeleton) and returns success status.
func FinishjanusfaceLogin(req *janusface.FinishLoginRequest) janusface.FinishLoginResponse {
    if req == nil {
        r := janusface.FinishLoginRequest{}
        resp, err := janusface.FinishLogin(r)
        if err != nil {
            return janusface.FinishLoginResponse{Success: false, Message: err.Error()}
        }
        return resp
    }
    resp, err := janusface.FinishLogin(*req)
    if err != nil {
        return janusface.FinishLoginResponse{Success: false, Message: err.Error()}
    }
    return resp
}
