package main

import (
	charonotp "backend/agents/auth/CharonOTP"
	hecateregister "backend/agents/auth/HecateRegister"
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
