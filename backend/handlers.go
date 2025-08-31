//go:build ignore

// Deprecated: API wrappers moved to main.go; this file is excluded from build.

package main

import (
	"context"
	"fmt"

	_ "github.com/hypermodeinc/modus/sdk/go"
	"github.com/hypermodeinc/modus/sdk/go/pkg/console"

	charonotp "backend/agents/auth/CharonOTP"
	hecateregister "backend/agents/auth/HecateRegister"
)

// SendOTP triggers generation and delivery of a one-time passcode.
// GraphQL: sendOTP(req: OTPRequest): OTPResponse
func SendOTP(req *charonotp.OTPRequest) charonotp.OTPResponse {
	console.Log("CharonOTP.SendOTP invoked (channel=" + req.Channel + ", recipient=redacted)")
	resp, err := charonotp.SendOTP(context.Background(), *req)
	if err != nil {
		console.Error("SendOTP error: " + err.Error())
		// Return a safe failure response without PII
		return charonotp.OTPResponse{
			OTPID:     "",
			Sent:      false,
			Verified:  false,
			Channel:   req.Channel,
			ExpiresAt: resp.ExpiresAt,
			Message:   fmt.Sprintf("failed to send OTP via %s", req.Channel),
		}
	}
	console.Log("CharonOTP.SendOTP completed successfully")
	return resp
}

// VerifyOTP validates an OTP sent to a recipient and routes next step.
// GraphQL: verifyOTP(req: VerifyOTPRequest): VerifyOTPResponse
func VerifyOTP(req *charonotp.VerifyOTPRequest) charonotp.VerifyOTPResponse {
	console.Log("CharonOTP.VerifyOTP invoked (recipient=redacted)")
	resp, err := charonotp.VerifyOTP(*req)
	if err != nil {
		console.Error("VerifyOTP error: " + err.Error())
		return charonotp.VerifyOTPResponse{
			Verified: false,
			Message:  "verification failed",
		}
	}
	console.Log("CharonOTP.VerifyOTP completed (verified=" + fmt.Sprintf("%t", resp.Verified) + ", action=" + resp.Action + ")")
	return resp
}

// CerberusMFA decides MFA path after channel verification.
// GraphQL: cerberusMFA(req: CerberusMFARequest): CerberusMFAResponse

// RegisterUser completes first-time registration after OTP verification.
// GraphQL: registerUser(req: UserRegistrationRequest): UserRegistrationResponse
func RegisterUser(req *hecateregister.UserRegistrationRequest) hecateregister.UserRegistrationResponse {
	console.Log("HecateRegister.RegisterUser invoked (channelType=" + req.ChannelType + ", recipient=redacted)")
	resp, err := hecateregister.RegisterUser(context.Background(), *req)
	if err != nil {
		console.Error("RegisterUser error: " + err.Error())
		return hecateregister.UserRegistrationResponse{
			Success: false,
			Message: "registration failed",
		}
	}
	return resp
}
