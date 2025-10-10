package email

import (
	"fmt"
	"sync"

	"github.com/hypermodeinc/modus/sdk/go/pkg/console"
)

// mail_service defines which email service to use (mailersend, hermes, etc.)
var mail_service = "mailersend"

// DefaultFromEmail is the default sender address used when none is provided
var DefaultFromEmail = "darren@darkolive.co.uk"

// EmailRequest represents the parameters needed to send an email
type EmailRequest struct {
	To           string            `json:"to"`
	From         string            `json:"from"`
	Subject      string            `json:"subject"`
	TemplateID   string            `json:"template_id"`
	Variables    map[string]string `json:"variables,omitempty"`
	Personalization []map[string]interface{} `json:"personalization,omitempty"`
}

// EmailResponse represents the response from the email service
type EmailResponse struct {
	Success   bool   `json:"success"`
	MessageID string `json:"message_id"`
	Message   string `json:"message"`
	Error     string `json:"error,omitempty"`
}

// EmailProvider defines the interface that all email providers must implement
type EmailProvider interface {
	SendEmail(req EmailRequest) (*EmailResponse, error)
	SendOTPEmail(to, otpCode string) (*EmailResponse, error)
	SendWelcomeEmail(to, userName string) (*EmailResponse, error)
	GetProviderName() string
}

// EmailService manages email providers and routing
type EmailService struct {
	primaryProvider   EmailProvider
	fallbackProvider  EmailProvider
	enableFallback    bool
	asyncQueue        *AsyncEmailQueue
	useAsyncQueue     bool
	mutex            sync.RWMutex
}

// Global email service instance
var defaultService *EmailService

// Initialize the email service with the configured mail provider
func init() {
	var primaryProvider EmailProvider
	
	// Use the mail_service variable to determine which provider to initialize
	switch mail_service {
	case "mailersend":
		primaryProvider = NewMailerSendProvider()
	default:
		// Default to MailerSend if unknown service specified
		primaryProvider = NewMailerSendProvider()
	}
	
	defaultService = &EmailService{
		primaryProvider:  primaryProvider,
		fallbackProvider: nil, // Can be set later for redundancy
		enableFallback:   false,
		// Note: Async queue disabled due to WASM goroutine limitations
		asyncQueue:       nil,
		useAsyncQueue:    false,
	}
}

// SetPrimaryProvider allows switching the primary email provider
func SetPrimaryProvider(provider EmailProvider) {
	defaultService.mutex.Lock()
	defer defaultService.mutex.Unlock()
	defaultService.primaryProvider = provider
}

// SetFallbackProvider sets a fallback provider for redundancy
func SetFallbackProvider(provider EmailProvider) {
	defaultService.mutex.Lock()
	defer defaultService.mutex.Unlock()
	defaultService.fallbackProvider = provider
	defaultService.enableFallback = true
}

// SendEmail sends an email using the configured provider
func SendEmail(req EmailRequest) (*EmailResponse, error) {
	return defaultService.SendEmail(req)
}

// SendOTPEmail sends an OTP email using the configured provider
func SendOTPEmail(to, otpCode string) (*EmailResponse, error) {
	return defaultService.SendOTPEmail(to, otpCode)
}

// SendOTPEmailAsync queues an OTP email for async sending
func SendOTPEmailAsync(to, otpCode string) (*EmailResponse, error) {
	return defaultService.SendOTPEmailAsync(to, otpCode)
}

// SendWelcomeEmail sends a welcome email using the configured provider
func SendWelcomeEmail(to, userName string) (*EmailResponse, error) {
	return defaultService.SendWelcomeEmail(to, userName)
}

// SendWelcomeEmailAsync queues a welcome email for async sending
func SendWelcomeEmailAsync(to, userName string) (*EmailResponse, error) {
	return defaultService.SendWelcomeEmailAsync(to, userName)
}

// GetProviderInfo returns information about the current email provider
func GetProviderInfo() string {
	defaultService.mutex.RLock()
	defer defaultService.mutex.RUnlock()
	return defaultService.primaryProvider.GetProviderName()
}

// EmailService methods

func (s *EmailService) SendEmail(req EmailRequest) (*EmailResponse, error) {
	console.Log("📧 EmailService: Starting email send process")
	console.Log(fmt.Sprintf("📧 EmailService: Provider=%s, To=%s, Subject=%s", s.primaryProvider.GetProviderName(), req.To, req.Subject))
	
	if s.useAsyncQueue {
		err := s.asyncQueue.QueueEmail(req, nil, nil)
		if err != nil {
			console.Error(fmt.Sprintf("🚨 EmailService: Failed to queue email: %v", err))
			// Fall back to synchronous sending
		} else {
			console.Log("⚡ EmailService: Email queued for async processing")
			return &EmailResponse{
				Success:   true,
				MessageID: "queued",
				Message:   "Email queued for sending",
			}, nil
		}
	}
	
	// Try primary provider first
	console.Log(fmt.Sprintf("🚀 EmailService: Using primary provider: %s", s.primaryProvider.GetProviderName()))
	response, err := s.primaryProvider.SendEmail(req)
	
	// If primary fails and fallback is enabled, try fallback
	if err != nil && s.enableFallback && s.fallbackProvider != nil {
		console.Warn(fmt.Sprintf("⚠️ EmailService: Primary provider (%s) failed, trying fallback (%s)", 
			s.primaryProvider.GetProviderName(), 
			s.fallbackProvider.GetProviderName()))
		return s.fallbackProvider.SendEmail(req)
	}
	
	if err != nil {
		console.Error(fmt.Sprintf("🚨 EmailService: Email sending failed: %v", err))
	} else {
		console.Log("✅ EmailService: Email sent successfully")
	}
	
	return response, err
}

func (s *EmailService) SendOTPEmail(to, otpCode string) (*EmailResponse, error) {
	console.Log("🔐 EmailService: Sending OTP email")
	console.Log(fmt.Sprintf("🔐 EmailService: To=%s, Provider=%s", to, s.primaryProvider.GetProviderName()))
	
	response, err := s.primaryProvider.SendOTPEmail(to, otpCode)
	
	if err != nil {
		console.Error(fmt.Sprintf("🚨 EmailService: OTP email failed: %v", err))
	} else {
		console.Log("✅ EmailService: OTP email sent successfully")
	}
	
	return response, err
}

func (s *EmailService) SendWelcomeEmail(to, userName string) (*EmailResponse, error) {
	console.Log("👋 EmailService: Sending Welcome email")
	console.Log(fmt.Sprintf("👋 EmailService: To=%s, UserName=%s, Provider=%s", to, userName, s.primaryProvider.GetProviderName()))
	
	response, err := s.primaryProvider.SendWelcomeEmail(to, userName)
	
	if err != nil {
		console.Error(fmt.Sprintf("🚨 EmailService: Welcome email failed: %v", err))
	} else {
		console.Log("✅ EmailService: Welcome email sent successfully")
	}
	
	return response, err
}

// SendOTPEmailAsync queues an OTP email for async processing
func (s *EmailService) SendOTPEmailAsync(to, otpCode string) (*EmailResponse, error) {
	console.Log("⚡ EmailService: Queuing OTP email for async processing")
	
	if !s.useAsyncQueue || s.asyncQueue == nil {
		console.Warn("⚠️ EmailService: Async queue not available, falling back to sync")
		return s.SendOTPEmail(to, otpCode)
	}
	
	// Use the provider's SendOTPEmail method via queue
	req := EmailRequest{
		To:         to,
		From:       DefaultFromEmail,
		Subject:    "Your OTP Code",
		TemplateID: OTPTemplateID, // Use provider-configured default
		Variables: map[string]string{
			"otp_code": otpCode,
			"purpose":  "authentication",
			"expires":  "5 minutes",
		},
	}
	
	err := s.asyncQueue.QueueEmail(req, 
		func(resp *EmailResponse) {
			console.Log(fmt.Sprintf("✅ Async OTP email sent successfully to %s", to))
		},
		func(err error) {
			console.Error(fmt.Sprintf("🚨 Async OTP email failed for %s: %v", to, err))
		},
	)
	
	if err != nil {
		console.Error(fmt.Sprintf("🚨 EmailService: Failed to queue OTP email: %v", err))
		return s.SendOTPEmail(to, otpCode) // Fall back to sync
	}
	
	return &EmailResponse{
		Success:   true,
		MessageID: "queued",
		Message:   "OTP email queued for sending",
	}, nil
}

// SendWelcomeEmailAsync queues a welcome email for async processing  
func (s *EmailService) SendWelcomeEmailAsync(to, userName string) (*EmailResponse, error) {
	console.Log("⚡ EmailService: Queuing Welcome email for async processing")
	
	if !s.useAsyncQueue || s.asyncQueue == nil {
		console.Warn("⚠️ EmailService: Async queue not available, falling back to sync")
		return s.SendWelcomeEmail(to, userName)
	}
	
	// Use the provider's SendWelcomeEmail method via queue
	req := EmailRequest{
		To:         to,
		From:       DefaultFromEmail,
		Subject:    "Welcome to DO Study!",
		TemplateID: WelcomeTemplateID, // Use provider-configured default
		Variables: map[string]string{
			"user_name": userName,
		},
	}
	
	err := s.asyncQueue.QueueEmail(req,
		func(resp *EmailResponse) {
			console.Log(fmt.Sprintf("✅ Async Welcome email sent successfully to %s", to))
		},
		func(err error) {
			console.Error(fmt.Sprintf("🚨 Async Welcome email failed for %s: %v", to, err))
		},
	)
	
	if err != nil {
		console.Error(fmt.Sprintf("🚨 EmailService: Failed to queue Welcome email: %v", err))
		return s.SendWelcomeEmail(to, userName) // Fall back to sync
	}
	
	return &EmailResponse{
		Success:   true,
		MessageID: "queued",
		Message:   "Welcome email queued for sending",
	}, nil
}

