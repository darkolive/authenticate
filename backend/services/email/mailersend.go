package email

import (
	"encoding/json"
	"fmt"

	"github.com/hypermodeinc/modus/sdk/go/pkg/http"
)

// Template ID configuration
var (
	OTPTemplateID     = "neqvygm91v8l0p7w"   // OTP email template ID
	WelcomeTemplateID = "vywj2lpz701g7oqz"  // Welcome email template ID
	DefaultTemplateID = "vywj2lpz701g7oqz"   // Default fallback template ID
)



// MailerSendProvider implements the EmailProvider interface for MailerSend
type MailerSendProvider struct {
	// No API key needed - authentication handled by Modus manifest
}

// NewMailerSendProvider creates a new MailerSend provider instance
func NewMailerSendProvider() EmailProvider {
	// Authentication is handled by Modus manifest, no API key needed
	return &MailerSendProvider{}
}

// SendEmail implements the EmailProvider interface for MailerSend
func (m *MailerSendProvider) SendEmail(req EmailRequest) (*EmailResponse, error) {
	// console.Log("📧 MailerSend: Starting email send process")
	// console.Log(fmt.Sprintf("📧 MailerSend: To=%s, From=%s, Subject=%s", req.To, req.From, req.Subject))
	// console.Log(fmt.Sprintf("📧 MailerSend: TemplateID=%s", req.TemplateID))
	
	// Build MailerSend API request
	payload := map[string]interface{}{
		"from": map[string]string{
			"email": req.From,
			"name":  "DO Study Platform",
		},
		"to": []map[string]string{
			{
				"email": req.To,
				"name":  "User",
			},
		},
		"subject": req.Subject,
	}

	// Add template and variables if provided
	if req.TemplateID != "" {
		// console.Log(fmt.Sprintf("📧 MailerSend: Using template ID: %s", req.TemplateID))
		payload["template_id"] = req.TemplateID
		if len(req.Variables) > 0 {
			// console.Log(fmt.Sprintf("📧 MailerSend: Template variables: %+v", req.Variables))
			personalization := []map[string]interface{}{
				{
					"email": req.To,
					"data":  req.Variables,
				},
			}
			payload["personalization"] = personalization
		}
	} else {
		// console.Log("📧 MailerSend: No template ID provided, sending plain email")
	}

	// Convert payload to JSON
	jsonPayload, err := json.Marshal(payload)
	if err != nil {
		// console.Error(fmt.Sprintf("🚨 MailerSend: Failed to marshal payload: %v", err))
		return &EmailResponse{
			Success: false,
			Error:   fmt.Sprintf("Failed to marshal payload: %v", err),
		}, err
	}
	// console.Log(fmt.Sprintf("📧 MailerSend: JSON payload: %s", string(jsonPayload)))

	// Make HTTP request using Modus connection
	// The URL must match the manifest baseUrl exactly
	url := "https://api.mailersend.com/v1/email/"
	// console.Log("🚀 MailerSend: Making HTTP POST request to MailerSend API")
	// console.Log("🔗 MailerSend: Request URL: " + url)
	// console.Log("📝 MailerSend: Request Method: POST")
	// console.Log(fmt.Sprintf("📝 MailerSend: Payload Size: %d bytes", len(jsonPayload)))
	request := http.NewRequest(url, &http.RequestOptions{
		Method: "POST",
		Body:   jsonPayload,
	})
	
	resp, err := http.Fetch(request)
	if err != nil {
		// console.Error(fmt.Sprintf("🚨 MailerSend: HTTP request failed: %v", err))
		return &EmailResponse{
			Success: false,
			Error:   fmt.Sprintf("HTTP request failed: %v", err),
		}, err
	}

	// console.Log(fmt.Sprintf("📊 MailerSend: HTTP Response Status: %d %s", resp.Status, resp.StatusText))
	// console.Log(fmt.Sprintf("📊 MailerSend: Response Body Length: %d bytes", len(resp.Body)))

	// Check if request was successful
	if !resp.Ok() {
		responseText := resp.Text()
		// console.Error(fmt.Sprintf("🚨 MailerSend: API Error - Status: %d, Response: %s", resp.Status, responseText))
		errorMsg := fmt.Sprintf("MailerSend API error: %d %s - %s", resp.Status, resp.StatusText, responseText)
		return &EmailResponse{
			Success: false,
			Error:   errorMsg,
		}, fmt.Errorf("%s", errorMsg)
	}

	// Handle response parsing - MailerSend may return empty body on success
	messageID := ""
	
	// console.Log("🔍 MailerSend: Parsing response body for message ID")
	// Try to parse response body if it exists
	if len(resp.Body) > 0 {
		// console.Log(fmt.Sprintf("📝 MailerSend: Response body: %s", string(resp.Body)))
		var response map[string]interface{}
		if err := json.Unmarshal(resp.Body, &response); err == nil {
			// console.Log(fmt.Sprintf("📝 MailerSend: Parsed response: %+v", response))
			// Check for API errors in response
			if errors, ok := response["errors"]; ok {
				// console.Error(fmt.Sprintf("🚨 MailerSend: API returned errors: %v", errors))
				return &EmailResponse{
					Success: false,
					Error:   fmt.Sprintf("MailerSend API errors: %v", errors),
				}, fmt.Errorf("MailerSend API errors: %v", errors)
			}
			
			// Extract message ID from response
			if data, ok := response["data"].(map[string]interface{}); ok {
				if id, ok := data["message_id"].(string); ok {
					messageID = id
					// console.Log(fmt.Sprintf("🆔 MailerSend: Extracted message ID: %s", messageID))
				}
			}
		} else {
			// console.Warn(fmt.Sprintf("⚠️ MailerSend: Failed to parse response JSON: %v", err))
		}
	} else {
		// console.Log("📝 MailerSend: Empty response body (normal for MailerSend success)")
	}
	
	// If no message ID from body, generate a placeholder since email was sent successfully
	if messageID == "" {
		messageID = fmt.Sprintf("sent-%d", resp.Status)
		// console.Log(fmt.Sprintf("🆔 MailerSend: Generated placeholder message ID: %s", messageID))
	}

	// console.Log("✅ MailerSend: Email sent successfully!")
	return &EmailResponse{
		Success:   true,
		MessageID: messageID,
		Message:   "Email sent successfully",
	}, nil
}

// SendOTPEmail implements the EmailProvider interface for OTP emails with MailerSend defaults
func (m *MailerSendProvider) SendOTPEmail(to, otpCode string) (*EmailResponse, error) {
	// Use configured template ID, fallback to default if empty
	templateID := OTPTemplateID
	if templateID == "" {
		templateID = DefaultTemplateID
	}
	
	req := EmailRequest{
		To:         to,
		From:       "darren@darkolive.co.uk",
		Subject:    "Your OTP Code",
		TemplateID: templateID,
		Variables: map[string]string{
			"otp_code": otpCode,
			"purpose":  "authentication",
			"expires":  "5 minutes",
		},
	}
	return m.SendEmail(req)
}

// SendWelcomeEmail implements the EmailProvider interface for welcome emails with MailerSend defaults
func (m *MailerSendProvider) SendWelcomeEmail(to, userName string) (*EmailResponse, error) {
	// Use configured template ID, fallback to default if empty
	templateID := WelcomeTemplateID
	if templateID == "" {
		templateID = DefaultTemplateID
	}
	
	req := EmailRequest{
		To:         to,
		From:       "darren@darkolive.co.uk",
		Subject:    "Welcome to DO Study!",
		TemplateID: templateID,
		Variables: map[string]string{
			"user_name": userName,
		},
	}
	return m.SendEmail(req)
}

// GetProviderName returns the name of this email provider
func (m *MailerSendProvider) GetProviderName() string {
	return "MailerSend"
}


