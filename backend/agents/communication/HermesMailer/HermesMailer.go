package hermesmailer

import (
	"context"
	"fmt"

	"backend/services/email"
)

type HermesMailer struct {
	// No client needed - we'll use Modus HTTP connections
}

func NewHermesMailer(apiKey string) *HermesMailer {
	// API key is handled by modus.json connection
	return &HermesMailer{}
}

type SendTemplateRequest struct {
	FromName   string            `json:"fromName"`
	FromEmail  string            `json:"fromEmail"`
	ToName     string            `json:"toName"`
	ToEmail    string            `json:"toEmail"`
	Subject    string            `json:"subject"`
	TemplateID string            `json:"templateId"`
	Variables  map[string]string `json:"variables"`
	Tags       []string          `json:"tags,omitempty"`
}

type SendTemplateResponse struct {
	MessageID string `json:"messageId"`
}

func (h *HermesMailer) Send(ctx context.Context, req *SendTemplateRequest) (*SendTemplateResponse, error) {
	// Delegate to central email service (provider-specific logic lives in services/email)
	eReq := email.EmailRequest{
		To:         req.ToEmail,
		From:       req.FromEmail,
		Subject:    req.Subject,
		TemplateID: req.TemplateID,
		Variables:  req.Variables,
	}

	resp, err := email.SendEmail(eReq)
	if err != nil {
		return nil, err
	}
	if resp == nil || !resp.Success {
		if resp != nil && resp.Error != "" {
			return nil, fmt.Errorf("email send failed: %s", resp.Error)
		}
		return nil, fmt.Errorf("email send failed: unknown error")
	}

	return &SendTemplateResponse{MessageID: resp.MessageID}, nil
}