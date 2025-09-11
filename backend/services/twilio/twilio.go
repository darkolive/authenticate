package twilio

import (
    "encoding/json"
    "encoding/base64"
    "fmt"
    "net/url"
    "os"
    "strings"
    "sync"

    "github.com/hypermodeinc/modus/sdk/go/pkg/console"
    "github.com/hypermodeinc/modus/sdk/go/pkg/http"
)

// normalizeE164 attempts to normalize a phone number to E.164 format using a
// default country code where needed. Minimal rules:
// - Remove spaces, dashes, parentheses
// - Strip leading "whatsapp:" (re-applied later if needed)
// - If starts with '+', assume already E.164
// - If starts with '00', convert to '+'
// - If starts with '0' and TWILIO_DEFAULT_COUNTRY_CODE is set, replace leading '0' with '+<CC>'
// - Otherwise return the cleaned number unchanged
func normalizeE164(input string, isWhatsApp bool) string {
    n := strings.TrimSpace(input)
    if strings.HasPrefix(strings.ToLower(n), "whatsapp:") {
        n = n[len("whatsapp:"):]
    }
    // strip common separators
    replacers := []string{" ", "-", "(", ")"}
    for _, r := range replacers {
        n = strings.ReplaceAll(n, r, "")
    }
    // apply normalization
    if strings.HasPrefix(n, "+") {
        // already E.164
    } else if strings.HasPrefix(n, "00") {
        n = "+" + n[2:]
    } else if strings.HasPrefix(n, "0") {
        // use default country code, if provided
        cc := strings.TrimSpace(os.Getenv("TWILIO_DEFAULT_COUNTRY_CODE"))
        if cc == "" {
            cc = strings.TrimSpace(os.Getenv("MODUS_TWILIO_TWILIO_DEFAULT_COUNTRY_CODE"))
        }
        if cc != "" {
            n = "+" + cc + n[1:]
        }
    }
    if isWhatsApp {
        if !strings.HasPrefix(strings.ToLower(n), "whatsapp:") {
            n = "whatsapp:" + n
        }
    }
    return n
}

// SendSMSOTP sends an OTP over SMS using Twilio Messages API.
func SendSMSOTP(to, otpCode string) error {
    body := fmt.Sprintf("Your verification code is %s. It expires in 5 minutes.", strings.TrimSpace(otpCode))
    to = normalizeE164(to, false)
    return sendMessage(to, body, false)
}

// SendWhatsAppOTP sends an OTP over WhatsApp using Twilio Messages API.
func SendWhatsAppOTP(to, otpCode string) error {
    body := fmt.Sprintf("Your verification code is %s. It expires in 5 minutes.", strings.TrimSpace(otpCode))
    to = normalizeE164(to, true)
    return sendMessage(to, body, true)
}

// sendMessage sends a text message via Twilio. If isWhatsApp is true, From should be a WhatsApp-enabled number with whatsapp: prefix
func sendMessage(to, body string, isWhatsApp bool) error {
    accountSID := strings.TrimSpace(os.Getenv("TWILIO_ACCOUNT_SID"))
    // Robust env loading: support Modus placeholder env as fallback
    if accountSID == "" {
        accountSID = strings.TrimSpace(os.Getenv("MODUS_TWILIO_TWILIO_ACCOUNT_SID"))
    }
    // Derive from Authorization Basic (AccountSID:AuthToken) if still empty
    if accountSID == "" {
        basic := strings.TrimSpace(os.Getenv("MODUS_TWILIO_TWILIO_BASIC_AUTH"))
        if basic != "" {
            if raw, err := base64.StdEncoding.DecodeString(basic); err == nil {
                parts := strings.SplitN(string(raw), ":", 2)
                if len(parts) > 0 && parts[0] != "" {
                    accountSID = parts[0]
                }
            }
        }
    }
    // As a last resort, fetch the authenticated account via Twilio API using the connection Authorization
    if accountSID == "" {
        var err error
        accountSID, err = getOrFetchAccountSID()
        if err != nil || accountSID == "" {
            return fmt.Errorf("TWILIO_ACCOUNT_SID is not set")
        }
    }

    // Prefer Messaging Service SID when present
    messagingServiceSid := strings.TrimSpace(os.Getenv("TWILIO_MESSAGING_SERVICE_SID"))
    if messagingServiceSid == "" {
        messagingServiceSid = strings.TrimSpace(os.Getenv("MODUS_TWILIO_TWILIO_MESSAGING_SERVICE_SID"))
    }
    // No fallback to fetch Messaging Service SID here (different API domain)

    from := ""
    if messagingServiceSid == "" {
        if isWhatsApp {
            from = strings.TrimSpace(os.Getenv("TWILIO_WHATSAPP_FROM"))
            if from == "" {
                from = "whatsapp:+14155238886" // Twilio sandbox default, can be overridden by env
            }
            if !strings.HasPrefix(strings.ToLower(from), "whatsapp:") {
                from = "whatsapp:" + from
            }
        } else {
            from = strings.TrimSpace(os.Getenv("TWILIO_SMS_FROM"))
            if from == "" {
                if f := getOrFetchSMSFromNumber(accountSID); f != "" {
                    from = f
                } else {
                    return fmt.Errorf("TWILIO_SMS_FROM is not set and TWILIO_MESSAGING_SERVICE_SID not provided")
                }
            }
        }
    }

    // Construct API URL. Must start with baseUrl defined in modus.json to receive injected headers.
    // baseUrl: https://api.twilio.com/2010-04-01/
    apiURL := fmt.Sprintf("https://api.twilio.com/2010-04-01/Accounts/%s/Messages.json", accountSID)

    // Build form data
    values := url.Values{}
    values.Set("To", to)
    values.Set("Body", body)
    if messagingServiceSid != "" {
        values.Set("MessagingServiceSid", messagingServiceSid)
    } else {
        values.Set("From", from)
    }
    payload := []byte(values.Encode())

    req := http.NewRequest(apiURL, &http.RequestOptions{
        Method: "POST",
        Body:   payload,
    })

    resp, err := http.Fetch(req)
    if err != nil {
        return fmt.Errorf("twilio request failed: %w", err)
    }

    // Parse response for diagnostics when not OK
    if !resp.Ok() {
        text := resp.Text()
        // Try to parse Twilio error JSON for clarity
        var parsed map[string]any
        if err := json.Unmarshal([]byte(text), &parsed); err == nil {
            if m, ok := parsed["message"].(string); ok && m != "" {
                return fmt.Errorf("twilio error: %s (%d %s)", m, resp.Status, resp.StatusText)
            }
        }
        return fmt.Errorf("twilio error: %d %s - %s", resp.Status, resp.StatusText, text)
    }

    console.Log(" Twilio message sent successfully")
    return nil
}

var (
    cachedAccountSID string
    fetchOnce        sync.Once
    fetchErr         error
)

// getOrFetchAccountSID retrieves and caches the primary Account SID using the connection's Authorization.
func getOrFetchAccountSID() (string, error) {
    fetchOnce.Do(func() {
        // Must start with baseUrl to receive injected headers
        url := "https://api.twilio.com/2010-04-01/Accounts.json"
        req := http.NewRequest(url, &http.RequestOptions{ Method: "GET" })
        resp, err := http.Fetch(req)
        if err != nil {
            fetchErr = fmt.Errorf("twilio accounts fetch failed: %w", err)
            return
        }
        if !resp.Ok() {
            fetchErr = fmt.Errorf("twilio accounts fetch error: %d %s - %s", resp.Status, resp.StatusText, resp.Text())
            return
        }
        // Parse minimal structure
        var body struct {
            Accounts []struct {
                SID string `json:"sid"`
            } `json:"accounts"`
        }
        if err := json.Unmarshal(resp.Body, &body); err != nil {
            fetchErr = fmt.Errorf("twilio accounts parse error: %w", err)
            return
        }
        if len(body.Accounts) == 0 || body.Accounts[0].SID == "" {
            fetchErr = fmt.Errorf("twilio accounts response missing sid")
            return
        }
        cachedAccountSID = body.Accounts[0].SID
    })
    return cachedAccountSID, fetchErr
}

// getOrFetchSMSFromNumber retrieves the SMS From number for the given Account SID.
func getOrFetchSMSFromNumber(accountSID string) string {
    if f, err := getSMSFromNumber(accountSID); err == nil && f != "" {
        return f
    } else {
        return strings.TrimSpace(os.Getenv("TWILIO_SMS_FROM"))
    }
}

// getSMSFromNumber retrieves the SMS From number for the given Account SID.
func getSMSFromNumber(accountSID string) (string, error) {
    // Must start with baseUrl to receive injected headers
    url := fmt.Sprintf("https://api.twilio.com/2010-04-01/Accounts/%s/IncomingPhoneNumbers.json", accountSID)
    req := http.NewRequest(url, &http.RequestOptions{ Method: "GET" })
    resp, err := http.Fetch(req)
    if err != nil {
        return "", fmt.Errorf("twilio incoming phone numbers fetch failed: %w", err)
    }
    if !resp.Ok() {
        return "", fmt.Errorf("twilio incoming phone numbers fetch error: %d %s - %s", resp.Status, resp.StatusText, resp.Text())
    }
    // Parse minimal structure
    var body struct {
        IncomingPhoneNumbers []struct {
            PhoneNumber string `json:"phone_number"`
        } `json:"incoming_phone_numbers"`
    }
    if err := json.Unmarshal(resp.Body, &body); err != nil {
        return "", fmt.Errorf("twilio incoming phone numbers parse error: %w", err)
    }
    if len(body.IncomingPhoneNumbers) == 0 || body.IncomingPhoneNumbers[0].PhoneNumber == "" {
        return "", fmt.Errorf("twilio incoming phone numbers response missing phone number")
    }
    return body.IncomingPhoneNumbers[0].PhoneNumber, nil
}
