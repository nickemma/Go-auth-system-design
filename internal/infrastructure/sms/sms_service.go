package sms

import (
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/http"
	"net/url"
	"strings"
)

type SMSService interface {
	SendOTP(phoneNumber, code string) error
	IsEnabled() bool
}

type TwilioSMSService struct {
	accountSID string
	authToken  string
	fromNumber string
	enabled    bool
}

type TwilioResponse struct {
	SID          string `json:"sid"`
	Status       string `json:"status"`
	ErrorCode    string `json:"error_code,omitempty"`
	ErrorMessage string `json:"error_message,omitempty"`
}

func NewTwilioSMSService(accountSID, authToken, fromNumber string) *TwilioSMSService {
	enabled := accountSID != "" && authToken != "" && fromNumber != ""

	service := &TwilioSMSService{
		accountSID: accountSID,
		authToken:  authToken,
		fromNumber: fromNumber,
		enabled:    enabled,
	}

	if !enabled {
		log.Println("Twilio SMS service initialized but disabled (missing credentials)")
	} else {
		log.Println("Twilio SMS service initialized and enabled")
	}

	return service
}

func (t *TwilioSMSService) IsEnabled() bool {
	return t.enabled
}

func (t *TwilioSMSService) SendOTP(phoneNumber, code string) error {
	if !t.enabled {
		return errors.New("SMS service is not configured Please set up Twilio credentials.")
	}

	// Validate phone number format
	if !strings.HasPrefix(phoneNumber, "+") {
		return errors.New("phone number must include country code (e.g., +1234567890)")
	}

	message := fmt.Sprintf("Your verification code is: %s. Valid for 5 minutes.", code)

	// Prepare the request
	apiURL := fmt.Sprintf("https://api.twilio.com/2010-04-01/Accounts/%s/Messages.json", t.accountSID)

	data := url.Values{}
	data.Set("To", phoneNumber)
	data.Set("From", t.fromNumber)
	data.Set("Body", message)

	// Create HTTP request
	req, err := http.NewRequest("POST", apiURL, strings.NewReader(data.Encode()))
	if err != nil {
		return fmt.Errorf("failed to create request: %v", err)
	}

	// Set headers
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.SetBasicAuth(t.accountSID, t.authToken)

	// Make the request
	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("failed to send request: %v", err)
	}
	defer resp.Body.Close()

	// Parse response
	var twilioResp TwilioResponse
	if err := json.NewDecoder(resp.Body).Decode(&twilioResp); err != nil {
		return fmt.Errorf("failed to decode response: %v", err)
	}

	// Check for errors
	if resp.StatusCode != http.StatusCreated {
		errorMsg := fmt.Sprintf("Twilio API error (status %d)", resp.StatusCode)
		if twilioResp.ErrorMessage != "" {
			errorMsg += ": " + twilioResp.ErrorMessage
		}
		return errors.New(errorMsg)
	}

	log.Printf("SMS sent successfully to %s. SID: %s, Status: %s", phoneNumber, twilioResp.SID, twilioResp.Status)

	return nil
}

// Helper function to format phone number
func (t *TwilioSMSService) FormatPhoneNumber(phoneNumber string) string {
	// Remove any spaces, dashes, or parentheses
	cleaned := strings.ReplaceAll(phoneNumber, " ", "")
	cleaned = strings.ReplaceAll(cleaned, "-", "")
	cleaned = strings.ReplaceAll(cleaned, "(", "")
	cleaned = strings.ReplaceAll(cleaned, ")", "")

	// Add + if not present
	if !strings.HasPrefix(cleaned, "+") {
		// Assume US number if no country code
		if len(cleaned) == 10 {
			cleaned = "+1" + cleaned
		} else if !strings.HasPrefix(cleaned, "+") {
			cleaned = "+" + cleaned
		}
	}

	return cleaned
}
