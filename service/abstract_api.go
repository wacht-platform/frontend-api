package service

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"
)

type AbstractAPIService struct {
	APIKey  string
	BaseURL string
}

type AbstractAPIResponse struct {
	PhoneNumber string `json:"phone_number"`
	PhoneFormat struct {
		International string `json:"international"`
		National      string `json:"national"`
	} `json:"phone_format"`
	PhoneCarrier struct {
		Name     string `json:"name"`
		LineType string `json:"line_type"`
		MCC      string `json:"mcc"`
		MNC      string `json:"mnc"`
	} `json:"phone_carrier"`
	PhoneLocation struct {
		CountryName   string `json:"country_name"`
		CountryCode   string `json:"country_code"`
		CountryPrefix string `json:"country_prefix"`
		Region        string `json:"region"`
		City          string `json:"city"`
		Timezone      string `json:"timezone"`
	} `json:"phone_location"`
	PhoneValidation struct {
		IsValid    bool   `json:"is_valid"`
		LineStatus string `json:"line_status"`
		IsVOIP     bool   `json:"is_voip"`
		MinimumAge int    `json:"minimum_age,omitempty"`
	} `json:"phone_validation"`
	PhoneRisk *struct {
		RiskLevel       string `json:"risk_level"`
		IsDisposable    bool   `json:"is_disposable"`
		IsAbuseDetected bool   `json:"is_abuse_detected"`
	} `json:"phone_risk,omitempty"`
	Error *struct {
		Message string `json:"message"`
		Code    string `json:"code"`
	} `json:"error,omitempty"`
}

type PhoneValidationResult struct {
	IsValid       bool
	PhoneType     string
	PhoneTypeCode string
	IsBlocked     bool
	IsVOIP        bool
	IsPrepaid     bool
	IsHighRisk    bool
	CountryCode   string
	CarrierName   string
	ErrorMessage  string
}

func NewAbstractAPIService(apiKey string) *AbstractAPIService {
	return &AbstractAPIService{
		APIKey:  apiKey,
		BaseURL: "https://phoneintelligence.abstractapi.com/v1/",
	}
}

func (a *AbstractAPIService) ValidatePhoneNumber(phoneNumber string) (*PhoneValidationResult, error) {
	cleanedNumber := strings.ReplaceAll(phoneNumber, " ", "")
	cleanedNumber = strings.ReplaceAll(cleanedNumber, "-", "")
	cleanedNumber = strings.ReplaceAll(cleanedNumber, "(", "")
	cleanedNumber = strings.ReplaceAll(cleanedNumber, ")", "")

	reqURL := fmt.Sprintf("%s?api_key=%s&phone=%s",
		a.BaseURL,
		url.QueryEscape(a.APIKey),
		url.QueryEscape(cleanedNumber),
	)

	req, err := http.NewRequest("GET", reqURL, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %v", err)
	}

	req.Header.Set("Accept", "application/json")

	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to make request: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return &PhoneValidationResult{
			IsValid:      false,
			ErrorMessage: fmt.Sprintf("Abstract API returned status %d", resp.StatusCode),
		}, nil
	}

	var abstractResp AbstractAPIResponse
	if err := json.NewDecoder(resp.Body).Decode(&abstractResp); err != nil {
		return nil, fmt.Errorf("failed to decode response: %v", err)
	}

	if abstractResp.Error != nil {
		return &PhoneValidationResult{
			IsValid:      false,
			ErrorMessage: abstractResp.Error.Message,
		}, nil
	}

	result := &PhoneValidationResult{
		IsValid:     abstractResp.PhoneValidation.IsValid,
		IsVOIP:      abstractResp.PhoneValidation.IsVOIP,
		CountryCode: abstractResp.PhoneLocation.CountryCode,
		CarrierName: abstractResp.PhoneCarrier.Name,
		PhoneType:   abstractResp.PhoneCarrier.LineType,
	}

	lineType := strings.ToLower(abstractResp.PhoneCarrier.LineType)
	if strings.Contains(lineType, "voip") || strings.Contains(lineType, "virtual") {
		result.IsVOIP = true
	}

	if strings.Contains(lineType, "prepaid") {
		result.IsPrepaid = true
	}

	if abstractResp.PhoneRisk != nil {
		result.IsHighRisk = abstractResp.PhoneRisk.RiskLevel == "high" ||
			abstractResp.PhoneRisk.IsDisposable ||
			abstractResp.PhoneRisk.IsAbuseDetected
	}

	if abstractResp.PhoneValidation.LineStatus == "inactive" {
		result.IsHighRisk = true
	}

	return result, nil
}
