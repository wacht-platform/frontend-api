package service

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"
)

type TelesignService struct {
	CustomerID string
	APIKey     string
	BaseURL    string
}

type TelesignPhoneIDResponse struct {
	ReferenceID string `json:"reference_id"`
	PhoneType   struct {
		Code               string `json:"code"`
		OverrideReason     string `json:"override_reason"`
		Description        string `json:"description"`
		OverrideReasonID   int    `json:"override_reason_id"`
	} `json:"phone_type"`
	Blocklisting struct {
		BlockCode        int    `json:"block_code"`
		BlockDescription string `json:"block_description"`
		Blocked          bool   `json:"blocked"`
	} `json:"blocklisting"`
	Status struct {
		Code        int       `json:"code"`
		Description string    `json:"description"`
		UpdatedOn   time.Time `json:"updated_on"`
	} `json:"status"`
	Numbering struct {
		Original struct {
			PhoneNumber         string `json:"phone_number"`
			CompletePhoneNumber string `json:"complete_phone_number"`
			CountryCode         string `json:"country_code"`
		} `json:"original"`
		Cleansing struct {
			Call struct {
				CleansedCode int    `json:"cleansed_code"`
				CountryCode  string `json:"country_code"`
				MaxLength    int    `json:"max_length"`
				MinLength    int    `json:"min_length"`
				PhoneNumber  string `json:"phone_number"`
			} `json:"call"`
			SMS struct {
				CleansedCode int    `json:"cleansed_code"`
				CountryCode  string `json:"country_code"`
				MaxLength    int    `json:"max_length"`
				MinLength    int    `json:"min_length"`
				PhoneNumber  string `json:"phone_number"`
			} `json:"sms"`
		} `json:"cleansing"`
	} `json:"numbering"`
	Location struct {
		City     string `json:"city"`
		County   string `json:"county"`
		State    string `json:"state"`
		Zip      string `json:"zip"`
		Country  struct {
			ISO2 string `json:"iso2"`
			ISO3 string `json:"iso3"`
			Name string `json:"name"`
		} `json:"country"`
		TimeZone struct {
			Name         string `json:"name"`
			UTCOffsetMax string `json:"utc_offset_max"`
			UTCOffsetMin string `json:"utc_offset_min"`
		} `json:"time_zone"`
		Coordinates struct {
			Latitude  float64 `json:"latitude"`
			Longitude float64 `json:"longitude"`
		} `json:"coordinates"`
		MetroCode string `json:"metro_code"`
	} `json:"location"`
	Carrier struct {
		CarrierID int    `json:"carrier_id"`
		Name      string `json:"name"`
		MCC       string `json:"mcc"`
		MNC       string `json:"mnc"`
	} `json:"carrier"`
}

type PhoneValidationResult struct {
	IsValid        bool
	PhoneType      string
	PhoneTypeCode  string
	IsBlocked      bool
	IsVOIP         bool
	IsPrepaid      bool
	IsHighRisk     bool
	CountryCode    string
	CarrierName    string
	ErrorMessage   string
}

func NewTelesignService(customerID, apiKey string) *TelesignService {
	return &TelesignService{
		CustomerID: customerID,
		APIKey:     apiKey,
		BaseURL:    "https://rest-ww.telesign.com/v1",
	}
}

func (t *TelesignService) ValidatePhoneNumber(phoneNumber string) (*PhoneValidationResult, error) {
	// Clean phone number (remove non-digits)
	cleanedNumber := strings.ReplaceAll(phoneNumber, "+", "")
	cleanedNumber = strings.ReplaceAll(cleanedNumber, "-", "")
	cleanedNumber = strings.ReplaceAll(cleanedNumber, " ", "")
	cleanedNumber = strings.ReplaceAll(cleanedNumber, "(", "")
	cleanedNumber = strings.ReplaceAll(cleanedNumber, ")", "")

	url := fmt.Sprintf("%s/phoneid/%s", t.BaseURL, cleanedNumber)

	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %v", err)
	}

	req.SetBasicAuth(t.CustomerID, t.APIKey)
	req.Header.Set("Accept", "application/json")
	req.Header.Set("Content-Type", "application/json")

	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to make request: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return &PhoneValidationResult{
			IsValid:      false,
			ErrorMessage: fmt.Sprintf("Telesign API returned status %d", resp.StatusCode),
		}, nil
	}

	var telesignResp TelesignPhoneIDResponse
	if err := json.NewDecoder(resp.Body).Decode(&telesignResp); err != nil {
		return nil, fmt.Errorf("failed to decode response: %v", err)
	}

	result := &PhoneValidationResult{
		IsValid:       telesignResp.Status.Code == 300,
		PhoneType:     telesignResp.PhoneType.Description,
		PhoneTypeCode: telesignResp.PhoneType.Code,
		IsBlocked:     telesignResp.Blocklisting.Blocked,
		CountryCode:   telesignResp.Numbering.Original.CountryCode,
		CarrierName:   telesignResp.Carrier.Name,
	}

	switch telesignResp.PhoneType.Code {
	case "1":
		result.IsHighRisk = false
		result.IsVOIP = false
		result.IsPrepaid = false
	case "2":
		result.IsHighRisk = false
		result.IsVOIP = false
		result.IsPrepaid = false
	case "3": 
		result.IsHighRisk = true
		result.IsVOIP = false
		result.IsPrepaid = true
	case "4": 
		result.IsHighRisk = true
		result.IsVOIP = false
		result.IsPrepaid = false
	case "5": 
		result.IsHighRisk = true
		result.IsVOIP = true
		result.IsPrepaid = false
	case "6": 
		result.IsHighRisk = true
		result.IsVOIP = false
		result.IsPrepaid = false
	case "7": 
		result.IsHighRisk = true
		result.IsVOIP = false
		result.IsPrepaid = false
	case "8": 
		result.IsHighRisk = true
		result.IsValid = false
		result.IsVOIP = false
		result.IsPrepaid = false
	case "9": /
		result.IsHighRisk = true
		result.IsVOIP = false
		result.IsPrepaid = false
	case "10":
		result.IsHighRisk = false
		result.IsVOIP = false
		result.IsPrepaid = false
	case "11":
		result.IsHighRisk = true
		result.IsVOIP = false
		result.IsPrepaid = false
	case "20": 
		result.IsHighRisk = true
		result.IsVOIP = false
		result.IsPrepaid = false
	default:
		result.IsHighRisk = true
	}

	return result, nil
}
