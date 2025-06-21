package utils

import (
	"bytes"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"

	"github.com/ilabs/wacht-fe/database"
	"github.com/ilabs/wacht-fe/model"
)

func GetSession(sessionID uint64) (*model.Session, error) {
	resp, err := http.Get(os.Getenv("CACHE_WORKER") + "?q=" + fmt.Sprintf("%d", sessionID))
	if err == nil && resp.StatusCode == 200 {
		defer resp.Body.Close()
		session := new(model.Session)
		if json.NewDecoder(resp.Body).Decode(&session) == nil {
			return session, nil
		}
	}

	session := &model.Session{}
	if err := database.Connection.First(session, sessionID).Error; err != nil {
		return nil, err
	}

	go SetSessionCache(*session)

	return session, nil
}

func SetSessionCache(session model.Session) {
	url := fmt.Sprintf(
		"https://api.cloudflare.com/client/v4/accounts/%s/storage/kv/namespaces/%s/values/%d",
		os.Getenv("CLOUDFLARE_ACCOUNT_ID"),
		os.Getenv("CLOUDFLARE_NAMESPACE_ID"),
		session.ID,
	)

	payload, err := json.Marshal(map[string]any{
		"value":          session,
		"expiration_ttl": 86400,
	})
	if err != nil {
		return
	}

	req, err := http.NewRequest(
		"PUT",
		url,
		bytes.NewBuffer(payload),
	)

	req.Header.Set("Authorization", "Bearer "+os.Getenv("CLOUDFLARE_API_KEY"))
	req.Header.Set("Content-Type", "application/json")

	_, err = http.DefaultClient.Do(req)
	if err != nil {
		log.Println("Error setting session cache: ", err)
		return
	}
}
