package utils

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
)

type CacheResponse[T any] struct {
	Value          T      `json:"value"`
	Expiration_ttl uint64 `json:"expiration_ttl"`
}

func GetFromCache[T any](resp *http.Response, target *T) error {
	defer resp.Body.Close()
	cacheResp := &CacheResponse[T]{Value: *target}
	if err := json.NewDecoder(resp.Body).Decode(&cacheResp); err != nil {
		return err
	}
	*target = cacheResp.Value
	return nil
}

func GetValueFromCache[T any](key string, target *T) error {
	url := fmt.Sprintf(
		"https://api.cloudflare.com/client/v4/accounts/%s/storage/kv/namespaces/%s/values/%s",
		os.Getenv("CLOUDFLARE_ACCOUNT_ID"),
		os.Getenv("CLOUDFLARE_NAMESPACE_ID"),
		key,
	)

	resp, err := http.Get(url)
	if err != nil {
		return err
	}

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("failed to get from cache. status: %s", resp.Status)
	}

	return GetFromCache(resp, target)
}

func SetToCache(key string, value any, ttl uint64) error {
	url := fmt.Sprintf(
		"https://api.cloudflare.com/client/v4/accounts/%s/storage/kv/namespaces/%s/values/%s",
		os.Getenv("CLOUDFLARE_ACCOUNT_ID"),
		os.Getenv("CLOUDFLARE_NAMESPACE_ID"),
		key,
	)

	payload, err := json.Marshal(map[string]any{
		"value":          value,
		"expiration_ttl": ttl,
	})
	if err != nil {
		return err
	}

	req, err := http.NewRequest(
		"PUT",
		url,
		bytes.NewBuffer(payload),
	)
	if err != nil {
		return err
	}

	req.Header.Set("Authorization", "Bearer "+os.Getenv("CLOUDFLARE_API_KEY"))
	req.Header.Set("Content-Type", "application/json")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("failed to set to cache. status: %s", resp.Status)
	}

	return nil
}

func DeleteFromCache(key string) error {
	url := fmt.Sprintf(
		"https://api.cloudflare.com/client/v4/accounts/%s/storage/kv/namespaces/%s/values/%s",
		os.Getenv("CLOUDFLARE_ACCOUNT_ID"),
		os.Getenv("CLOUDFLARE_NAMESPACE_ID"),
		key,
	)

	req, err := http.NewRequest(
		"DELETE",
		url,
		nil,
	)
	if err != nil {
		return err
	}

	req.Header.Set("Authorization", "Bearer "+os.Getenv("CLOUDFLARE_API_KEY"))

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("failed to delete from cache. status: %s", resp.Status)
	}

	return nil
}
