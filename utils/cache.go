package utils

import (
	"encoding/json"
	"net/http"
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
