package utils

import (
	"fmt"
	"time"

	"github.com/ilabs/wacht-fe/model"
	"github.com/jellydator/ttlcache/v3"
)

var (
	Cache *ttlcache.Cache[string, any]
)

func init() {
	Cache = ttlcache.New(
		ttlcache.WithTTL[string, any](30 * time.Second),
	)
	go Cache.Start()
}

// GetCachedDeployment attempts to retrieve a deployment from cache
func GetCachedDeployment(key string) (*model.Deployment, bool) {
	if !Cache.Has(key) {
		return nil, false
	}
	cache := Cache.Get(key)
	if cache == nil {
		return nil, false
	}
	return cache.Value().(*model.Deployment), true
}

// SetCachedDeployment stores a deployment in cache
func SetCachedDeployment(key string, deployment *model.Deployment) {
	Cache.Set(key, deployment, 30*time.Second)
}

// GetCachedSession attempts to retrieve a session from cache
func GetCachedSession(sessionID uint64) (*model.Session, bool) {
	if !Cache.Has(fmt.Sprintf("%d", sessionID)) {
		return nil, false
	}
	cache := Cache.Get(fmt.Sprintf("%d", sessionID))
	if cache == nil {
		return nil, false
	}
	return cache.Value().(*model.Session), true
}

// SetCachedSession stores a session in cache
func SetCachedSession(sessionID uint64, session *model.Session) {
	Cache.Set(fmt.Sprintf("%d", sessionID), session, 30*time.Second)
}

// RemoveCachedSession removes a session from cache
func RemoveCachedSession(sessionID uint64) {
	Cache.Delete(fmt.Sprintf("%d", sessionID))
}

// RemoveCachedDeployment removes a deployment from cache
func RemoveCachedDeployment(key string) {
	Cache.Delete(key)
}
