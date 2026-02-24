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
		ttlcache.WithTTL[string, any](20*time.Second),
		ttlcache.WithDisableTouchOnHit[string, any](),
	)
	go Cache.Start()
}

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

func SetCachedDeployment(key string, deployment *model.Deployment) {
	Cache.Set(key, deployment, 300*time.Second)
}

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

func SetCachedSession(sessionID uint64, session *model.Session) {
	Cache.Set(fmt.Sprintf("%d", sessionID), session, 5*time.Second)
}

func RemoveCachedSession(sessionID uint64) {
	Cache.Delete(fmt.Sprintf("%d", sessionID))
}

func RemoveCachedDeployment(key string) {
	Cache.Delete(key)
}
