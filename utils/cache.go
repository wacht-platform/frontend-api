package utils

import (
	"time"

	"github.com/ilabs/wacht-fe/model"
	"github.com/jellydator/ttlcache/v3"
)

var (
	// DeploymentCache stores deployment data with 0 second TTL and 2000 max keys
	DeploymentCache *ttlcache.Cache[string, *model.Deployment]

	SessionCache *ttlcache.Cache[uint64, *model.Session]
)

func init() {
	// Initialize deployment cache
	DeploymentCache = ttlcache.New(
		ttlcache.WithTTL[string, *model.Deployment](30*time.Second),
		ttlcache.WithCapacity[string, *model.Deployment](2000),
	)
	go DeploymentCache.Start()

	// Initialize session cache
	SessionCache = ttlcache.New(
		ttlcache.WithTTL[uint64, *model.Session](30*time.Second),
		ttlcache.WithCapacity[uint64, *model.Session](2000),
	)
	go SessionCache.Start()
}

// GetCachedDeployment attempts to retrieve a deployment from cache
func GetCachedDeployment(key string) (*model.Deployment, bool) {
	item := DeploymentCache.Get(key)
	if item == nil {
		return nil, false
	}
	return item.Value(), true
}

// SetCachedDeployment stores a deployment in cache
func SetCachedDeployment(key string, deployment *model.Deployment) {
	DeploymentCache.Set(key, deployment, ttlcache.DefaultTTL)
}

// GetCachedSession attempts to retrieve a session from cache
func GetCachedSession(sessionID uint64) (*model.Session, bool) {
	item := SessionCache.Get(sessionID)
	if item == nil {
		return nil, false
	}
	return item.Value(), true
}

// SetCachedSession stores a session in cache
func SetCachedSession(sessionID uint64, session *model.Session) {
	SessionCache.Set(sessionID, session, ttlcache.DefaultTTL)
}

// RemoveCachedSession removes a session from cache
func RemoveCachedSession(sessionID uint64) {
	SessionCache.Delete(sessionID)
}

// RemoveCachedDeployment removes a deployment from cache
func RemoveCachedDeployment(key string) {
	DeploymentCache.Delete(key)
}
