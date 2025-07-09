package utils

import (
	"time"

	"github.com/hashicorp/golang-lru/v2/expirable"
	"github.com/ilabs/wacht-fe/model"
)

var (
	// DeploymentCache stores deployment data with 5 second TTL and 2000 max keys
	DeploymentCache *expirable.LRU[string, *model.Deployment]

	// SessionCache stores session data with 5 second TTL and 2000 max keys
	SessionCache *expirable.LRU[uint64, *model.Session]
)

func init() {
	// Initialize deployment cache
	DeploymentCache = expirable.NewLRU[string, *model.Deployment](2000, nil, time.Second*30)

	// Initialize session cache
	SessionCache = expirable.NewLRU[uint64, *model.Session](2000, nil, time.Second*30)
}

// GetCachedDeployment attempts to retrieve a deployment from cache
func GetCachedDeployment(key string) (*model.Deployment, bool) {
	return DeploymentCache.Get(key)
}

// SetCachedDeployment stores a deployment in cache
func SetCachedDeployment(key string, deployment *model.Deployment) {
	DeploymentCache.Add(key, deployment)
}

// GetCachedSession attempts to retrieve a session from cache
func GetCachedSession(sessionID uint64) (*model.Session, bool) {
	return SessionCache.Get(sessionID)
}

// SetCachedSession stores a session in cache
func SetCachedSession(sessionID uint64, session *model.Session) {
	SessionCache.Add(sessionID, session)
}

// RemoveCachedSession removes a session from cache
func RemoveCachedSession(sessionID uint64) {
	SessionCache.Remove(sessionID)
}

// RemoveCachedDeployment removes a deployment from cache
func RemoveCachedDeployment(key string) {
	DeploymentCache.Remove(key)
}
