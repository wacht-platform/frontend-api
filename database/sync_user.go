package database

import "gorm.io/gorm"

// PublishSearchSync enqueues a search-index refresh for a user. The actual
// denormalization is owned by the platform-api worker (one implementation); this
// package only needs to fire the event. It's an injected func (wired in main) so
// `database` doesn't have to import service/utils, which would create an import cycle.
var PublishSearchSync func(userID uint64)

// SyncUserWrapper keeps its original signature so existing call sites stay
// untouched; the db handle is no longer used (the worker reads the data itself).
func SyncUserWrapper(_ *gorm.DB, userID uint64, _ string) {
	if PublishSearchSync != nil {
		PublishSearchSync(userID)
	}
}
