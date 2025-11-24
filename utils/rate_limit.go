package utils

import (
	"context"
	"fmt"
	"time"

	"github.com/ilabs/wacht-fe/database"
)

const (
	MaxAttempts     = 10
	BlockDuration   = 30 * time.Minute
	RateLimitPrefix = "rate_limit:login:"
)

func CheckRateLimit(identifier string) (bool, error) {
	if database.Redis == nil {
		return false, nil
	}

	key := fmt.Sprintf("%s%s", RateLimitPrefix, identifier)
	val, err := database.Redis.Get(context.Background(), key).Int()
	if err != nil {
		// If key doesn't exist, they are not blocked
		return false, nil
	}

	return val >= MaxAttempts, nil
}

func IncrementRateLimit(identifier string) error {
	if database.Redis == nil {
		return nil
	}

	key := fmt.Sprintf("%s%s", RateLimitPrefix, identifier)
	ctx := context.Background()

	val, err := database.Redis.Incr(ctx, key).Result()
	if err != nil {
		return err
	}

	if val == 1 {
		database.Redis.Expire(ctx, key, BlockDuration)
	}

	return nil
}

func ClearRateLimit(identifier string) error {
	if database.Redis == nil {
		return nil
	}

	key := fmt.Sprintf("%s%s", RateLimitPrefix, identifier)
	return database.Redis.Del(context.Background(), key).Err()
}
