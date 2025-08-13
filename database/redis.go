package database

import (
	"context"
	"crypto/tls"
	"fmt"
	"os"
	"time"

	"github.com/redis/go-redis/v9"
)

var Redis *redis.Client

func InitRedisConnection() error {
	rdb := redis.NewClient(&redis.Options{
		Addr: fmt.Sprintf(
			"%s:%s",
			os.Getenv("REDIS_HOST"),
			os.Getenv("REDIS_PORT"),
		),
		Username:  os.Getenv("REDIS_USERNAME"),
		Password:  os.Getenv("REDIS_PASSWORD"),
		TLSConfig: &tls.Config{},
	})

	ctx, cancel := context.WithTimeout(
		context.Background(),
		5*time.Second,
	)
	defer cancel()

	_, err := rdb.Ping(ctx).Result()
	if err != nil {
		return err
	}

	Redis = rdb

	return nil
}

