package database

import (
	"context"
	"crypto/tls"
	"fmt"
	"os"
	"strconv"
	"time"

	"github.com/redis/go-redis/v9"
)

var Redis *redis.Client

func InitRedisConnection() error {
	tlsEnabled := true
	if value := os.Getenv("REDIS_TLS"); value != "" {
		parsed, err := strconv.ParseBool(value)
		if err != nil {
			return fmt.Errorf("invalid REDIS_TLS value %q: %w", value, err)
		}
		tlsEnabled = parsed
	}

	options := &redis.Options{
		Addr: fmt.Sprintf(
			"%s:%s",
			os.Getenv("REDIS_HOST"),
			os.Getenv("REDIS_PORT"),
		),
		Username: os.Getenv("REDIS_USERNAME"),
		Password: os.Getenv("REDIS_PASSWORD"),
	}
	if tlsEnabled {
		options.TLSConfig = &tls.Config{}
	}

	rdb := redis.NewClient(options)

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
