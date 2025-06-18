package database

import (
	"context"
	"crypto/tls"
	"fmt"
	"os"
	"time"

	celery "github.com/marselester/gopher-celery"
	celeryredis "github.com/marselester/gopher-celery/goredis"
	"github.com/redis/go-redis/v9"
)

var Redis *redis.Client
var CeleryApp *celery.App

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

func InitCeleryApp() error {
	if Redis == nil {
		return fmt.Errorf("redis not initialized")
	}

	broker := celeryredis.NewBroker(
		celeryredis.WithClient(Redis),
	)

	app := celery.NewApp(
		celery.WithBroker(broker),
	)

	CeleryApp = app

	return nil
}
