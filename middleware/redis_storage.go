package middleware

import (
	"context"
	"time"

	"github.com/ilabs/wacht-fe/database"
	"github.com/redis/go-redis/v9"
)

type RedisStorage struct {
	client *redis.Client
}

func NewRedisStorage() *RedisStorage {
	return &RedisStorage{
		client: database.Redis,
	}
}

func (s *RedisStorage) Get(key string) ([]byte, error) {
	val, err := s.client.Get(context.Background(), key).Bytes()
	if err == redis.Nil {
		return nil, nil
	}
	return val, err
}

func (s *RedisStorage) Set(key string, val []byte, exp time.Duration) error {
	return s.client.Set(context.Background(), key, val, exp).Err()
}

func (s *RedisStorage) Delete(key string) error {
	return s.client.Del(context.Background(), key).Err()
}

func (s *RedisStorage) Reset() error {
	return s.client.FlushDB(context.Background()).Err()
}

func (s *RedisStorage) Close() error {
	return s.client.Close()
}
