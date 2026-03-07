package middleware

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"strconv"
	"time"

	"github.com/google/uuid"
	"github.com/jellydator/ttlcache/v3"
	"github.com/nats-io/nats.go/jetstream"
	"github.com/wacht-platform/frontend-api/service"
	"github.com/wacht-platform/frontend-api/utils"
)

type RateLimitMessage struct {
	Key       string `json:"key"`
	Increment int    `json:"increment"`
	NodeID    string `json:"node_id"`
}

type NatsStorage struct {
	natsService *service.NatsService
	kv          jetstream.KeyValue
	nodeID      string
}

func NewNatsStorage(natsService *service.NatsService) *NatsStorage {
	storage := &NatsStorage{
		natsService: natsService,
		nodeID:      uuid.New().String(),
	}

	// Initialize KV
	ctx := context.Background()
	kv, err := natsService.GetRateLimitKV(ctx)
	if err != nil {
		log.Printf("Failed to initialize NATS KV for rate limiting: %v", err)
	} else {
		storage.kv = kv
	}

	go storage.subscribe()

	return storage
}

func (s *NatsStorage) subscribe() {
	ch := make(chan []byte)
	s.natsService.SubscribeToRateLimits(ch)

	for msg := range ch {
		var update RateLimitMessage
		if err := json.Unmarshal(msg, &update); err != nil {
			continue
		}

		if update.NodeID == s.nodeID {
			continue
		}

		if item := utils.Cache.Get(update.Key); item != nil {
			newValue := item.Value().(int) + update.Increment
			utils.Cache.Set(update.Key, newValue, ttlcache.DefaultTTL)
		}
	}
}

func (s *NatsStorage) Get(key string) ([]byte, error) {
	if item := utils.Cache.Get(key); item != nil {
		return fmt.Appendf(nil, "%d", item.Value()), nil
	}

	if s.kv != nil {
		kvEntry, err := s.kv.Get(context.Background(), key)
		if err == nil {
			val := kvEntry.Value()
			intVal, _ := strconv.Atoi(string(val))

			utils.Cache.Set(key, intVal, time.Minute)

			return val, nil
		}
	}

	return nil, nil
}

func (s *NatsStorage) Set(key string, val []byte, exp time.Duration) error {
	return s.SetWithExp(key, val, exp)
}

func (s *NatsStorage) SetWithExp(key string, val []byte, exp time.Duration) error {
	var newVal int
	fmt.Sscanf(string(val), "%d", &newVal)

	var oldVal int
	if item := utils.Cache.Get(key); item != nil {
		oldVal = item.Value().(int)
	}

	delta := newVal - oldVal

	if delta > 0 {
		msg := RateLimitMessage{
			Key:       key,
			Increment: delta,
			NodeID:    s.nodeID,
		}
		if bytes, err := json.Marshal(msg); err == nil {
			s.natsService.PublishRateLimit(bytes)
		}

		if s.kv != nil {
			go s.persistAsync(key, delta)
		}
	}

	utils.Cache.Set(key, newVal, exp)

	return nil
}

func (s *NatsStorage) persistAsync(key string, delta int) {
	ctx := context.Background()
	for range 5 {
		entry, err := s.kv.Get(ctx, key)
		if err == jetstream.ErrKeyNotFound {
			_, err = s.kv.Create(ctx, key, []byte(strconv.Itoa(delta)))
			if err == nil {
				return
			}
			continue
		} else if err != nil {
			return
		}

		currentVal, _ := strconv.Atoi(string(entry.Value()))
		newVal := currentVal + delta

		_, err = s.kv.Update(ctx, key, []byte(strconv.Itoa(newVal)), entry.Revision())
		if err == nil {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
}

func (s *NatsStorage) Delete(key string) error {
	utils.Cache.Delete(key)
	if s.kv != nil {
		go s.kv.Delete(context.Background(), key)
	}
	return nil
}

func (s *NatsStorage) Reset() error {
	return nil
}

func (s *NatsStorage) Close() error {
	return nil
}
