package middleware

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"strconv"
	"time"

	"github.com/google/uuid"
	"github.com/ilabs/wacht-fe/service"
	"github.com/jellydator/ttlcache/v3"
	"github.com/nats-io/nats.go/jetstream"
)

type RateLimitMessage struct {
	Key       string `json:"key"`
	Increment int    `json:"increment"`
	NodeID    string `json:"node_id"`
}

type NatsStorage struct {
	data        *ttlcache.Cache[string, int]
	natsService *service.NatsService
	kv          jetstream.KeyValue
	nodeID      string
}

func NewNatsStorage(natsService *service.NatsService) *NatsStorage {
	storage := &NatsStorage{
		natsService: natsService,
		nodeID:      uuid.New().String(),
		data: ttlcache.New(
			ttlcache.WithTTL[string, int](1 * time.Minute),
		),
	}

	// Initialize KV
	ctx := context.Background()
	kv, err := natsService.GetRateLimitKV(ctx)
	if err != nil {
		log.Printf("Failed to initialize NATS KV for rate limiting: %v", err)
	} else {
		storage.kv = kv
	}

	go storage.data.Start()

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

		if item := s.data.Get(update.Key); item != nil {
			newValue := item.Value() + update.Increment
			s.data.Set(update.Key, newValue, ttlcache.DefaultTTL)
		}
	}
}

func (s *NatsStorage) Get(key string) ([]byte, error) {
	if item := s.data.Get(key); item != nil {
		return fmt.Appendf(nil, "%d", item.Value()), nil
	}

	if s.kv != nil {
		kvEntry, err := s.kv.Get(context.Background(), key)
		if err == nil {
			val := kvEntry.Value()
			intVal, _ := strconv.Atoi(string(val))

			s.data.Set(key, intVal, ttlcache.DefaultTTL)

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
	if item := s.data.Get(key); item != nil {
		oldVal = item.Value()
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

	s.data.Set(key, newVal, exp)

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
	s.data.Delete(key)
	if s.kv != nil {
		go s.kv.Delete(context.Background(), key)
	}
	return nil
}

func (s *NatsStorage) Reset() error {
	s.data.DeleteAll()
	return nil
}

func (s *NatsStorage) Close() error {
	s.data.Stop()
	return nil
}
