package middleware

import (
	"bytes"
	"context"
	"encoding/json"
	"log"
	"time"

	"github.com/google/uuid"
	"github.com/jellydator/ttlcache/v3"
	"github.com/nats-io/nats.go/jetstream"
	"github.com/wacht-platform/frontend-api/service"
	"github.com/wacht-platform/frontend-api/utils"
)

type RateLimitMessage struct {
	Key    string `json:"key"`
	Value  []byte `json:"value"`
	NodeID string `json:"node_id"`
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

		utils.Cache.Set(update.Key, append([]byte(nil), update.Value...), ttlcache.DefaultTTL)
	}
}

func (s *NatsStorage) Get(key string) ([]byte, error) {
	if item := utils.Cache.Get(key); item != nil {
		if raw, ok := item.Value().([]byte); ok {
			return append([]byte(nil), raw...), nil
		}
		utils.Cache.Delete(key)
	}

	if s.kv != nil {
		kvEntry, err := s.kv.Get(context.Background(), key)
		if err == nil {
			val := kvEntry.Value()
			if !isLimiterPayload(val) {
				_ = s.kv.Delete(context.Background(), key)
				return nil, nil
			}

			utils.Cache.Set(key, append([]byte(nil), val...), time.Minute)
			return append([]byte(nil), val...), nil
		}
	}

	return nil, nil
}

func (s *NatsStorage) GetWithContext(_ context.Context, key string) ([]byte, error) {
	return s.Get(key)
}

func (s *NatsStorage) Set(key string, val []byte, exp time.Duration) error {
	return s.SetWithExp(key, val, exp)
}

func (s *NatsStorage) SetWithContext(_ context.Context, key string, val []byte, exp time.Duration) error {
	return s.Set(key, val, exp)
}

func (s *NatsStorage) SetWithExp(key string, val []byte, exp time.Duration) error {
	raw := append([]byte(nil), val...)
	utils.Cache.Set(key, raw, exp)

	msg := RateLimitMessage{
		Key:    key,
		Value:  raw,
		NodeID: s.nodeID,
	}
	if payload, err := json.Marshal(msg); err == nil {
		s.natsService.PublishRateLimit(payload)
	}

	if s.kv != nil {
		go s.persistAsync(key, raw)
	}

	return nil
}

func (s *NatsStorage) persistAsync(key string, raw []byte) {
	ctx := context.Background()
	for range 5 {
		entry, err := s.kv.Get(ctx, key)
		if err == jetstream.ErrKeyNotFound {
			_, err = s.kv.Create(ctx, key, raw)
			if err == nil {
				return
			}
			continue
		} else if err != nil {
			return
		}

		if bytes.Equal(entry.Value(), raw) {
			return
		}

		_, err = s.kv.Update(ctx, key, raw, entry.Revision())
		if err == nil {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
}

func (s *NatsStorage) Delete(key string) error {
	utils.Cache.Delete(key)
	if s.kv != nil {
		go func() {
			_ = s.kv.Delete(context.Background(), key)
		}()
	}
	return nil
}

func (s *NatsStorage) DeleteWithContext(_ context.Context, key string) error {
	return s.Delete(key)
}

func (s *NatsStorage) Reset() error {
	return nil
}

func (s *NatsStorage) ResetWithContext(_ context.Context) error {
	return s.Reset()
}

func (s *NatsStorage) Close() error {
	return nil
}

func isLimiterPayload(raw []byte) bool {
	if len(raw) == 0 {
		return false
	}

	// Fiber v3 limiter stores a msgpack map with currHits/prevHits/exp.
	// Legacy v2 cache entries were plain ASCII integers; treat those as stale.
	if raw[0] >= '0' && raw[0] <= '9' {
		return false
	}

	return raw[0]&0xf0 == 0x80 || bytes.HasPrefix(raw, []byte{0xde}) || bytes.HasPrefix(raw, []byte{0xdf})
}
