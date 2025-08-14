package cache

import (
	"context"
	"encoding/json"
	"log"
	"time"

	"github.com/go-redis/redis/v8"
)

type RedisCache struct {
	client *redis.Client
	ctx    context.Context
}

func NewRedisCache(redisURL, password string, db int) *RedisCache {
	// Parse URL or use direct connection
	var rdb *redis.Client

	if redisURL != "" && redisURL != "redis://redis:6379/0" {
		// Use URL-based connection
		opt, err := redis.ParseURL(redisURL)
		if err != nil {
			log.Printf("Failed to parse Redis URL, using default connection: %v", err)
			rdb = redis.NewClient(&redis.Options{
				Addr:     "redis:6379",
				Password: password,
				DB:       db,
			})
		} else {
			rdb = redis.NewClient(opt)
		}
	} else {
		// Use direct connection
		rdb = redis.NewClient(&redis.Options{
			Addr:     "redis:6379",
			Password: password,
			DB:       db,
		})
	}

	cache := &RedisCache{
		client: rdb,
		ctx:    context.Background(),
	}

	// Test connection
	if err := cache.client.Ping(cache.ctx).Err(); err != nil {
		log.Printf("WARNING: Redis connection failed: %v. Cache features may not work properly.", err)
	} else {
		log.Println("Redis connected successfully")
	}

	return cache
}

func (r *RedisCache) Set(key string, value interface{}, expiration time.Duration) error {
	json, err := json.Marshal(value)
	if err != nil {
		return err
	}
	return r.client.Set(r.ctx, key, json, expiration).Err()
}

func (r *RedisCache) Get(key string, dest interface{}) error {
	val, err := r.client.Get(r.ctx, key).Result()
	if err != nil {
		return err
	}
	return json.Unmarshal([]byte(val), dest)
}

func (r *RedisCache) Delete(key string) error {
	return r.client.Del(r.ctx, key).Err()
}

func (r *RedisCache) Exists(key string) bool {
	result, err := r.client.Exists(r.ctx, key).Result()
	return err == nil && result > 0
}

func (r *RedisCache) Increment(key string, expiration time.Duration) (int64, error) {
	pipe := r.client.TxPipeline()
	incr := pipe.Incr(r.ctx, key)
	pipe.Expire(r.ctx, key, expiration)
	_, err := pipe.Exec(r.ctx)
	if err != nil {
		return 0, err
	}
	return incr.Val(), nil
}
