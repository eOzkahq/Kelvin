package main

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"log"
	"time"

	"github.com/google/uuid"
	commonqueue "github.com/kelvin/kelvin/packages/common/queue"
	"github.com/redis/go-redis/v9"
)

func main() {
	redisURL := "rediss://default:gQAAAAAAAv3kAAIgcDI1NTg4ODZiNTBlYmM0YWVlOGVmYjA2YTJlYzY4Y2FjNA@learning-viper-196068.upstash.io:6379"

	opt, err := redis.ParseURL(redisURL)
	if err != nil {
		log.Fatalf("Parse Redis URL failed: %v", err)
	}
	opt.TLSConfig = &tls.Config{MinVersion: tls.VersionTLS12}

	rdb := redis.NewClient(opt)
	ctx := context.Background()

	if err := rdb.Ping(ctx).Err(); err != nil {
		log.Fatalf("Redis Ping failed: %v", err)
	}
	log.Println("Connected to Redis successfully!")

	asmtID := "9dacd8a0-a6b1-4fd0-8fe7-34666bca2978"
	tenantID := "344480a7-7d57-4db9-a269-0b36e542643a"
	targetAddress := "https://kush05bhardwaj.vercel.app"
	profileID := "kelvin.profile.standard.v1"
	jobID := uuid.New().String()
	correlationID := uuid.New().String()

	now := time.Now().UTC()
	deadlineSeconds := int64(1800)
	expiresAt := now.Add(24 * time.Hour)

	envelope := commonqueue.JobEnvelope{
		SchemaVersion:       2,
		JobID:               jobID,
		AssessmentID:        asmtID,
		TenantID:            tenantID,
		TargetID:            uuid.New().String(),
		TargetAddress:       targetAddress,
		ScanProfile:         profileID,
		RequestedScanners:   []string{"http_preflight", "nmap", "tls_assessor", "http_security_headers", "zap", "nuclei"},
		RateLimit:           "10",
		HardDeadlineSeconds: deadlineSeconds,
		CreatedAt:           now,
		ExpiresAt:           expiresAt,
		CorrelationID:       correlationID,
	}

	payloadBytes, err := json.Marshal(envelope)
	if err != nil {
		log.Fatalf("Marshal envelope failed: %v", err)
	}

	queueMsg := commonqueue.Message{
		Version:       2,
		ID:            jobID,
		AssessmentID:  asmtID,
		TenantID:      tenantID,
		CorrelationID: correlationID,
		Type:          "ASSESSMENT",
		Payload:       payloadBytes,
		MaxAttempts:   3,
	}

	if err := queueMsg.Validate(); err != nil {
		log.Fatalf("Queue message validation failed: %v", err)
	}

	log.Printf("Enqueueing Job ID: %s for Assessment ID: %s (Target: %s)...", jobID, asmtID, targetAddress)

	q, err := commonqueue.NewRedis(rdb, commonqueue.RedisConfig{
		Prefix:      "kelvin:jobs",
		Group:       "workers",
		Consumer:    "oracle-arm64-worker-01",
		WorkerID:    "oracle-arm64-worker-01",
		TokenSecret: []byte("a7f3c91e5b2d8046f1a9c7e3d8b6052f9c4e1a7b3d6f8025e9b1c4a7d3f6082e"),
	})
	if err != nil {
		log.Fatalf("NewRedis failed: %v", err)
	}

	if err := q.Enqueue(ctx, queueMsg); err != nil {
		log.Fatalf("Enqueue failed: %v", err)
	}

	fmt.Println("Job enqueued successfully via commonqueue.NewRedis.Enqueue!")
}
