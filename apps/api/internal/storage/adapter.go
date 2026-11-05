package storage

import (
	"context"
	"fmt"
	"path"
	"time"

	"github.com/kelvin/kelvin/apps/api/internal/evidence"
)

// EvidenceStorageAdapter wraps StorageService to satisfy evidence.StorageService.
type EvidenceStorageAdapter struct {
	storage StorageService
	bucket  string
}

// NewEvidenceStorageAdapter returns an adapter implementing evidence.StorageService.
func NewEvidenceStorageAdapter(storage StorageService, bucket string) *EvidenceStorageAdapter {
	if bucket == "" {
		bucket = "kelvin-evidence-private"
	}
	return &EvidenceStorageAdapter{
		storage: storage,
		bucket:  bucket,
	}
}

func (a *EvidenceStorageAdapter) PutObject(ctx context.Context, tenantID, objectID, contentType string, data []byte) (*evidence.ObjectMetadata, error) {
	objectPath := fmt.Sprintf("%s/evidence/%s", tenantID, objectID)
	err := a.storage.Upload(ctx, a.bucket, objectPath, contentType, data)
	if err != nil {
		return nil, err
	}

	meta := &evidence.ObjectMetadata{
		TenantID:    tenantID,
		ObjectID:    objectID,
		StorageKey:  objectPath,
		ContentType: contentType,
		SizeBytes:   int64(len(data)),
		CreatedAt:   time.Now().UTC(),
	}
	return meta, nil
}

func (a *EvidenceStorageAdapter) GetObject(ctx context.Context, tenantID, objectID string) ([]byte, *evidence.ObjectMetadata, error) {
	objectPath := fmt.Sprintf("%s/evidence/%s", tenantID, objectID)
	data, err := a.storage.Download(ctx, a.bucket, objectPath)
	if err != nil {
		return nil, nil, err
	}

	meta := &evidence.ObjectMetadata{
		TenantID:   tenantID,
		ObjectID:   objectID,
		StorageKey: objectPath,
		SizeBytes:  int64(len(data)),
		CreatedAt:  time.Now().UTC(),
	}
	return data, meta, nil
}

func (a *EvidenceStorageAdapter) GetMetadata(ctx context.Context, tenantID, objectID string) (*evidence.ObjectMetadata, error) {
	data, meta, err := a.GetObject(ctx, tenantID, objectID)
	if err != nil {
		return nil, err
	}
	meta.SizeBytes = int64(len(data))
	return meta, nil
}

func (a *EvidenceStorageAdapter) DeleteObject(ctx context.Context, tenantID, objectID string) error {
	objectPath := fmt.Sprintf("%s/evidence/%s", tenantID, objectID)
	return a.storage.Delete(ctx, a.bucket, objectPath)
}

func (a *EvidenceStorageAdapter) SecurePurge(ctx context.Context, tenantID, objectID string) error {
	return a.DeleteObject(ctx, tenantID, objectID)
}

// ReportingObjectStoreAdapter wraps StorageService to satisfy reporting.ObjectStore.
type ReportingObjectStoreAdapter struct {
	storage StorageService
	bucket  string
}

// NewReportingObjectStoreAdapter returns an adapter implementing reporting.ObjectStore.
func NewReportingObjectStoreAdapter(storage StorageService, bucket string) *ReportingObjectStoreAdapter {
	if bucket == "" {
		bucket = "kelvin-reports-private"
	}
	return &ReportingObjectStoreAdapter{
		storage: storage,
		bucket:  bucket,
	}
}

func (r *ReportingObjectStoreAdapter) Put(ctx context.Context, storagePath string, data []byte) error {
	contentType := "application/octet-stream"
	ext := path.Ext(storagePath)
	switch ext {
	case ".pdf":
		contentType = "application/pdf"
	case ".html", ".htm":
		contentType = "text/html; charset=utf-8"
	case ".json":
		contentType = "application/json"
	}

	return r.storage.Upload(ctx, r.bucket, storagePath, contentType, data)
}

func (r *ReportingObjectStoreAdapter) Get(ctx context.Context, storagePath string) ([]byte, error) {
	return r.storage.Download(ctx, r.bucket, storagePath)
}

func (r *ReportingObjectStoreAdapter) Delete(ctx context.Context, storagePath string) error {
	return r.storage.Delete(ctx, r.bucket, storagePath)
}
