package service

import (
	"context"
	"crypto/md5"
	"fmt"
	"os"
	"time"
)

type SnapshotInput struct {
	GitTarget
}

type SnapshotOutput struct {
	Data      []byte
	Ref       string
	SHA       string
	MD5       string
	Size      int64
	FromCache bool
	Timestamp time.Time
}

// ReadRepoSnapshot returns a repo snapshot zip as bytes, using stored or prompted credentials.
func (s *Service) ReadRepoSnapshot(ctx context.Context, in *SnapshotInput, prompt func(string)) (*SnapshotOutput, error) {
	if in == nil {
		return nil, fmt.Errorf("snapshot input is nil")
	}
	domain, owner, name, ref, alias, err := in.GitTarget.Init(s)
	if err != nil {
		return nil, err
	}
	if alias == "" {
		if a, aerr := in.GitTarget.GetAlias(ctx, s); aerr == nil {
			alias = a
		}
	}
	return withRepoCredentialRetry(ctx, s, alias, domain, owner, name, prompt, func(token string) (*SnapshotOutput, error) {
		path, size, fromCache, sha, err := s.GetOrFetchSnapshotZip(ctx, s.Namespace(ctx), alias, domain, owner, name, ref, token)
		if err != nil {
			return nil, err
		}
		data, err := os.ReadFile(path)
		if err != nil {
			return nil, err
		}
		sum := md5.Sum(data)
		return &SnapshotOutput{
			Data:      data,
			Ref:       ref,
			SHA:       sha,
			MD5:       fmt.Sprintf("%x", sum),
			Size:      size,
			FromCache: fromCache,
			Timestamp: time.Now(),
		}, nil
	})
}
