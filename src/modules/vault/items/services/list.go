package services

import (
	"context"
	"slices"
	"strings"

	"github.com/guialves50/password-manager/src/cli"
)

type ListService struct {
	Repo lister
}

func (l *ListService) List(ctx context.Context, s *cli.Session) ([]string, int, error) {
	items, skipped, err := decryptAll(ctx, l.Repo, s)
	if err != nil {
		return nil, 0, err
	}
	names := make([]string, len(items))
	for i, it := range items {
		names[i] = it.Name
	}
	slices.SortStableFunc(names, func(a, b string) int {
		return strings.Compare(strings.ToLower(a), strings.ToLower(b))
	})
	return names, skipped, nil
}
