package services

import (
	"context"
	"slices"
	"strings"

	"github.com/guialves50/password-manager/src/cli"
	"github.com/guialves50/password-manager/src/modules/vault/items/dto"
)

type ListService struct {
	Repo lister
}

func (l *ListService) List(ctx context.Context, s *cli.Session) ([]string, int, error) {
	items, skipped, err := l.Items(ctx, s)
	names := make([]string, len(items))
	for i, it := range items {
		names[i] = it.Name
	}
	return names, skipped, err
}

// Items returns the decrypted items sorted by name, ignoring case.
func (l *ListService) Items(ctx context.Context, s *cli.Session) ([]dto.Item, int, error) {
	items, skipped, err := decryptAll(ctx, l.Repo, s)
	if err != nil {
		return nil, 0, err
	}
	slices.SortStableFunc(items, func(a, b dto.Item) int {
		return strings.Compare(strings.ToLower(a.Name), strings.ToLower(b.Name))
	})
	return items, skipped, nil
}
