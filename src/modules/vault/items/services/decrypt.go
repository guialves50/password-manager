package services

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/guialves50/password-manager/src/cli"
	"github.com/guialves50/password-manager/src/modules/auth/keys"
	"github.com/guialves50/password-manager/src/modules/vault/items/dto"
)

type lister interface {
	ListItems(ctx context.Context, s *cli.Session) ([]dto.StoredItem, error)
}

func aad(userID uint64, id string) []byte {
	return []byte(fmt.Sprintf("pm/item/v1|%d|%s", userID, id))
}

// ponytail: one Open per item on every command; add an HMAC blind index on the name if vaults grow large
func decryptAll(ctx context.Context, r lister, s *cli.Session) ([]dto.Item, int, error) {
	rows, err := r.ListItems(ctx, s)
	if err != nil {
		return nil, 0, err
	}
	items := make([]dto.Item, 0, len(rows))
	skipped := 0
	for _, row := range rows {
		plain, err := keys.Open(s.VaultKey, row.Blob, aad(s.UserID, row.ID))
		if err != nil {
			skipped++
			continue
		}
		var it dto.Item
		err = json.Unmarshal(plain, &it)
		keys.Zero(plain)
		if err != nil {
			skipped++
			continue
		}
		it.ID = row.ID
		items = append(items, it)
	}
	return items, skipped, nil
}
