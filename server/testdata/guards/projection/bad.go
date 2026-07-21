package projection

import (
	"context"

	"example.com/server/internal/store/generated"
)

func outsideProjector(ctx context.Context, db generated.DBTX) error {
	_, err := generated.New(db).UpsertInventorySnapshot(ctx, generated.UpsertInventorySnapshotParams{})
	return err
}
