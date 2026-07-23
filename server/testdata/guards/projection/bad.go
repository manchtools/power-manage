package projection

import (
	"context"

	"github.com/manchtools/power-manage/server/internal/store/generated"
)

func outsideProjector(ctx context.Context, db generated.DBTX) error {
	_, err := generated.New(db).UpsertInventorySnapshot(ctx, generated.UpsertInventorySnapshotParams{})
	return err
}
