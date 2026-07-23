package projectionsamename

type unrelatedQueries struct{}

func (unrelatedQueries) UpsertInventorySnapshot() {}

func projectInventorySnapshot() {
	var queries unrelatedQueries
	queries.UpsertInventorySnapshot()
}
