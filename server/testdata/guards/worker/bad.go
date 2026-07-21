package worker

import "context"

type Queue struct{}

func (Queue) RunOnce(context.Context) error {
	return nil
}
