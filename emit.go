package main

import "context"

// notifyEmit is set by the notification feature (notify.go) from init(); until then events are dropped.
var notifyEmit func(s *server, ctx context.Context, projectID int64, event string, payload map[string]any)

// emit queues a notification event for a project's subscribed channels.
func (s *server) emit(ctx context.Context, projectID int64, event string, payload map[string]any) {
	if notifyEmit != nil {
		notifyEmit(s, ctx, projectID, event, payload)
	}
}
