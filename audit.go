package main

import (
	"context"
	"log"
)

// audit records an action by the caller in c (user or token). A failed write is logged, never fatal.
func (s *server) audit(ctx context.Context, c *reqCtx, action string, projectID *int64, target string, details map[string]any) {
	var userID, tokenID *int64
	ip := ""
	if c != nil {
		if c.User != nil {
			userID = &c.User.ID
		}
		if c.Token != nil {
			tokenID = &c.Token.ID
		}
		ip = c.IP
	}
	if details == nil {
		details = map[string]any{}
	}
	_, err := s.db.Exec(ctx, `insert into audit_log(actor_user, actor_token, ip, action, project_id, target, details)
		values($1, $2, $3, $4, $5, $6, $7)`, userID, tokenID, ip, action, projectID, target, details)
	if err != nil {
		log.Printf("audit %s: %v", action, err)
	}
}
