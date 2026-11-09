package main

import (
	"cmp"
	"context"
	"fmt"
	"log"
	"slices"
	"strings"
)

type policyResult struct {
	Passed  bool     `json:"passed"`
	Reasons []string `json:"reasons"`
	Error   string   `json:"error,omitempty"`
}

// severityLabel is the web's SEVERITY_LABEL, for Korean sentences that CI logs and the UI show as they are.
var severityLabel = map[string]string{"CRITICAL": "치명", "HIGH": "높음", "MEDIUM": "중간", "LOW": "낮음", "UNKNOWN": "알 수 없음"}

// evaluatePolicy applies the project's policy (spec 3.10) to the scan's target. Any error fails the gate.
func (s *server) evaluatePolicy(ctx context.Context, projectID, scanID int64) policyResult {
	p, n, err := s.policyCount(ctx, projectID, scanID)
	if err != nil {
		log.Printf("policy of scan %d: %v", scanID, err)
		msg := "정책을 판정하지 못해 실패로 처리했습니다."
		return policyResult{Reasons: []string{msg}, Error: msg}
	}
	if !p.Enabled || n <= p.MaxCount {
		return policyResult{Passed: true, Reasons: []string{}}
	}
	var only []string
	if p.NewOnly {
		only = append(only, "새 결과")
	}
	if p.FixableOnly {
		only = append(only, "조치 가능한 결과")
	}
	scope := "열린 결과"
	if only != nil {
		scope = "열린 결과(" + strings.Join(only, ", ") + "만)"
	}
	return policyResult{Reasons: []string{fmt.Sprintf("심각도 %s 이상 %s가 %d건으로 허용 %d건을 넘었습니다.",
		cmp.Or(severityLabel[p.MinSeverity], p.MinSeverity), scope, n, p.MaxCount)}}
}

// policyCount counts the findings the policy counts: open, in the scan's target, at or above min_severity, under
// no approved unexpired exception, and optionally only new or only fixable ones.
func (s *server) policyCount(ctx context.Context, projectID, scanID int64) (policy, int, error) {
	p, err := s.projectPolicy(ctx, projectID)
	if err != nil {
		return p, 0, err
	}
	i := slices.Index(policySeverities, p.MinSeverity)
	if i < 0 {
		return p, 0, fmt.Errorf("unknown min_severity %q", p.MinSeverity)
	}
	if p.MaxCount < 0 {
		return p, 0, fmt.Errorf("negative max_count %d", p.MaxCount)
	}
	// new_only: now() is the transaction start, so the findings the scan's ingest created have first_seen_at =
	// finished_at. Group by makes an unknown scan (or another project's) no row, so it fails closed.
	var n int
	err = s.db.QueryRow(ctx, `select count(f.id) from scans s left join findings f on f.target_id = s.target_id
			and f.status = 'open' and f.severity = any($3)
			and (not $4 or f.first_seen_at = s.finished_at)
			and (not $5 or f.fixed_version <> '')
			and not exists (select 1 from exceptions e where e.status = 'approved' and e.expires_at > now() and `+exceptionMatchSQL+`)
		where s.id = $1 and s.project_id = $2 group by s.id`,
		scanID, projectID, policySeverities[:i+1], p.NewOnly, p.FixableOnly).Scan(&n)
	return p, n, err
}
