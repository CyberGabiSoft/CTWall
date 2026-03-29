package componentanalysis

import (
	"testing"
	"time"
)

func TestSchedulerTimeUntilNextRunReturnsRemainingWhenNotDue(t *testing.T) {
	svc := NewService(nil, nil)
	svc.SetScheduleAnchor(time.Now().UTC().Add(-2 * time.Hour))
	s := NewScheduler(svc, nil)

	got := s.timeUntilNextRun(6 * time.Hour)
	if got < (4*time.Hour-time.Second) || got > (4*time.Hour+time.Second) {
		t.Fatalf("expected wait close to 4h, got %s", got)
	}
}

func TestSchedulerTimeUntilNextRunReturnsZeroWhenOverdue(t *testing.T) {
	svc := NewService(nil, nil)
	svc.SetScheduleAnchor(time.Now().UTC().Add(-7 * time.Hour))
	s := NewScheduler(svc, nil)

	got := s.timeUntilNextRun(6 * time.Hour)
	if got != 0 {
		t.Fatalf("expected overdue wait to be 0, got %s", got)
	}
}
