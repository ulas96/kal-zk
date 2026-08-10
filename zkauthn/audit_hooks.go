//go:build zkaudit

package zkauthn

import (
	"context"
	"io"
	"time"
)

// AuditSetRandomSource replaces this service's entropy source and returns a restore function.
// It exists only in zkaudit builds and must be installed before concurrent use of the service.
func (z *ZK) AuditSetRandomSource(random io.Reader) func() {
	previous := z.random
	z.random = random
	return func() { z.random = previous }
}

// AuditHoldVerificationSlots acquires n slots through the production admission semaphore and
// returns a release function. It lets the audit suite prove the exact concurrency boundary.
func (z *ZK) AuditHoldVerificationSlots(ctx context.Context, n int64) (func(), error) {
	if err := z.sem.Acquire(ctx, n); err != nil {
		return nil, err
	}
	return func() { z.sem.Release(n) }, nil
}

// AuditSetVerifyWait replaces the per-service admission timeout and returns a restore function.
func (z *ZK) AuditSetVerifyWait(wait time.Duration) func() {
	previous := z.verifyWait
	z.verifyWait = wait
	return func() { z.verifyWait = previous }
}

// AuditSetChallengeTTL replaces the per-service challenge lifetime and returns a restore function.
func (z *ZK) AuditSetChallengeTTL(ttl time.Duration) func() {
	previous := z.challengeTTL
	z.challengeTTL = ttl
	return func() { z.challengeTTL = previous }
}
