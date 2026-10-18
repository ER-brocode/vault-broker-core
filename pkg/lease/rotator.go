package lease

import (
	"context"
	"fmt"
	"sync"
	"time"
)

// AutoRotationDaemon monitors leases approaching expiration and triggers automated rotation callbacks.
type AutoRotationDaemon struct {
	manager         *Manager
	rotationWindow  float64 // Percentage of TTL remaining when rotation should trigger (e.g., 0.20 for 20%)
	checkInterval   time.Duration
	stopCh          chan struct{}
	mu              sync.RWMutex
	inFlightRotate  map[string]bool
	onRotateSuccess func(leaseID string)
}

// NewAutoRotationDaemon initializes the auto-rotation daemon.
func NewAutoRotationDaemon(mgr *Manager, rotationWindowPercent float64, checkInterval time.Duration) *AutoRotationDaemon {
	if rotationWindowPercent <= 0 || rotationWindowPercent >= 1.0 {
		rotationWindowPercent = 0.20 // Default to rotating when 20% TTL remaining
	}
	if checkInterval <= 0 {
		checkInterval = 100 * time.Millisecond
	}

	return &AutoRotationDaemon{
		manager:        mgr,
		rotationWindow: rotationWindowPercent,
		checkInterval:  checkInterval,
		stopCh:         make(chan struct{}),
		inFlightRotate: make(map[string]bool),
	}
}

// SetOnRotateSuccess sets a callback notifying when rotation succeeds.
func (d *AutoRotationDaemon) SetOnRotateSuccess(fn func(leaseID string)) {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.onRotateSuccess = fn
}

// Start begins the auto-rotation background loop.
func (d *AutoRotationDaemon) Start(ctx context.Context) {
	ticker := time.NewTicker(d.checkInterval)
	go func() {
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-d.stopCh:
				return
			case <-ticker.C:
				d.evaluateLeases(ctx)
			}
		}
	}()
}

// Stop terminates the auto-rotation daemon.
func (d *AutoRotationDaemon) Stop() {
	d.mu.Lock()
	defer d.mu.Unlock()
	select {
	case <-d.stopCh:
		// already stopped
	default:
		close(d.stopCh)
	}
}

// evaluateLeases iterates active leases and rotates those in the rotation window.
func (d *AutoRotationDaemon) evaluateLeases(ctx context.Context) {
	d.manager.mu.RLock()
	var candidates []*Lease
	now := time.Now().UTC()

	for _, l := range d.manager.leases {
		if l.State != StateActive && l.State != StateRenewed {
			continue
		}
		if l.rotateFunc == nil {
			continue
		}

		totalDuration := l.ExpiresAt.Sub(l.CreatedAt)
		timeRemaining := l.ExpiresAt.Sub(now)

		// Check if time remaining is within window
		triggerDuration := time.Duration(float64(totalDuration) * d.rotationWindow)
		if timeRemaining <= triggerDuration && timeRemaining > 0 {
			candidates = append(candidates, l)
		}
	}
	d.manager.mu.RUnlock()

	for _, l := range candidates {
		d.mu.Lock()
		if d.inFlightRotate[l.ID] {
			d.mu.Unlock()
			continue
		}
		d.inFlightRotate[l.ID] = true
		d.mu.Unlock()

		go func(target *Lease) {
			defer func() {
				d.mu.Lock()
				delete(d.inFlightRotate, target.ID)
				d.mu.Unlock()
			}()

			rotCtx, cancel := context.WithTimeout(ctx, 15*time.Second)
			defer cancel()

			if err := target.rotateFunc(rotCtx, target); err != nil {
				// Rotation error - log or handle
				fmt.Printf("[AutoRotate Daemon] Warning: rotation failed for lease %s: %v\n", target.ID, err)
				return
			}

			d.mu.RLock()
			hook := d.onRotateSuccess
			d.mu.RUnlock()
			if hook != nil {
				hook(target.ID)
			}
		}(l)
	}
}
