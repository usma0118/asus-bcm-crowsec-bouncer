package syncer

import (
	"context"
	"time"

	"github.com/usma0118/asus-bcm-crowsec-bouncer/pkg/crowdsec"
	"github.com/usma0118/asus-bcm-crowsec-bouncer/pkg/health"
	"github.com/usma0118/asus-bcm-crowsec-bouncer/pkg/router"

	"go.uber.org/zap"
)

type Syncer struct {
	cs       *crowdsec.Client
	router   *router.SSHRouter
	interval time.Duration
	state    *health.State
	log      *zap.Logger
}

func New(
	cs *crowdsec.Client,
	r *router.SSHRouter,
	interval time.Duration,
	state *health.State,
	log *zap.Logger,
) *Syncer {
	return &Syncer{
		cs:       cs,
		router:   r,
		interval: interval,
		state:    state,
		log:      log,
	}
}

func (s *Syncer) Run(ctx context.Context) error {
	ticker := time.NewTicker(s.interval)
	defer ticker.Stop()

	// Run immediately on startup
	if err := s.syncOnce(ctx); err != nil {
		s.log.Error("initial sync failed", zap.Error(err))
		s.state.RecordError(err)
	} else {
		s.state.RecordSuccess()
	}

	for {
		select {
		case <-ctx.Done():
			s.log.Info("syncer stopping")
			return nil
		case <-ticker.C:
			if err := s.syncOnce(ctx); err != nil {
				s.log.Error("periodic sync failed", zap.Error(err))
				s.state.RecordError(err)
			} else {
				s.state.RecordSuccess()
			}
		}
	}
}

func (s *Syncer) syncOnce(ctx context.Context) error {
	decisions, err := s.cs.ListIPv4Bans(ctx)
	if err != nil {
		return err
	}
	s.log.Info("fetched decisions", zap.Int("count", len(decisions)))
	if err := s.router.Sync(ctx, decisions); err != nil {
		return err
	}
	return nil
}
