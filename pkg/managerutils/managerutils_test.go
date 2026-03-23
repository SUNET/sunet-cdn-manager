package managerutils

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/rs/zerolog"
)

func TestRetryWithBackoff(t *testing.T) {
	errAllFailed := errors.New("all failed")

	logger := zerolog.New(zerolog.NewTestWriter(t)).With().Timestamp().Caller().Logger()

	tests := []struct {
		description string
		sleepBase   time.Duration
		sleepCap    time.Duration
		attempts    int
		operation   func(context.Context) error
		err         error
		cancel      bool
	}{
		{
			description: "successful first attempt",
			sleepBase:   time.Millisecond * 1,
			sleepCap:    time.Millisecond * 10,
			attempts:    3,
			operation: func(context.Context) error {
				return nil
			},
			err:    nil,
			cancel: false,
		},
		{
			description: "failed first attempt with 1ns sleepBase (sleepDuration/2 rounds to 0)",
			sleepBase:   time.Nanosecond * 1,
			sleepCap:    time.Millisecond * 10,
			attempts:    3,
			operation: func() func(context.Context) error {
				attemptCounter := 0
				return func(context.Context) error {
					logger.Info().Int("attempt_counter", attemptCounter).Msg("trying attempt")
					if attemptCounter > 0 {
						return nil
					}
					attemptCounter++
					return errors.New("first attempt")
				}
			}(),
			err:    nil,
			cancel: false,
		},
		{
			description: "all attempts failed",
			sleepBase:   time.Millisecond * 1,
			sleepCap:    time.Millisecond * 10,
			attempts:    3,
			operation: func(context.Context) error {
				return errAllFailed
			},
			err:    errAllFailed,
			cancel: false,
		},
		{
			description: "success after retry",
			sleepBase:   time.Millisecond * 1,
			sleepCap:    time.Millisecond * 10,
			attempts:    3,
			operation: func() func(context.Context) error {
				attemptCounter := 0
				return func(context.Context) error {
					logger.Info().Int("attempt_counter", attemptCounter).Msg("trying attempt")
					if attemptCounter > 0 {
						return nil
					}
					attemptCounter++
					return errors.New("first attempt")
				}
			}(),
			err:    nil,
			cancel: false,
		},
		{
			description: "failed with cancelled context",
			sleepBase:   time.Millisecond * 1,
			sleepCap:    time.Millisecond * 10,
			attempts:    3,
			operation: func(context.Context) error {
				return errors.New("we expect to exit early due to context being cancelled")
			},
			err:    context.Canceled,
			cancel: true,
		},
	}

	for _, test := range tests {
		t.Run(test.description, func(t *testing.T) {
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()

			if test.cancel {
				cancel()
			}
			err := RetryWithBackoff(ctx, logger, test.sleepBase, test.sleepCap, test.attempts, test.description, test.operation)
			if !errors.Is(err, test.err) {
				t.Fatalf("wanted err to be: %#v, got: %#v", test.err, err)
			}
		})
	}
}
