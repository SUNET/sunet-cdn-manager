package managerutils

import (
	"context"
	"fmt"
	mrand "math/rand/v2"
	"time"

	"github.com/rs/zerolog"
)

func RetryWithBackoff(ctx context.Context, logger zerolog.Logger, sleepBase time.Duration, sleepCap time.Duration, attempts int, description string, operation func(context.Context) error) error {
	var err error

	if sleepBase <= 0 {
		return fmt.Errorf("sleepBase must be larger than 0")
	}

	if sleepCap < sleepBase {
		return fmt.Errorf("sleepCap must be equal to or larger than sleepBase")
	}

	if attempts <= 0 {
		return fmt.Errorf("attempts must be larger than 0")
	}

	for attempt := range attempts {
		err = operation(ctx)
		if err == nil {
			if attempt > 0 {
				logger.Info().Int("attempt", attempt+1).Msgf("retryWithBackoff: operation '%s' succeeded after retries", description)
			}
			break
		}

		if attempt < attempts-1 {
			// Exponential backoff
			sleepDuration := min(sleepCap, sleepBase*(1<<attempt))
			// Add jitter
			sleepDuration = sleepDuration/2 + time.Duration(mrand.Int64N(int64(sleepDuration/2))) // #nosec G404 -- no need for cryptographically secure randomness for backoff timer
			logger.Err(err).Msgf("retryWithBackoff: operation '%s' failed, sleeping for %s", description, sleepDuration)
			select {
			case <-ctx.Done():
				return fmt.Errorf("retryWithBackoff: context cancelled while waiting for '%s': %w", description, ctx.Err())
			case <-time.After(sleepDuration):
			}
		} else {
			logger.Err(err).Msgf("retryWithBackoff: hit retry limit, giving up on '%s'", description)
		}
	}
	if err != nil {
		return fmt.Errorf("retryWithBackoff: '%s' failed after %d attempts: %w", description, attempts, err)
	}

	return nil
}
