package server

import "github.com/rs/zerolog"

func Run(logger zerolog.Logger) {
	logger.Info().Msg("Run() called")
}
