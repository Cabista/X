package zerologx

import (
	"os"

	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
)

func DefaultLoggerContext() zerolog.Context {
	return zerolog.New(os.Stderr).With().Timestamp()
}

func PrettyLogger() {
	log.Logger = DefaultLoggerContext().Logger().Output(zerolog.ConsoleWriter{Out: os.Stderr})
}

func ProductionLogger() {
	log.Logger = DefaultLoggerContext().Logger()
}
