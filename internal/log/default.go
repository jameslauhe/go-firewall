package log

import (
	"log/slog"
	"os"

	"github.com/jameslauhe/go-firewall/internal/config"
)

// ConfigureDefault sets the process-wide slog default logger (used for
// startup messages, warnings, and every other non-access-log log line)
// from the top-level log config, so general application logs share the
// same level/JSON-format settings as the access log.
func ConfigureDefault(cfg config.LogConfig) {
	handler := slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: parseLevel(cfg.Level)})
	slog.SetDefault(slog.New(handler))
}
