package acme

import (
	"sync"

	"go.uber.org/zap"
)

var logger *zap.Logger

// acmeChallengeResponses stores the HTTP-01 challenge responses.
var acmeChallengeResponses sync.Map

func init() {
	logger = zap.L().With(zap.String("package", "acme"))
}
