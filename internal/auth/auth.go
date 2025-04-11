package auth

import (
	"go.uber.org/zap"
)

var logger *zap.Logger

func init() {
	logger = zap.L().With(zap.String("package", "auth"))
}
