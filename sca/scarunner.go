package sca

import (
	"github.com/jfrog/jfrog-cli-security/utils"
	"github.com/jfrog/jfrog-cli-security/utils/results"
)

type ScaStrategy interface {
}

func RunScaScans(auditParallelRunner *utils.SecurityParallelRunner, cmdResults *results.SecurityCommandResults, strategy ScaStrategy) (generalError error) {

	return
}
