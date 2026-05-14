package external_connection

import "github.com/wacht-platform/frontend-api/utils"

func decryptDeploymentSecret(encrypted string) (string, error) {
	return utils.DecryptAtRest(encrypted)
}
