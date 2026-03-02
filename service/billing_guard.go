package service

import (
	"errors"

	"github.com/ilabs/wacht-fe/database"
)

type pulseUsageGuardRow struct {
	PulseUsageDisabled bool `gorm:"column:pulse_usage_disabled"`
}

var ErrPulseUsageDisabled = errors.New("pulse usage is paused")

func EnsurePulseUsageAllowedForDeployment(deploymentID uint64) error {
	var row pulseUsageGuardRow
	err := database.Connection.Raw(`
		SELECT COALESCE(ba.pulse_usage_disabled, false) AS pulse_usage_disabled
		FROM deployments d
		JOIN projects p ON p.id = d.project_id
		JOIN billing_accounts ba ON ba.id = p.billing_account_id
		WHERE d.id = ?
		LIMIT 1
	`, deploymentID).Scan(&row).Error
	if err != nil {
		return err
	}

	if row.PulseUsageDisabled {
		return ErrPulseUsageDisabled
	}

	return nil
}
