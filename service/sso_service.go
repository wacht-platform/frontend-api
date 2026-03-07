package service

import (
	"github.com/wacht-platform/frontend-api/database"
	"github.com/wacht-platform/frontend-api/model"
)

type SSOService struct{}

func NewSSOService() *SSOService {
	return &SSOService{}
}

func (s *SSOService) GetVerifiedDomain(fqdn string, deploymentID uint64) (*model.OrganizationDomain, error) {
	var domain model.OrganizationDomain
	err := database.Connection.
		Where("fqdn = ? AND deployment_id = ? AND verified = true", fqdn, deploymentID).
		First(&domain).Error
	if err != nil {
		return nil, err
	}
	return &domain, nil
}

func (s *SSOService) GetConnectionByDomain(domainID uint64) (*model.EnterpriseConnection, error) {
	var conn model.EnterpriseConnection
	err := database.Connection.
		Where("domain_id = ?", domainID).
		First(&conn).Error
	if err != nil {
		return nil, err
	}
	return &conn, nil
}

func (s *SSOService) GetConnectionByID(connectionID uint64) (*model.EnterpriseConnection, error) {
	var conn model.EnterpriseConnection
	err := database.Connection.
		Where("id = ?", connectionID).
		First(&conn).Error
	if err != nil {
		return nil, err
	}
	return &conn, nil
}
