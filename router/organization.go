package router

import (
	"github.com/gofiber/fiber/v2"
	"github.com/ilabs/wacht-fe/handler/organization"
	"github.com/ilabs/wacht-fe/middleware"
)

func setupOrganizationRoutes(
	app *fiber.App,
) {
	orgHandler := organization.NewHandler()
	router := app.Group("/organizations")

	router.Use(middleware.EnforceB2BSettings)

	router.Post("/", orgHandler.CreateOrganization)
	router.Post("/:id/update", orgHandler.UpdateOrganization)
	router.Post("/:id/delete", orgHandler.DeleteOrganization)
	router.Post("/:id/members/:memberId/remove", orgHandler.RemoveMember)
	router.Post("/:id/members/:memberId/roles/:roleId/add", orgHandler.AddMemberRole)
	router.Post("/:id/members/:memberId/roles/:roleId/remove", orgHandler.RemoveMemberRole)
	router.Post("/:id/leave", orgHandler.LeaveOrganization)
	router.Get("/:id/members", orgHandler.GetOrganizationMembers)
	router.Get("/:id/invitations", orgHandler.GetOrganizationInvitations)
	router.Post("/:id/invitations", orgHandler.InviteMember)
	router.Post("/:id/invitations/:invitationId/discard", orgHandler.DiscardInvitation)
	router.Post("/invitations/accept", orgHandler.AcceptInvitation)
	router.Post("/:id/roles", orgHandler.CreateOrganizationRole)
	router.Get("/:id/roles", orgHandler.GetOrganizationRoles)
	router.Post("/:id/roles/:roleId/remove", orgHandler.RemoveOrganizationRoles)
	router.Get("/:id/domains", orgHandler.GetOrganizationDomains)
	router.Post("/:id/domains", orgHandler.AddOrganizationDomain)
	router.Post("/:id/domains/:domainId/verify", orgHandler.VerifyOrganizationDomain)
	router.Post("/:id/domains/:domainId/delete", orgHandler.DeleteOrganizationDomain)
	router.Get("/:id/enterprise-connections", orgHandler.GetEnterpriseConnections)
	router.Post("/:id/enterprise-connections", orgHandler.CreateEnterpriseConnection)
	router.Post("/:id/enterprise-connections/test", orgHandler.TestEnterpriseConnectionConfig)
	router.Post("/:id/enterprise-connections/:connectionId/update", orgHandler.UpdateEnterpriseConnection)
	router.Post("/:id/enterprise-connections/:connectionId/delete", orgHandler.DeleteEnterpriseConnection)
	router.Post("/:id/enterprise-connections/:connectionId/test", orgHandler.TestEnterpriseConnection)

	// SCIM token management
	router.Post("/:id/enterprise-connections/:connectionId/scim/token", orgHandler.GenerateSCIMToken)
	router.Get("/:id/enterprise-connections/:connectionId/scim/token", orgHandler.GetSCIMToken)
	router.Post("/:id/enterprise-connections/:connectionId/scim/token/revoke", orgHandler.RevokeSCIMToken)
}
