package router

import (
	"github.com/gofiber/fiber/v3"
	"github.com/wacht-platform/frontend-api/handler/organization"
	"github.com/wacht-platform/frontend-api/middleware"
)

func setupOrganizationRoutes(
	app *fiber.App,
) {
	orgHandler := organization.NewHandler()
	router := app.Group("/organizations")

	router.Post("/", orgHandler.CreateOrganization)
	router.Post("/invitations/accept", orgHandler.AcceptInvitation)

	orgRoutes := router.Group("/:id", middleware.SetOrganizationContext)

	orgRoutes.Post("/update", orgHandler.UpdateOrganization)
	orgRoutes.Post("/delete", orgHandler.DeleteOrganization)
	orgRoutes.Post("/members/:memberId/remove", orgHandler.RemoveMember)
	orgRoutes.Post("/members/:memberId/roles/:roleId/add", orgHandler.AddMemberRole)
	orgRoutes.Post("/members/:memberId/roles/:roleId/remove", orgHandler.RemoveMemberRole)
	orgRoutes.Post("/leave", orgHandler.LeaveOrganization)
	orgRoutes.Get("/members", orgHandler.GetOrganizationMembers)
	orgRoutes.Get("/invitations", orgHandler.GetOrganizationInvitations)
	orgRoutes.Post("/invitations", orgHandler.InviteMember)
	orgRoutes.Post("/invitations/:invitationId/discard", orgHandler.DiscardInvitation)
	orgRoutes.Post("/invitations/:invitationId/resend", orgHandler.ResendInvitation)
	orgRoutes.Post("/roles", orgHandler.CreateOrganizationRole)
	orgRoutes.Get("/roles", orgHandler.GetOrganizationRoles)
	orgRoutes.Post("/roles/:roleId/remove", orgHandler.RemoveOrganizationRoles)
	orgRoutes.Get("/domains", orgHandler.GetOrganizationDomains)
	orgRoutes.Post("/domains", orgHandler.AddOrganizationDomain)
	orgRoutes.Post("/domains/:domainId/verify", orgHandler.VerifyOrganizationDomain)
	orgRoutes.Post("/domains/:domainId/delete", orgHandler.DeleteOrganizationDomain)
	orgRoutes.Get("/enterprise-connections", orgHandler.GetEnterpriseConnections)
	orgRoutes.Post("/enterprise-connections", orgHandler.CreateEnterpriseConnection)
	orgRoutes.Post("/enterprise-connections/test", orgHandler.TestEnterpriseConnectionConfig)
	orgRoutes.Post("/enterprise-connections/:connectionId/update", orgHandler.UpdateEnterpriseConnection)
	orgRoutes.Post("/enterprise-connections/:connectionId/delete", orgHandler.DeleteEnterpriseConnection)
	orgRoutes.Post("/enterprise-connections/:connectionId/test", orgHandler.TestEnterpriseConnection)
	orgRoutes.Post("/enterprise-connections/:connectionId/scim/token", orgHandler.GenerateSCIMToken)
	orgRoutes.Get("/enterprise-connections/:connectionId/scim/token", orgHandler.GetSCIMToken)
	orgRoutes.Post("/enterprise-connections/:connectionId/scim/token/revoke", orgHandler.RevokeSCIMToken)
}
