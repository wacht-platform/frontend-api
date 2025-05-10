package router

import (
	"github.com/gofiber/fiber/v2"
	"github.com/ilabs/wacht-fe/handler/organization"
)

func setupOrganizationRoutes(
	app *fiber.App,
) {
	orgHandler := organization.NewHandler()
	router := app.Group("/organizations")
	router.Post("/", orgHandler.CreateOrganization)
	router.Put("/:id", orgHandler.UpdateOrganization)
	router.Delete("/:id", orgHandler.DeleteOrganization)
	router.Delete("/:id/members/:memberId", orgHandler.RemoveMember)
	router.Put("/:id/members/:memberId/roles/:roleId", orgHandler.AddMemberRole)
	router.Delete("/:id/members/:memberId/roles/:roleId", orgHandler.RemoveMemberRole)
	router.Delete("/:id/leave", orgHandler.LeaveOrganization)
	router.Get("/:id/members", orgHandler.GetOrganizationMembers)
	router.Get("/:id/invitations", orgHandler.GetOrganizationInvitations)
	router.Post("/:id/invitations", orgHandler.InviteMember)
	router.Delete("/:id/invitations/:invitationId", orgHandler.DiscardInvitation)
	router.Get("/:id/roles", orgHandler.GetOrganizationRoles)
	router.Get("/:id/domains", orgHandler.GetOrganizationDomains)
	router.Post("/:id/domains", orgHandler.AddOrganizationDomain)
	router.Post("/:id/domains/:domainId/verify", orgHandler.VerifyOrganizationDomain)
	router.Delete("/:id/domains/:domainId", orgHandler.DeleteOrganizationDomain)
	router.Get("/:id/billing-addresses", orgHandler.GetOrganizationBillingAddresses)
	router.Post("/:id/billing-addresses", orgHandler.AddOrganizationBillingAddress)
	router.Put("/:id/billing-addresses/:billingAddressId", orgHandler.UpdateOrganizationBillingAddress)
	router.Delete("/:id/billing-addresses/:billingAddressId", orgHandler.DeleteOrganizationBillingAddress)
}
