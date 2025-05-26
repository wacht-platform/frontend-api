package waitlist

type JoinWaitlistRequest struct {
	FirstName string `form:"first_name"`
	LastName  string `form:"last_name"`
	Email     string `form:"email"`
}
