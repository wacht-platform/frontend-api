package auth

type SignInRequest struct {
	Username string `form:"username"`
	Email    string `form:"email"`
	Phone    string `form:"phone"`
	Password string `form:"password"`
}

type SignUpRequest struct {
	FirstName   string `form:"firstName"`
	LastName    string `form:"lastName"`
	Username    string `form:"username"`
	PhoneNumber string `form:"phoneNumber"`
	Email       string `form:"email"`
	Password    string `form:"password"`
}

type VerifyOTPRequest struct {
	Email string `form:"email"`
	Passcode string `form:"passcode"`	
}
