package templates

import "fmt"

func FormatEmailOTPTemplate(otp string) string {
	return fmt.Sprintf(`
  <div style="font-family: Helvetica, Arial, sans-serif; max-width: 90%%; margin: auto; line-height: 1.6; color: #333; padding: 20px; box-sizing: border-box;">
    <div style="margin: auto; padding: 20px; background: #f9f9f9; border-radius: 8px; box-shadow: 0 4px 8px rgba(0, 0, 0, 0.1);">
      <div style="border-bottom: 2px solid #000; padding-bottom: 10px; margin-bottom: 20px;">
        <a href="#" style="font-size: 1.5em; color: #000; text-decoration: none; font-weight: bold;">Intellinesia</a>
      </div>
      <p style="font-size: 1.2em; margin-bottom: 10px;">Hi,</p>
      <p style="margin-bottom: 20px;">Thank you for choosing Wacht. Use the following OTP to complete your Sign Up procedures. OTP is valid for 5 minutes:</p>
      <h2 style="background: #000; color: #fff; padding: 10px 20px; border-radius: 5px; display: inline-block; margin: 0 auto;">%s</h2>
      <p style="font-size: 1em; margin-top: 20px;">Regards,<br><strong>Wacht</strong></p>
      <hr style="border: none; border-top: 1px solid #eee; margin: 20px 0;">
      <div style="text-align: right; color: #aaa; font-size: 0.9em; line-height: 1.4;">
        <p style="margin: 0;">Intellinesia LTD</p>
        <p style="margin: 0;">Kolkata</p>
        <p style="margin: 0;">India</p>
      </div>
    </div>
  </div>
  `, otp)
}
