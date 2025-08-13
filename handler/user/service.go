package user

import (
	"context"
	"fmt"
	"mime/multipart"
	"net"
	"regexp"
	"strings"
	"time"

	"github.com/ilabs/wacht-fe/config"
	"github.com/ilabs/wacht-fe/database"
	"github.com/ilabs/wacht-fe/handler"
	"github.com/ilabs/wacht-fe/model"
	"github.com/ilabs/wacht-fe/service"
	"gorm.io/gorm"
)

const otpExpirationTime = 5 * time.Minute

type UserService struct {
	db   *gorm.DB
	sns  *service.SnsService
	s3   *service.S3Service
	nats *service.NatsService
}

func NewUserService() *UserService {
	natsService, err := service.NewNatsService()
	if err != nil {
		panic(fmt.Sprintf("Failed to initialize NATS service: %v", err))
	}
	
	return &UserService{
		db:   database.Connection,
		sns:  service.NewSnsService(),
		s3:   service.NewS3Service(),
		nats: natsService,
	}
}

func (s *UserService) storeOTPInCache(key string, otp string) error {
	return database.Redis.Set(
		context.Background(),
		fmt.Sprintf("otp:%s", key),
		otp,
		otpExpirationTime,
	).Err()
}

func (s *UserService) removeOTPFromCache(key string) error {
	return database.Redis.Del(
		context.Background(),
		fmt.Sprintf("otp:%s", key),
	).Err()
}

func (s *UserService) getOTPFromCache(key string) (string, error) {
	return database.Redis.Get(
		context.Background(),
		fmt.Sprintf("otp:%s", key),
	).Result()
}

func (s *UserService) sendEmailOTPVerificationAsync(
	deploymentID uint64,
	email string,
) error {
	var emailAddress model.UserEmailAddress
	if err := s.db.Where("email_address = ?", email).First(&emailAddress).Error; err != nil {
		return fmt.Errorf("email address not found: %s", email)
	}
	
	cacheKey := fmt.Sprintf("otp:%d", emailAddress.ID)
	code, err := database.Redis.Get(context.Background(), cacheKey).Result()
	if err != nil {
		return fmt.Errorf("verification code not found for email ID: %d", emailAddress.ID)
	}
	
	return s.nats.SendVerificationEmail(deploymentID, *emailAddress.UserID, email, code)
}

func (s *UserService) sendSmsOTPVerificationAsync(
	deploymentID uint64,
	phone string,
) error {
	return fmt.Errorf("SMS sending not implemented in NATS service")
}

func (s *UserService) uploadProfilePicture(
	userID uint64,
	file *multipart.FileHeader,
) (string, error) {
	reader, err := file.Open()
	if err != nil {
		return "", err
	}

	return s.s3.UploadToCdn(fmt.Sprintf("users/%d", userID), reader)
}

func (s *UserService) ValidateEmailRestrictions(email string, restrictions model.DeploymentRestrictions) error {
	if restrictions.AllowlistEnabled && len(restrictions.AllowlistedResources) > 0 {
		allowed := false
		emailDomain := strings.Split(email, "@")[1]
		for _, allowedResource := range restrictions.AllowlistedResources {
			if email == allowedResource || emailDomain == allowedResource {
				allowed = true
				break
			}
		}
		if !allowed {
			return handler.ErrEmailNotAllowed
		}
	}

	if restrictions.BlocklistEnabled && len(restrictions.BlocklistedResources) > 0 {
		emailDomain := strings.Split(email, "@")[1]
		for _, blockedResource := range restrictions.BlocklistedResources {
			if email == blockedResource || emailDomain == blockedResource {
				return handler.ErrEmailBlocked
			}
		}
	}

	if restrictions.BlockDisposableEmails {
		if s.isDisposableEmail(email) {
			return handler.ErrDisposableEmail
		}
	}

	if err := s.validateEmailMXRecord(email); err != nil {
		return handler.ErrEmailNotAllowed
	}

	return nil
}

func (s *UserService) ValidatePhoneRestrictions(phoneNumber string, restrictions model.DeploymentRestrictions) error {
	telesignService := service.NewTelesignService(
		config.GetEnv("TELESIGN_CUSTOMER_ID", ""),
		config.GetEnv("TELESIGN_API_KEY", ""),
	)

	if telesignService.CustomerID != "" && telesignService.APIKey != "" {
		result, err := telesignService.ValidatePhoneNumber(phoneNumber)
		if err != nil {
			return s.validatePhoneBasic(phoneNumber, restrictions)
		}

		if !result.IsValid {
			return handler.ErrVoipNumberBlocked
		}

		if result.IsBlocked {
			return handler.ErrVoipNumberBlocked
		}

		if restrictions.BlockVoipNumbers && result.IsVOIP {
			return handler.ErrVoipNumberBlocked
		}

		if restrictions.BlockVoipNumbers && result.IsHighRisk {
			return handler.ErrVoipNumberBlocked
		}

		if restrictions.CountryRestrictions.Enabled && len(restrictions.CountryRestrictions.CountryCodes) > 0 {
			allowed := false
			for _, allowedCountry := range restrictions.CountryRestrictions.CountryCodes {
				if result.CountryCode == allowedCountry {
					allowed = true
					break
				}
			}
			if !allowed {
				return handler.ErrCountryRestricted
			}
		}
	} else {
		return s.validatePhoneBasic(phoneNumber, restrictions)
	}

	return nil
}

func (s *UserService) validatePhoneBasic(phoneNumber string, restrictions model.DeploymentRestrictions) error {
	if restrictions.CountryRestrictions.Enabled && len(restrictions.CountryRestrictions.CountryCodes) > 0 {
		countryCode := s.extractCountryCodeFromPhone(phoneNumber)
		allowed := false
		for _, allowedCountry := range restrictions.CountryRestrictions.CountryCodes {
			if countryCode == allowedCountry {
				allowed = true
				break
			}
		}
		if !allowed {
			return handler.ErrCountryRestricted
		}
	}

	return nil
}

func (s *UserService) extractCountryCodeFromPhone(phoneNumber string) string {
	digits := regexp.MustCompile(`\D`).ReplaceAllString(phoneNumber, "")

	if strings.HasPrefix(digits, "1") && len(digits) == 11 {
		return "US"
	}
	if strings.HasPrefix(digits, "44") {
		return "GB"
	}
	if strings.HasPrefix(digits, "49") {
		return "DE"
	}
	if strings.HasPrefix(digits, "33") {
		return "FR"
	}
	if strings.HasPrefix(digits, "81") {
		return "JP"
	}
	if strings.HasPrefix(digits, "86") {
		return "CN"
	}
	if strings.HasPrefix(digits, "91") {
		return "IN"
	}

	return "XX"
}

func (s *UserService) validateEmailMXRecord(email string) error {
	domain := strings.Split(email, "@")[1]

	mxRecords, err := net.LookupMX(domain)
	if err != nil || len(mxRecords) == 0 {
		_, err := net.LookupHost(domain)
		if err != nil {
			return fmt.Errorf("invalid email domain: %s", domain)
		}
	}

	return nil
}

func (s *UserService) isDisposableEmail(email string) bool {
	domain := strings.ToLower(strings.Split(email, "@")[1])

	disposableDomains := []string{
		"10minutemail.com", "20minutemail.com", "guerrillamail.com", "mailinator.com",
		"tempmail.org", "temp-mail.org", "throwaway.email", "yopmail.com",
		"maildrop.cc", "sharklasers.com", "guerrillamailblock.com", "pokemail.net",
		"spam4.me", "bccto.me", "chacuo.net", "dispostable.com", "spambox.us",
		"tempail.com", "tempemail.com", "10minutesemail.net", "emailondeck.com",
		"fakeinbox.com", "mailnesia.com", "trashmail.com", "mytrashmail.com",
		"mailcatch.com", "mailexpire.com", "mailforspam.com", "mailmetrash.com",
		"mailnull.com", "mailshell.com", "mailsac.com", "mailtothis.com",
		"no-spam.ws", "nospam.ze.tc", "nowmymail.com", "objectmail.com",
		"pookmail.com", "proxymail.eu", "rcpt.at", "safe-mail.net",
		"sneakemail.com", "sogetthis.com", "spaml.com", "spammotel.com",
		"speed.1s.fr", "temporary.email", "thankyou2010.com", "trash2009.com",
		"trashymail.com", "trbvm.com", "tyldd.com", "uggsrock.com",
		"wegwerfmail.de", "wegwerfmail.net", "wegwerfmail.org", "wh4f.org",
		"whyspam.me", "willselfdestruct.com", "xoxy.net", "yoggm.com",
		"zoemail.org", "0-mail.com", "0815.ru", "0clickemail.com",
		"0wnd.net", "0wnd.org", "10mail.org", "123-m.com",
		"1chuan.com", "1pad.de", "20email.eu", "2prong.com",
		"30minutemail.com", "33mail.com", "3d-painting.com", "4warding.com",
		"7tags.com", "9ox.net", "a-bc.net", "ama-trade.de",
		"anonbox.net", "anonymbox.com", "antichef.com", "antichef.net",
		"antispam.de", "armyspy.com", "artman-conception.com", "azmeil.tk",
		"baxomale.ht.cx", "beefmilk.com", "bigstring.com", "binkmail.com",
		"bio-muesli.net", "bobmail.info", "bodhi.lawlita.com", "bofthew.com",
		"bootybay.de", "boun.cr", "bouncr.com", "breakthru.com",
		"brefmail.com", "brennendesreich.de", "broadbandninja.com", "bsnow.net",
		"bugmenot.com", "bumpymail.com", "burnthespam.info", "burstmail.info",
		"buyusedlibrarybooks.org", "byom.de", "c2.hu", "card.zp.ua",
		"casualdx.com", "cek.pm", "centermail.com", "centermail.net",
		"chammy.info", "childsavetrust.org", "chogmail.com", "choicemail1.com",
		"clixser.com", "cmail.net", "cmail.org", "coldemail.info",
		"cool.fr.nf", "correo.blogos.net", "cosmorph.com", "courriel.fr.nf",
		"courrieltemporaire.com", "crapmail.org", "cust.in", "cuvox.de",
		"d3p.dk", "dacoolest.com", "dandikmail.com", "dayrep.com",
		"dcemail.com", "deadaddress.com", "deadspam.com", "delikkt.de",
		"despam.it", "despammed.com", "devnullmail.com", "dfgh.net",
		"digitalsanctuary.com", "dingbone.com", "disposableaddress.com", "disposableemailaddresses.com",
		"disposableinbox.com", "dispose.it", "dispostable.com", "dm.w3internet.com",
		"dodgeit.com", "dodgit.com", "donemail.ru", "dontreg.com",
		"dontsendmespam.de", "drdrb.net", "dump-email.info", "dumpandjunk.com",
		"dumpyemail.com", "e-mail.com", "e-mail.org", "e4ward.com",
		"easytrashmail.com", "einrot.com", "email60.com", "emailias.com",
		"emailinfive.com", "emailmiser.com", "emailsensei.com", "emailtemporanea.com",
		"emailtemporanea.net", "emailtemporar.ro", "emailtemporario.com.br", "emailthe.net",
		"emailtmp.com", "emailto.de", "emailwarden.com", "emailx.at.hm",
		"emailxfer.com", "emz.net", "enterto.com", "ephemail.net",
		"etranquil.com", "etranquil.net", "etranquil.org", "evopo.com",
		"explodemail.com", "express.net.ua", "eyepaste.com", "fakemailz.com",
		"fastacura.com", "fastchevy.com", "fastchrysler.com", "fastkawasaki.com",
		"fastmazda.com", "fastmitsubishi.com", "fastnissan.com", "fastsubaru.com",
		"fastsuzuki.com", "fasttoyota.com", "fastyamaha.com", "filzmail.com",
		"fizmail.com", "fleckens.hu", "flyspam.com", "footard.com",
		"forgetmail.com", "fr33mail.info", "frapmail.com", "freundin.ru",
		"friendlymail.co.uk", "front14.org", "fuckingduh.com", "fudgerub.com",
		"fux0ringduh.com", "garliclife.com", "gelitik.in", "get-mail.cf",
		"get1mail.com", "get2mail.fr", "getairmail.com", "getmails.eu",
		"getonemail.com", "getonemail.net", "ghosttemail.com", "girlsundertheinfluence.com",
		"gishpuppy.com", "gmial.com", "goemailgo.com", "gotmail.net",
		"gotmail.org", "gotti.otherinbox.com", "great-host.in", "greensloth.com",
		"grr.la", "gsrv.co.uk", "guerillamail.biz", "guerillamail.com",
		"guerillamail.de", "guerillamail.net", "guerillamail.org", "guerrillamailblock.com",
		"h.mintemail.com", "haltospam.com", "harakirimail.com", "hat-geld.de",
		"hatespam.org", "hidemail.de", "hidzz.com", "hmamail.com",
		"hochsitze.com", "hotpop.com", "hulapla.de", "ieatspam.eu",
		"ieatspam.info", "ieh-mail.de", "ikbenspamvrij.nl", "imails.info",
		"inboxalias.com", "inboxclean.com", "inboxclean.org", "incognitomail.com",
		"incognitomail.net", "incognitomail.org", "insorg-mail.info", "instant-mail.de",
		"ip6.li", "irish2me.com", "iwi.net", "jetable.com",
		"jetable.fr.nf", "jetable.net", "jetable.org", "jnxjn.com",
		"jourrapide.com", "jsrsolutions.com", "junk1e.com", "kaspop.com",
		"keepmymail.com", "killmail.com", "killmail.net", "kir.ch.tc",
		"klassmaster.com", "klzlk.com", "koszmail.pl", "kurzepost.de",
		"lawlita.com", "letthemeatspam.com", "lhsdv.com", "lifebyfood.com",
		"link2mail.net", "litedrop.com", "lol.ovpn.to", "lolfreak.net",
		"lookugly.com", "lopl.co.cc", "lortemail.dk", "lr78.com",
		"lroid.com", "lukop.dk", "m4ilweb.info", "maboard.com",
		"mail-filter.com", "mail-temporaire.fr", "mail.by", "mail.mezimages.net",
		"mail.zp.ua", "mail1a.de", "mail21.cc", "mail2rss.org",
		"mail333.com", "mail4trash.com", "mailbidon.com", "mailblocks.com",
		"mailbucket.org", "mailcat.biz", "mailcatch.com", "mailde.de",
		"mailde.info", "maildrop.cc", "maildrop.cf", "maildrop.ga",
		"maildrop.gq", "maildrop.ml", "maildx.com", "maileater.com",
		"mailed.ro", "maileimer.de", "mailexpire.com", "mailfa.tk",
		"mailforspam.com", "mailfreeonline.com", "mailguard.me", "mailimate.com",
		"mailin8r.com", "mailinatar.com", "mailinatar.tk", "mailinator.com",
		"mailinator.net", "mailinator.org", "mailinator2.com", "mailincubator.com",
		"mailismagic.com", "mailme.lv", "mailme24.com", "mailmetrash.com",
		"mailmoat.com", "mailms.com", "mailnesia.com", "mailnull.com",
		"mailorg.org", "mailpick.biz", "mailrock.biz", "mailscrap.com",
		"mailshell.com", "mailsiphon.com", "mailtemp.info", "mailtome.de",
		"mailtothis.com", "mailtrash.net", "mailtv.net", "mailtv.tv",
		"mailzilla.com", "mailzilla.org", "makemetheking.com", "manybrain.com",
		"mbx.cc", "mega.zik.dj", "meinspamschutz.de", "meltmail.com",
		"messagebeamer.de", "mezimages.net", "mierdamail.com", "migmail.pl",
		"mintemail.com", "mjukglass.nu", "mobi.web.id", "moburl.com",
		"moncourrier.fr.nf", "monemail.fr.nf", "monmail.fr.nf", "monumentmail.com",
		"mt2009.com", "mt2014.com", "mycard.net.ua", "mycleaninbox.net",
		"myemailboxy.com", "mymail-in.net", "mymailoasis.com", "mynetstore.de",
		"mypacks.net", "mypartyclip.de", "myphantomemail.com", "myspaceinc.com",
		"myspaceinc.net", "myspaceinc.org", "myspacepimpedup.com", "myspamless.com",
		"mytemp.email", "mytempmail.com", "mytrashmail.com", "nabuma.com",
		"neomailbox.com", "nepwk.com", "nervmich.net", "nervtmich.net",
		"netmails.com", "netmails.net", "netzidiot.de", "neverbox.com",
		"no-spam.ws", "nobulk.com", "noclickemail.com", "nogmailspam.info",
		"nomail.xl.cx", "nomail2me.com", "nomorespamemails.com", "nonspam.eu",
		"nonspammer.de", "noref.in", "nospam.ze.tc", "nospam4.us",
		"nospamfor.us", "nospamthanks.info", "notmailinator.com", "notsharingmy.info",
		"nowmymail.com", "nurfuerspam.de", "nus.edu.sg", "nwldx.com",
		"objectmail.com", "obobbo.com", "odnorazovoe.ru", "one-time.email",
		"onewaymail.com", "online.ms", "oopi.org", "opayq.com",
		"ordinaryamerican.net", "otherinbox.com", "ovpn.to", "owlpic.com",
		"pancakemail.com", "pjkly.com", "plexolan.de", "poczta.onet.pl",
		"politikerclub.de", "pooae.com", "pookmail.com", "privacy.net",
		"privatdemail.net", "proxymail.eu", "prtnx.com", "punkass.com",
		"putthisinyourspamdatabase.com", "pwrby.com", "quickinbox.com", "rcpt.at",
		"reallymymail.com", "realtyalerts.ca", "recode.me", "recursor.net",
		"regbypass.com", "regbypass.comsafe-mail.net", "rejectmail.com", "rhyta.com",
		"rklips.com", "rmqkr.net", "royal.net", "rppkn.com",
		"rtrtr.com", "s0ny.net", "safe-mail.net", "safersignup.de",
		"safetymail.info", "safetypost.de", "sandelf.de", "saynotospams.com",
		"schafmail.de", "schrott-email.de", "secretemail.de", "secure-mail.biz",
		"selfdestructingmail.com", "selfdestructingmail.org", "sendspamhere.com", "sharklasers.com",
		"shieldedmail.com", "shieldemail.com", "shiftmail.com", "shitmail.me",
		"shitware.nl", "shmeriously.com", "shortmail.net", "sibmail.com",
		"sinnlos-mail.de", "siteposter.net", "skeefmail.com", "slaskpost.se",
		"slopsbox.com", "slushmail.com", "smashmail.de", "smellfear.com",
		"snakemail.com", "sneakemail.com", "sneakmail.de", "snkmail.com",
		"sofimail.com", "sofort-mail.de", "sogetthis.com", "soodonims.com",
		"spam.la", "spam.su", "spam4.me", "spamail.de",
		"spambob.com", "spambob.net", "spambob.org", "spambog.com",
		"spambog.de", "spambog.ru", "spambox.info", "spambox.irishspringtours.com",
		"spambox.us", "spamcannon.com", "spamcannon.net", "spamcero.com",
		"spamcon.org", "spamcorptastic.com", "spamcowboy.com", "spamcowboy.net",
		"spamcowboy.org", "spamday.com", "spamex.com", "spamfree24.com",
		"spamfree24.de", "spamfree24.eu", "spamfree24.net", "spamfree24.org",
		"spamgoes.com", "spamgourmet.com", "spamgourmet.net", "spamgourmet.org",
		"spamherelots.com", "spamhereplease.com", "spamhole.com", "spami.spam.co.za",
		"spaminator.de", "spamkill.info", "spaml.com", "spaml.de",
		"spammotel.com", "spamobox.com", "spamoff.de", "spamslicer.com",
		"spamspot.com", "spamthis.co.uk", "spamthisplease.com", "spamtrail.com",
		"spamtroll.net", "speed.1s.fr", "spoofmail.de", "stuffmail.de",
		"super-auswahl.de", "supergreatmail.com", "supermailer.jp", "superrito.com",
		"superstachel.de", "suremail.info", "talkinator.com", "tapchicuoihoi.com",
		"teewars.org", "teleworm.com", "teleworm.us", "temp-mail.org",
		"temp-mail.ru", "tempail.com", "tempalias.com", "tempe-mail.com",
		"tempemail.biz", "tempemail.com", "tempemail.net", "tempinbox.co.uk",
		"tempinbox.com", "tempmail.eu", "tempmail.it", "tempmail2.com",
		"tempmaildemo.com", "tempmailer.com", "tempmailer.de", "tempomail.fr",
		"temporarily.de", "temporarioemail.com.br", "temporaryemail.net", "temporaryforwarding.com",
		"temporaryinbox.com", "temporarymailaddress.com", "tempthe.net", "thanksnospam.info",
		"thankyou2010.com", "thecloudindex.com", "thisisnotmyrealemail.com", "thismail.net",
		"throwawayemailaddress.com", "tilien.com", "tittbit.in", "tizi.com",
		"tmailinator.com", "toomail.biz", "topranklist.de", "tradermail.info",
		"trash-amil.com", "trash-mail.at", "trash-mail.com", "trash-mail.de",
		"trash2009.com", "trashdevil.com", "trashdevil.de", "trashemail.de",
		"trashmail.at", "trashmail.com", "trashmail.de", "trashmail.me",
		"trashmail.net", "trashmail.org", "trashmail.ws", "trashmailer.com",
		"trashymail.com", "trashymail.net", "trbvm.com", "trialmail.de",
		"trillianpro.com", "tryalert.com", "turual.com", "twinmail.de",
		"tyldd.com", "uggsrock.com", "umail.net", "upliftnow.com",
		"uplipht.com", "uroid.com", "us.af", "venompen.com",
		"veryrealemail.com", "viditag.com", "viewcastmedia.com", "viewcastmedia.net",
		"viewcastmedia.org", "vomoto.com", "vubby.com", "walala.org",
		"walkmail.net", "webemail.me", "webm4il.info", "wegwerfadresse.de",
		"wegwerfemail.de", "wegwerfmail.de", "wegwerfmail.net", "wegwerfmail.org",
		"wh4f.org", "whatiaas.com", "whatpaas.com", "whatsaas.com",
		"whopy.com", "whyspam.me", "willhackforfood.biz", "willselfdestruct.com",
		"winemaven.info", "wronghead.com", "wuzup.net", "wuzupmail.net",
		"www.e4ward.com", "www.gishpuppy.com", "www.mailinator.com", "wwwnew.eu",
		"x.ip6.li", "xagloo.com", "xemaps.com", "xents.com",
		"xmaily.com", "xoxy.net", "yapped.net", "yeah.net",
		"yep.it", "yoggm.com", "yopmail.com", "yopmail.fr",
		"yopmail.net", "yourdomain.com", "ypmail.webredirect.org", "yuurok.com",
		"zehnminutenmail.de", "zippymail.info", "zoemail.org", "zoemail.com",
	}

	for _, disposableDomain := range disposableDomains {
		if domain == disposableDomain {
			return true
		}
	}

	patterns := []string{
		"temp", "disposable", "throw", "trash", "spam", "fake", "guerrilla",
		"mailinator", "10minute", "20minute", "temporary", "tempmail",
	}

	for _, pattern := range patterns {
		if strings.Contains(domain, pattern) {
			return true
		}
	}

	return false
}

func (s *UserService) ValidatePasswordRemoval(user *model.User, deployment *model.Deployment) error {
	authSettings := deployment.AuthSettings
	hasAlternativeMethod := false

	if authSettings.FirstFactor == model.FirstFactorEmailOTP {
		for _, email := range user.UserEmailAddresses {
			if email.Verified {
				hasAlternativeMethod = true
				break
			}
		}
	}

	if authSettings.MagicLink != nil && authSettings.MagicLink.Enabled {
		for _, email := range user.UserEmailAddresses {
			if email.Verified {
				hasAlternativeMethod = true
				break
			}
		}
	}

	if authSettings.Passkey != nil && authSettings.Passkey.Enabled {
		hasAlternativeMethod = true
	}

	if len(user.SocialConnections) > 0 {
		for _, socialConn := range deployment.SocialConnections {
			if socialConn.Enabled {
				hasAlternativeMethod = true
				break
			}
		}
	}

	if authSettings.AuthFactorsEnabled.PhoneOTP {
		for _, phone := range user.UserPhoneNumbers {
			if phone.Verified {
				hasAlternativeMethod = true
				break
			}
		}
	}

	if !hasAlternativeMethod {
		return handler.ErrNoAlternativeAuthMethod
	}

	return nil
}
