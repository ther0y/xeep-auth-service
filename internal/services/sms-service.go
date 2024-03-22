package services

type SmsService interface {
	SendSmsOtp(receptor string, token string) error
}

func NewSmsService() SmsService {
	return newKavenegarService()
}
