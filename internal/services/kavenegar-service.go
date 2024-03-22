package services

import (
	"fmt"
	"github.com/kavenegar/kavenegar-go"
	"github.com/ther0y/xeep-auth-service/internal/errors"
	"github.com/ther0y/xeep-auth-service/internal/utils"
)

type kavenegarService struct {
	client *kavenegar.Kavenegar
}

func newKavenegarService() SmsService {
	kavenegarApiKey, err := utils.GetEnv("KAVENEGAR_API_KEY")
	if err != nil {
		panic("KAVENEGAR_API_KEY is not set")
	}

	client := kavenegar.New(kavenegarApiKey)
	return &kavenegarService{
		client: client,
	}
}

func (k *kavenegarService) SendSmsOtp(receptor string, token string) error {
	// TODO: Put the template name in the config
	template := "verify"
	params := &kavenegar.VerifyLookupParam{}

	if _, err := k.client.Verify.Lookup(receptor, template, token, params); err != nil {
		switch err := err.(type) {
		case *kavenegar.APIError:
			fmt.Println(err.Error())
		case *kavenegar.HTTPError:
			fmt.Println(err.Error())
		default:
			fmt.Println(err.Error())
		}

		return errors.InternalError("failed to send the OTP", err)
	}

	return nil
}
