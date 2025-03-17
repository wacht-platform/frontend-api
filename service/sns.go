package service

import (
	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/service/sns"
	"github.com/ilabs/wacht-fe/config"
)

type SnsService struct {
	sns *sns.SNS
}

func NewSnsService() *SnsService {
	return &SnsService{
		sns: sns.New(config.AwsSession),
	}
}

func (s *SnsService) SendSMS(phoneNumber string, message string) error {
	params := &sns.PublishInput{
		Message:     aws.String(message),
		PhoneNumber: aws.String(phoneNumber),
		MessageAttributes: map[string]*sns.MessageAttributeValue{
			"AWS.SNS.SMS.SenderID": {
				DataType:    aws.String("String"),
				StringValue: aws.String("WACHT"),
			},
			"AWS.SNS.SMS.SMSType": {
				DataType:    aws.String("String"),
				StringValue: aws.String("Transactional"),
			},
		},
	}

	_, err := s.sns.Publish(params)

	return err
}
