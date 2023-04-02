from django.core.mail import send_mail
from django.conf import settings


def send_otp_via_email(email, otp):
    subject = "Your account activation email."
    message = f"Your account activation OTP is {otp}"
    email_from = settings.DEFAULT_FROM_EMAIL
    send_mail(subject, message, email_from, [email])




def send_otp_sms(phone_number, otp):
    # Use your preferred method to send an SMS message containing the OTP to the user's phone number
    # For example, you can use Twilio
    # Here's an example code using Twilio:
    # from twilio.rest import Client
    #
    # account_sid = 'YOUR_ACCOUNT_SID'
    # auth_token = 'YOUR_AUTH_TOKEN'
    # client = Client(account_sid, auth_token)
    # message = client.messages.create(
    #     body=f'Your OTP is {otp}',
    #     from_='YOUR_TWILIO_PHONE_NUMBER',
    #     to=phone_number
    # )
    # print(message.sid)
    pass
