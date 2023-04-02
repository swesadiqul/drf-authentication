from rest_framework.response import Response
from rest_framework.views import APIView
from .serializers import *
from django.contrib.auth import login, logout
import pyotp
from rest_framework.permissions import IsAuthenticated
from rest_framework_simplejwt.tokens import RefreshToken
from rest_framework import status
from django.contrib.auth import get_user_model
from .emails import send_otp_via_email
from django.core.exceptions import ObjectDoesNotExist
import datetime
import json
User = get_user_model()



def generate_otp():
    # Generate a random secret key
    secret = pyotp.random_base32()

    # Create an OTP object
    totp = pyotp.TOTP(secret, digits=4)

    # Generate the OTP
    otp = totp.now()

    return secret, otp


class SignupAPIView(APIView):

    def post(self, request):
        # Get the user's phone number and email from the request
        serializer = SignupSerializer(data=request.data)
        if serializer.is_valid():
            email = request.data.get('email')
            phone_number = request.data.get('phone_number')
            password2 = request.data.get('password2')

            # Check if the phone number and email are valid
            # if not phone_number or not email:
            #     return Response({'error': 'Phone number and email are required.'}, status=400)

            # Check if the user already exists
            try:
                user = CustomUser.objects.get(email=email)
                return Response({'error': 'User already exists.'}, status=400)
            except ObjectDoesNotExist:
                pass

            # Generate a new OTP
            secret, otp = generate_otp()

            otp_expire_time = datetime.datetime.now() + datetime.timedelta(minutes=1)
            otp_expire_time_str = otp_expire_time.strftime('%Y-%m-%d %H:%M:%S')
            # Serialize the string using JSON
            otp_expire_time_json = json.dumps({'timestamp': otp_expire_time_str})

            # Save the secret key, phone_number, email, otp_expire_time and OTP in the user's session
            request.session['otp_secret'] = secret
            request.session['otp'] = otp
            request.session['phone_number'] = phone_number
            request.session['email'] = email
            request.session['otp_expire_time'] = otp_expire_time_json
            request.session['password2'] = password2

            # Send the OTP to the user's phone number using your preferred method
            # For example, you can use Twilio to send an SMS message
            # send_otp_sms(phone_number, otp)
            send_otp_via_email(email, otp)

            return Response({'success': 'OTP has been sent.'}, status=200)
        else:
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


class VerifyOTPView(APIView):

    def post(self, request):
        # Get the user's OTP from the request
        otp = request.data.get('otp')

        # Check if the OTP is valid
        if not otp:
            return Response({'error': 'OTP is required.'}, status=400)

        # Get the secret key, phone number, email, and OTP expiry time from the user's session
        otp_secret = request.session.get('otp_secret')
        otp = request.session.get('otp')
        phone_number = request.session.get('phone_number')
        email = request.session.get('email')
        otp_expire_time = request.session.get('otp_expire_time')
        password2 = request.session.get('password2')
        recent_time = datetime.datetime.now()
        # Convert datetime object to string
        recent_time_str = recent_time.strftime('%Y-%m-%d %H:%M:%S')

        # Serialize the string using JSON
        recent_time_json = json.dumps({'timestamp': recent_time_str})
       

        # Check if the OTP has expired
        if recent_time_json > otp_expire_time:
            # Generate a new OTP
            secret, otp = generate_otp()

            otp_expire_time = datetime.datetime.now() + datetime.timedelta(minutes=1)
            otp_expire_time_str = otp_expire_time.strftime('%Y-%m-%d %H:%M:%S')
            # Serialize the string using JSON
            otp_expire_time_json = json.dumps({'timestamp': otp_expire_time_str})

            # Save the secret key and OTP in the user's session
            request.session['otp_secret'] = secret
            request.session['otp'] = otp
            request.session['phone_number'] = phone_number
            request.session['email'] = email
            request.session['otp_expire_time'] = otp_expire_time_json
            request.session['password2'] = password2
            send_otp_via_email(email, otp)

            return Response({'error': 'OTP has expired. A new OTP has been sent.'}, status=400)

        # Verify the OTP
        # totp = pyotp.TOTP(otp_secret)
        # print(request.session['otp'])
        # if totp.verify(otp):
        elif request.session['otp'] == otp:
            # Create the user
            user = CustomUser.objects.create_user(email=email, phone_number=phone_number)
            print(password2)
            user.set_password(password2)
            user.save()

            # Clear the session data
            del request.session['otp_secret']
            del request.session['otp']
            del request.session['phone_number']
            del request.session['email']
            del request.session['otp_expire_time']
            del request.session['password2']

            return Response({'success': 'User has been created.'}, status=200)
        else:
            return Response({'error': 'Invalid OTP.'}, status=400)


class LoginAPIView(APIView):

    def post(self, request):
        try:
            data = request.data
            serializer = LoginSerializer(data=data)
            if serializer.is_valid():
                email = serializer.data['email']
                password = serializer.data['password']
                user = authenticate(email=email, password=password)
                
                if user is None:
                     return Response({
                    'status': status.HTTP_203_NON_AUTHORITATIVE_INFORMATION,
                    'message': 'Invalid email or password.',
                    'error': serializer.errors
                    })

                refresh = RefreshToken.for_user(user)
                login(request, user)
                return Response({
                    'status': status.HTTP_200_OK,
                    'message': 'User successfully login',
                    'access': str(refresh.access_token),
                    'refresh': str(refresh)
                    })

            return Response({
                'status': status.HTTP_203_NON_AUTHORITATIVE_INFORMATION,
                'message': 'Invalid email or password.',
                'error': serializer.errors
            })
        except Exception as e:
            print(e)
        
        
        return Response({
            'status': status.HTTP_404_NOT_FOUND,
            'message': 'Email or password is invalid.',
            })
    

class LogoutAPIView(APIView):
    permission_classes = [IsAuthenticated]
    def post(self, request, *args, **kwargs):
        logout(request)
        return Response({
            'status': status.HTTP_200_OK,
            'message': 'User successfully logout',
        })


# class ChangePasswordAPIView(APIView):
#     permission_classes = [IsAuthenticated]

#     def get_object(self, queryset=None):
#         return self.request.user

#     def post(self, request, *args, **kwargs):
#         self.object = self.get_object()
#         serializer = ChangePasswordSerializer(data=request.data)

#         if serializer.is_valid():
#             # Check old password
#             old_password = serializer.data.get("old_password")
#             if not self.object.check_password(old_password):
#                 return Response({"old_password": ["Wrong password."]}, 
#                                 status=status.HTTP_400_BAD_REQUEST)
#             # set_password also hashes the password that the user will get
#             self.object.set_password(serializer.data.get("new_password"))
#             self.object.save()
#             return Response(status=status.HTTP_204_NO_CONTENT)

#         return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)



class ChangePasswordAPIView(APIView):
    permission_classes = [IsAuthenticated]
    # authentication_classes = [JWTAuthentication]

    def post(self, request):
        serializer = ChangePasswordSerializer(data=request.data)
        if serializer.is_valid():
            user = User.objects.get(id=request.user.id)
            if user.check_password(serializer.data.get('old_password')):
                user.set_password(serializer.data.get('new_password'))
                user.save()
                return Response({'status': 'Password changed successful.'}, status=status.HTTP_200_OK)
            else:
                return Response({'error': 'Wrong password.'}, status=status.HTTP_400_BAD_REQUEST)
        else:
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)