from django.urls import path
from .views import *
from django.contrib.auth.views import LogoutView
from rest_framework_simplejwt.views import (
    TokenObtainPairView,
    TokenRefreshView,
    TokenVerifyView
)


#create url mapping
urlpatterns = [
    path('signup/', SignupAPIView.as_view(), name="signup"),
    path('verify_otp/', VerifyOTPView.as_view(), name="verify_otp"),
    path('signin/', LoginAPIView.as_view(), name="signin"),
    path('logout/', LogoutAPIView.as_view(), name='logout'),
    path('change-password/', ChangePasswordAPIView.as_view(), name="change_password"),
    path('api/token/', TokenObtainPairView.as_view(), name='token_obtain_pair'),
    path('api/token/refresh/', TokenRefreshView.as_view(), name='token_refresh'),
    path('api/token/verify/', TokenVerifyView.as_view(), name='token_verify'),
    path('reset-password-otp/', ResetPasswordOTPAPIView.as_view(), name='reset-password-otp'),
    path('verify-reset-otp/', VerifyOTPAPIView.as_view(), name='verify-reset-otp'),
    path('reset-password/', ResetPasswordAPIView.as_view(), name='reset-password'),

]
