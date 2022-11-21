from .serializers import RegistrationSerializer, EmailVerificationSerializer, ResendVerificationEmailSerializer, LoginSerializer, RequestPasswordResetEmailSerializer, SetNewPasswordSerializer, UserSerializer
from rest_framework.response import Response
from django.contrib.sites.shortcuts import get_current_site
from django.contrib.auth import get_user_model
from django.urls import reverse
from .utils import Mail
from rest_framework_simplejwt.tokens import RefreshToken
from rest_framework import generics, status, views
from django.conf import settings
import jwt

from django.contrib.auth.tokens import PasswordResetTokenGenerator
from django.utils.encoding import smart_bytes, smart_str, DjangoUnicodeDecodeError
from django.utils.http import urlsafe_base64_encode, urlsafe_base64_decode

User = get_user_model()

# Create your views here.

class RegistrationView(generics.GenericAPIView):

    serializer_class = RegistrationSerializer
    
    def post(self, request):
        user = request.data
        serializer = self.serializer_class(data=user)
        serializer.is_valid(raise_exception=True)
        serializer.save()
        user_data = serializer.data

        ####  Sending email
        user = User.objects.get(email=user_data['email'])

        token = RefreshToken.for_user(user).access_token

        current_site_domain = get_current_site(request).domain
        relativeLink = reverse('verify-email')

        verification_link = 'https://' + current_site_domain + relativeLink + "?token=" + str(token)
        message = ". Use the link below to verify your email.\n If you were not expecting any account verification email, please ignore this \n"
        email_body = "Hi " + user.email+ message + verification_link
        data = {'email_body': email_body,'to_email': user.email,
         'email_subject':'Demo Email Verification'}
        Mail.send_email(data)

        return Response(user_data, status=status.HTTP_201_CREATED)


class EmailVerificationView(views.APIView):
    serializer_class = EmailVerificationSerializer

    def get(self, request):
        token = request.GET.get('token')
        try:
            payload = jwt.decode(token,settings.SECRET_KEY, algorithms=['HS256'])
            user = User.objects.get(id=payload['user_id'])
            if not user.is_verified:
                user.is_verified = True
                user.is_active = True
                user.save()
            return Response({'Email Successfully verified'}, status = status.HTTP_200_OK)

        except jwt.ExpiredSignatureError as identifier:
            return Response({'error': 'Activation Expired'}, status= status.HTTP_400_BAD_REQUEST)
        except jwt.exceptions.DecodeError as identifier:
            return Response({'error': 'Invalid token'}, status=status.HTTP_400_BAD_REQUEST)
            

class ResendVerificationEmailView(views.APIView):
    serializer_class = ResendVerificationEmailSerializer

    def post(self, request):
        input = request.data
        Email = input['email']

        try:
            if  User.objects.filter(email=Email).exists:
                user = User.objects.get(email__exact=Email)
                token = RefreshToken.for_user(user).access_token
                current_site_domain = get_current_site(request).domain
                relativeLink = reverse('verify-email')
                verification_link = 'https://' + current_site_domain + relativeLink + "?token=" + str(token)
                message = ". Use the link below to verify your email.\n If you were not expecting any account verification email, please ignore this \n"
                email_body = "Hi " + Email+ message + verification_link
                data = {'email_body': email_body,'to_email': Email,
                'email_subject':'Demo Email Verification'}
                Mail.send_email(data)
                return Response({'Verification Email sent. Check your inbox.'}, status = status.HTTP_200_OK)
            
        except User.DoesNotExist as exc:
            return Response({'The email address does not not match any user account.'}, status = status.HTTP_400_BAD_REQUEST)
    

class LoginView(generics.GenericAPIView):
    serializer_class = LoginSerializer
    def post(self, request):
        serializer = self.serializer_class(data=request.data)
        serializer.is_valid(raise_exception=True)

        return Response(serializer.data, status=status.HTTP_200_OK)


class RequestPasswordResetEmailView(generics.GenericAPIView):
    serializer_class = RequestPasswordResetEmailSerializer

    def post(self, request):
        serializer = self.serializer_class(data=request.data)
        serializer.is_valid(raise_exception=True)
        
        Email = request.data['email']
        
        if User.objects.filter(email=Email).exists():
            user = User.objects.get(email=Email)
            uidb64 = urlsafe_base64_encode(smart_bytes(user.id))
            token = PasswordResetTokenGenerator().make_token(user)

            current_site = get_current_site(request=request).domain
            relativeLink = reverse('password-reset-confirm', kwargs={'uidb64': uidb64, 'token': token})
            absurl = 'https://' + current_site + relativeLink 
            
            email_body = "Hello! \n Use the link below to reset your password \n" + absurl
            data = {'email_body': email_body,'to_email': user.email,
                    'email_subject':'Reset your password'}
            
            Mail.send_email(data)
            
        return Response({'Success': 'Password reset email sent'}, status=status.HTTP_200_OK)
    
    
class PasswordResetTokenValidationView(generics.GenericAPIView):
    def get(self, request, uidb64, token):
        
        try:
            id = smart_str(urlsafe_base64_decode(uidb64))
            user = User.objects.get(id=id)

            if not PasswordResetTokenGenerator().check_token(user, token):
                return Response({'Error': 'Password reset link is expired! Please request for a new one!'}, status=status.HTTP_401_UNAUTHORIZED)

            return Response({'Success':True, 'Message':'Valid Credentials','uidb64':uidb64, 'token': token}, status=status.HTTP_200_OK)

        except DjangoUnicodeDecodeError as exc:
            if not PasswordResetTokenGenerator().check_token(user):
                return Response({'Error': 'Token is not valid! Please request for a new one!'}, status=status.HTTP_401_UNAUTHORIZED)
            
            
class SetNewPasswordView(generics.GenericAPIView):
    serializer_class = SetNewPasswordSerializer

    def put(self, request):
        serializer = self.serializer_class(data=request.data)
        serializer.is_valid(raise_exception=True)
        return Response({'success': True, 'message':'Password changed successfully'}, status= status.HTTP_200_OK)
    
    
class UserList(generics.ListAPIView):
    queryset = User.objects.all()
    serializer_class = UserSerializer

class UserDetail(generics.RetrieveAPIView):
    queryset = User.objects.all()
    serializer_class = UserSerializer
