from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import authentication, permissions
from rest_framework import status
from rest_framework.permissions import IsAuthenticated

from rest_framework_simplejwt.tokens import RefreshToken

from accounts import serializers as accounts_serializers

from django.contrib.auth.models import User

# Create your views here.


class RegisterView(APIView):
    @staticmethod
    def post(request):
        data = request.data

        serializer_instance = accounts_serializers.RegisterSerializer(data=data)

        if not serializer_instance.is_valid():
            return Response(
                serializer_instance.errors,
                status=status.HTTP_400_BAD_REQUEST,
            )

        serializer_instance.save()
        return Response(
            {
                "message": "User created successfully.",
                "status": True,
                "data": serializer_instance.data,
            },
            status=status.HTTP_201_CREATED,
        )


class LoginView(APIView):
    
    @staticmethod
    def post(request):
        data = request.data

        username = data.get('username')
        password = data.get('password')

        user_instance = User.objects.filter(username=username).first()

        if user_instance and user_instance.check_password(password):
            refresh = RefreshToken.for_user(user_instance)

            return Response({
                "access_token": str(refresh.access_token),
                "refresh_token": str(refresh)
            })


        return Response({
            "message": "Invalid Credentials"
        }, status=status.HTTP_400_BAD_REQUEST)
    



class ProfileView(APIView):
    permission_classes  = [IsAuthenticated]

    @staticmethod
    def get(request):
        user = request.user
        
        serializer_instance = accounts_serializers.RegisterSerializer(user)

        return Response(serializer_instance.data)

