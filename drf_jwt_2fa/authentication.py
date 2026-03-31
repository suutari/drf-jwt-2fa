from rest_framework_simplejwt import authentication as jwt_auth


class Jwt2faAuthentication(jwt_auth.JWTAuthentication):
    pass
