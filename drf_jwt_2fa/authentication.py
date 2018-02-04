from rest_framework_jwt import authentication as jwt_auth


class Jwt2faAuthentication(jwt_auth.JSONWebTokenAuthentication):
    pass
