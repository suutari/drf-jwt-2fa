from django.conf.urls import url

from . import views

urlpatterns = [
    url('^get-code/', views.obtain_code_token, name='get-code'),
    url('^auth/', views.obtain_auth_token, name='auth'),
    url('^refresh/', views.refresh_auth_token, name='refresh'),
    url('^verify/', views.verify_auth_token, name='verify'),
]
