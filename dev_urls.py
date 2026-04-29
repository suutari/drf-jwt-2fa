from django.conf import settings
from django.conf.urls.static import static
from django.contrib import admin
from django.urls import include, path

import drf_jwt_2fa.urls

urlpatterns = [
    path("admin/", admin.site.urls),
    path("auth/", include(drf_jwt_2fa.urls)),
    *static("static/", document_root=settings.STATIC_ROOT),
]
