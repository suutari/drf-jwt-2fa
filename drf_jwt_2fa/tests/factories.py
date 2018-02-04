from django.contrib.auth.models import User


def get_user(username='testuser', password='a42', email='testuser@localhost'):
    user = User.objects.get_or_create(username=username)[0]
    user.set_password(password)
    user.email = email
    user.is_active = True
    user.save()
    return user
