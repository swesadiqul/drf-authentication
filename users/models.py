from django.db import models
from django.contrib.auth.models import AbstractBaseUser, BaseUserManager, PermissionsMixin

class CustomUserManager(BaseUserManager):
    def create_user(self, email, password=None, **extra_fields):
        if not email:
            raise ValueError('The Email field must be set')

        email = self.normalize_email(email)
        user = self.model(email=email, **extra_fields)
        user.set_password(password)
        user.save(using=self._db)
        return user

    def create_superuser(self, email, password=None, **extra_fields):
        extra_fields.setdefault('is_staff', True)
        extra_fields.setdefault('is_superuser', True)
        return self.create_user(email, password, **extra_fields)

class CustomUser(AbstractBaseUser, PermissionsMixin):
    username = None
    full_name = models.CharField(max_length=255)
    email = models.EmailField(unique=True)
    corporation_name = models.CharField(max_length=255)
    corporation_number = models.CharField(max_length=20)
    date_of_birth = models.DateField(null=True)
    phone_number = models.CharField(max_length=20)
    last_login = models.DateTimeField(null=True)
    join_date = models.DateTimeField(auto_now_add=True)
    is_active = models.BooleanField(default=True)
    is_staff = models.BooleanField(default=False)
    is_superuser = models.BooleanField(default=False)
    is_user = models.BooleanField(default=False)
    is_professional = models.BooleanField(default=False)

    USERNAME_FIELD = 'email'
    REQUIRED_FIELDS = ['full_name','corporation_name', 'corporation_number', 'date_of_birth', 'phone_number']

    objects = CustomUserManager()

    def __str__(self):
        return self.email

    def get_full_name(self):
        return self.full_name

    def get_short_name(self):
        return self.full_name.split()[0]

    def has_perm(self, perm, obj=None):
        return True

    def has_module_perms(self, app_label):
        return True
    

    class Meta:
        verbose_name_plural = "Custom User"

    def __str__(self):
        return self.full_name
