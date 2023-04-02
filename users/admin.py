# from django import forms
from django.contrib import admin
# from django.contrib.auth.models import Group
# from django.contrib.auth.admin import UserAdmin as BaseUserAdmin
# from django.contrib.auth.forms import ReadOnlyPasswordHashField
# from django.core.exceptions import ValidationError
from .models import CustomUser
# from django.contrib.auth.models import Permission


# class CustomUserCreationForm(forms.ModelForm):
#     """A form for creating new users. Includes all the required
#     fields, plus a repeated password."""
#     password1 = forms.CharField(label='Password', widget=forms.PasswordInput)
#     password2 = forms.CharField(label='Password confirmation', widget=forms.PasswordInput)

#     class Meta:
#         model = CustomUser
#         fields = ('email', 'full_name',)

#     def clean_password2(self):
#         # Check that the two password entries match
#         password1 = self.cleaned_data.get("password1")
#         password2 = self.cleaned_data.get("password2")
#         if password1 and password2 and password1 != password2:
#             raise ValidationError("Passwords don't match")
#         return password2

#     def save(self, commit=True):
#         # Save the provided password in hashed format
#         user = super().save(commit=False)
#         user.set_password(self.cleaned_data["password1"])
#         if commit:
#             user.save()
#         return user


# class CustomUserChangeForm(forms.ModelForm):
#     """A form for updating users. Includes all the fields on
#     the user, but replaces the password field with admin's
#     disabled password hash display field.
#     """
#     password = ReadOnlyPasswordHashField()

#     class Meta:
#         model = CustomUser
#         fields = ['email', 'password', 'is_active', 'is_superuser',]


# class CustomUserAdmin(BaseUserAdmin):
#     # The forms to add and change user instances
#     form = CustomUserChangeForm
#     add_form = CustomUserCreationForm

#     # The fields to be used in displaying the User model.
#     # These override the definitions on the base UserAdmin
#     # that reference specific fields on auth.User.
#     list_display = ['full_name', 'email', 'phone_number']
#     list_filter = ('is_superuser',)
#     list_display_links = ['full_name']
#     fieldsets = (
#         (None, {'fields': ('password',)}),
#         ('Personal info', {'fields': ('full_name', 'email', 'date_of_birth', 'corporation_name',
#         'corporation_number', 'phone_number',)}),
#         ('Permissions', {'fields': ('is_superuser', 'is_active', 'is_staff', 'is_user',
#         'is_professional', 'user_permissions',)}),
#     )
#     # add_fieldsets is not a standard ModelAdmin attribute. UserAdmin
#     # overrides get_fieldsets to use this attribute when creating a user.
#     add_fieldsets = (
#         (None, {
#             'classes': ('wide',),
#             'fields': ('full_name', 'email', 'password1', 'password2', 'date_of_birth', 'phone_number', 
#                   'corporation_name', 'corporation_number', 'is_user', 'is_professional')
#         }),
#     )
#     search_fields = ('email',)
#     ordering = ('email',)
#     filter_horizontal = ()



# # Now register the new UserAdmin...
# admin.site.register(CustomUser, CustomUserAdmin)
admin.site.register(CustomUser)
# # ... and, since we're not using Django's built-in permissions,
# # unregister the Group model from admin.
# admin.site.unregister(Group)
# admin.site.register(Permission)