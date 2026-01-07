
"""
FixMyCampus URL Configuration
"""
from django.contrib import admin
from django.urls import path, include

urlpatterns = [
    path('admin_django/', admin.site.urls), # Standard Django admin
    path('', include('core.urls')),
]
