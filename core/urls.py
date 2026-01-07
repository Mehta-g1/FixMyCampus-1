from django.urls import path
from . import views

urlpatterns = [
    # Auth
    path('', views.index, name='index'),
    path('login/', views.login_view, name='login'),
    path('signup/', views.signup, name='signup'),
    path('logout/', views.logout_view, name='logout'),
    path('forgot_password/', views.forgot_password, name='forgot_password'),
    
    # User
    path('home/', views.home, name='home'),
    path('profile/', views.profile, name='profile'),
    path('update_profile/', views.update_profile, name='update_profile'),
    path('change_password/', views.change_password, name='change_password'),
    
    # Issue
    path('report_issue/', views.report_issue, name='report_issue'),
    path('my_issues/', views.my_issues, name='my_issues'),
    path('issue_dashboard/', views.issue_dashboard, name='issue_dashboard'),
    
    # Static
    path('about_campus/', views.about_campus, name='about_campus'),
    path('help_support/', views.help_support, name='help_support'),
    path('about/', views.about, name='about'),
    
    # Admin Custom
    path('admin/login/', views.admin_login, name='admin_login'),
    path('admin/dashboard/', views.admin_dashboard, name='admin_dashboard'),
    path('admin/manage_issues/', views.admin_manage_issues, name='admin_manage_issues'),
    path('admin/update_issue_status/', views.admin_update_issue_status, name='admin_update_issue_status'),
    path('admin/delete_issue/<int:issue_id>/', views.admin_delete_issue, name='admin_delete_issue'),
    path('admin/user_management/', views.admin_user_management, name='admin_user_management'),
    path('admin/ban_user/<str:roll_no>/', views.admin_ban_user, name='admin_ban_user'),
    path('admin/unban_user/<str:roll_no>/', views.admin_unban_user, name='admin_unban_user'),

    
    path('admin/audit_logs/', views.admin_audit_logs, name='admin_audit_logs'),
    path('admin/logout/', views.admin_logout, name='admin_logout'),
    path('admin/api/data/issues_by_date/', views.issues_by_date, name='issues_by_date'),
]
