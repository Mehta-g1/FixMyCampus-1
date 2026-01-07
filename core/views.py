from django.shortcuts import render, redirect, get_object_or_404
from django.contrib.auth import login, logout, authenticate, update_session_auth_hash
from django.contrib.auth.decorators import login_required
from django.contrib import messages
from django.db.models import Count
from django.http import  JsonResponse
from django.utils import timezone
from .models import User, Issue, AuditLog
import datetime
import pandas as pd
import json

def is_admin(user):
    return user.is_authenticated and user.is_staff

def index(request):
    if request.user.is_authenticated:
        if request.user.is_staff:
            return redirect('admin_dashboard')
        return redirect('home')
    return render(request, 'login.html')

def login_view(request):
    if request.method == 'POST':
        roll_no = request.POST.get('roll_no')
        password = request.POST.get('password')
        
        user = authenticate(request, roll_no=roll_no, password=password)
        
        if user is not None:
            if user.is_banned:
                messages.error(request, 'Your account has been banned. Please contact admin.')
                return render(request, 'login.html')
            
            login(request, user)
            messages.success(request, 'Login successful!', extra_tags='success') # extra_tags for bootstrap class match
            return redirect('home')
        else:
            messages.error(request, 'Invalid credentials')
    
    return render(request, 'login.html')

def signup(request):
    if request.method == 'POST':
        first_name = request.POST.get('first_name')
        last_name = request.POST.get('last_name')
        email = request.POST.get('email')
        password = request.POST.get('password')
        mob_num = request.POST.get('mob_num')
        gender = request.POST.get('gender')
        roll_no = request.POST.get('roll_no')
        
        try:
            if User.objects.filter(roll_no=roll_no).exists():
                 messages.error(request, 'User with this Roll No already exists.')
                 return render(request, 'signup.html')

            user = User.objects.create_user(
                roll_no=roll_no,
                password=password,
                email=email,
                first_name=first_name,
                last_name=last_name,
                mob_num=mob_num,
                gender=gender
            )
            messages.success(request, 'Registration successful! Please login.')
            return redirect('login')
        except Exception as e:
            messages.error(request, f'Error: {str(e)}')
    
    return render(request, 'signup.html')

def logout_view(request):
    logout(request)
    messages.info(request, 'You have been logged out')
    return redirect('login')

def forgot_password(request):
    if request.method == 'POST':
        roll_no = request.POST.get('roll_no')
        mob_num = request.POST.get('mob_num')
        new_password = request.POST.get('new_password')
        
        try:
            user = User.objects.get(roll_no=roll_no, mob_num=mob_num)
            user.set_password(new_password)
            user.save()
            messages.success(request, 'Password reset successful!')
            return redirect('login')
        except User.DoesNotExist:
            messages.error(request, 'No matching user found with that Roll Number and Mobile Number.')
    
    return render(request, 'forgot_password.html')

@login_required
def home(request):
    return render(request, 'home.html', {'username': f"{request.user.first_name} {request.user.last_name}"})

@login_required
def profile(request):
    return render(request, 'profile.html', {'user': request.user})

@login_required
def update_profile(request):
    if request.method == 'POST':
        user = request.user
        user.first_name = request.POST.get('first_name')
        user.last_name = request.POST.get('last_name')
        user.email = request.POST.get('email')
        user.mob_num = request.POST.get('mob_num')
        user.gender = request.POST.get('gender')
        user.save()
        messages.success(request, 'Profile updated successfully!')
        return redirect('profile')
    return redirect('profile')

@login_required
def change_password(request):
    if request.method == 'POST':
        current_password = request.POST.get('current_password')
        new_password = request.POST.get('new_password')
        confirm_password = request.POST.get('confirm_password')
        
        if new_password != confirm_password:
            messages.error(request, 'New passwords do not match')
            return redirect('change_password')
        
        if not request.user.check_password(current_password):
            messages.error(request, 'Current password is incorrect')
        else:
            request.user.set_password(new_password)
            request.user.save()
            update_session_auth_hash(request, request.user) # Keep user logged in
            messages.success(request, 'Password updated successfully!')
            return redirect('profile')
    
    return render(request, 'change_password.html')

@login_required
def report_issue(request):
    if request.method == 'POST':
        issue_type = request.POST.get('issue_type')
        if issue_type == 'Other':
            issue_type = request.POST.get('custom_issue_type')
        description = request.POST.get('description')
        location = request.POST.get('location')
        
        Issue.objects.create(
            user=request.user,
            issue_type=issue_type,
            description=description,
            location=location,
            status='Pending'
        )
        
        messages.success(request, 'Issue reported successfully!')
        return redirect('my_issues')
    
    return render(request, 'report_issue.html')

@login_required
def my_issues(request):
    issues = Issue.objects.filter(user=request.user).order_by('-date_reported')
    return render(request, 'my_issues.html', {'issues': issues})

@login_required
def issue_dashboard(request):
    issues = Issue.objects.all().order_by('-date_reported')
    
    # Prepare data for charts
    status_data = {}
    category_data = {}
    
    for issue in issues:
        status = issue.status
        status_data[status] = status_data.get(status, 0) + 1
        
        category = issue.issue_type
        category_data[category] = category_data.get(category, 0) + 1
        
    return render(request, 'issue_dashboard.html', {
        'issues': issues,
        'status_data': status_data,
        'category_data': category_data
    })

def about_campus(request):
    return render(request, 'about_campus.html')

def help_support(request):
    return render(request, 'help_support.html')

def about(request):
    return render(request, 'about.html')

# Admin Views

def admin_login(request):
    if request.user.is_authenticated and request.user.is_staff:
        return redirect('admin_dashboard')
        
    if request.method == 'POST':
        username = request.POST.get('username')
        password = request.POST.get('password')
        
        # Check against Django User model (roll_no as username) or superuser
        # The Flask app used 'admin@1234'. We should probably allow signing in with superuser creds.
        user = authenticate(request, roll_no=username, password=password)
        if user and user.is_staff:
             login(request, user)
             return redirect('admin_dashboard')
        else:
             messages.error(request, 'Invalid credentials')
             
    return render(request, 'admin/login.html')

@login_required
def admin_dashboard(request):
    if not request.user.is_staff:
        return redirect('admin_login')
    
    issues = Issue.objects.all()
    users = User.objects.all()
    
    pending_count = issues.filter(status='Pending').count()
    in_progress_count = issues.filter(status='In Progress').count()
    resolved_count = issues.filter(status='Resolved').count()
    
    return render(request, 'admin/dashboard.html', {
        'issues': issues,
        'users': users,
        'total_issues': issues.count(),
        'pending_count': pending_count,
        'in_progress_count': in_progress_count,
        'resolved_count': resolved_count
    })

@login_required
def admin_manage_issues(request):
    if not request.user.is_staff:
        return redirect('admin_login')

    status_filter = request.GET.get('status', 'All')
    roll_no_filter = request.GET.get('roll_no', '')
    category_filter = request.GET.get('category', '')
    
    issues = Issue.objects.all().order_by('-date_reported')
    
    if status_filter != 'All':
        issues = issues.filter(status=status_filter)
    if roll_no_filter:
        issues = issues.filter(user__roll_no__icontains=roll_no_filter)
    if category_filter:
        issues = issues.filter(issue_type__icontains=category_filter)
        
    return render(request, 'admin/manage_issues.html', {
        'issues': issues,
        'status_filter': status_filter,
        'roll_no_filter': roll_no_filter,
        'category_filter': category_filter
    })

@login_required
def admin_update_issue_status(request):
    if not request.user.is_staff:
        return redirect('admin_login')
        
    if request.method == 'POST':
        issue_id = request.POST.get('issue_id')
        new_status = request.POST.get('status')
        
        issue = get_object_or_404(Issue, issue_id=issue_id)
        issue.status = new_status
        issue.save()
        
        AuditLog.objects.create(
            action="Issue Updated",
            details=f"Issue ID: {issue_id}, New Status: {new_status}"
        )
        
        messages.success(request, 'Issue status updated successfully!')
        
    return redirect('admin_manage_issues')

@login_required
def admin_delete_issue(request, issue_id):
    if not request.user.is_staff:
        return redirect('admin_login')
        
    if request.method == 'POST':
        issue = get_object_or_404(Issue, issue_id=issue_id)
        issue.delete()
        
        AuditLog.objects.create(
            action="Issue Deleted",
            details=f"Issue ID: {issue_id}"
        )
        
        messages.success(request, 'Issue deleted successfully!')
        
    return redirect('admin_manage_issues')

@login_required
def admin_user_management(request):
    if not request.user.is_staff:
        return redirect('admin_login')
        
    users = User.objects.all()
    return render(request, 'admin/user_management.html', {'users': users})

@login_required
def admin_ban_user(request, roll_no):
    if not request.user.is_staff:
        return redirect('admin_login')
        
    if request.method == 'POST':
        user = get_object_or_404(User, roll_no=roll_no)
        user.is_banned = True
        user.save()
        
        AuditLog.objects.create(
            action="User Banned",
            details=f"Roll No: {roll_no}"
        )
        messages.success(request, 'User banned successfully!')
        
    return redirect('admin_user_management')

@login_required
def admin_unban_user(request, roll_no):
    if not request.user.is_staff:
        return redirect('admin_login')

    if request.method == 'POST':
        user = get_object_or_404(User, roll_no=roll_no)
        user.is_banned = False
        user.save()
        
        AuditLog.objects.create(
            action="User Unbanned",
            details=f"Roll No: {roll_no}"
        )
        messages.success(request, 'User unbanned successfully!')
        
    return redirect('admin_user_management')

@login_required
def admin_audit_logs(request):
    if not request.user.is_staff:
        return redirect('admin_login')
        
    logs = AuditLog.objects.all().order_by('-timestamp')[:50]
    return render(request, 'admin/audit_logs.html', {'logs': logs})

@login_required
def admin_logout(request):
    logout(request)
    messages.info(request, 'Admin logged out')
    return redirect('admin_login')

@login_required
def issues_by_date(request):
    if not request.user.is_staff:
        return JsonResponse({'error': 'Unauthorized'}, status=401)
    
    issues = Issue.objects.values('date_reported').order_by('date_reported')
    
    if not issues:
        return JsonResponse({'dates': [], 'counts': []})
        
    # Process data similar to original app
    df = pd.DataFrame(list(issues))
    df['date_reported'] = pd.to_datetime(df['date_reported']).dt.date
    grouped = df.groupby('date_reported').size().reset_index(name='count')
    
    return JsonResponse({
        'dates': [d.strftime('%Y-%m-%d') for d in grouped['date_reported']],
        'counts': grouped['count'].tolist()
    })
