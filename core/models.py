from django.db import models
from django.contrib.auth.models import AbstractUser, BaseUserManager

class UserManager(BaseUserManager):
    def create_user(self, roll_no, password=None, **extra_fields):
        if not roll_no:
            raise ValueError('The Roll No field must be set')
        user = self.model(roll_no=roll_no, **extra_fields)
        user.set_password(password)
        user.save(using=self._db)
        return user

    def create_superuser(self, roll_no, password=None, **extra_fields):
        extra_fields.setdefault('is_staff', True)
        extra_fields.setdefault('is_superuser', True)
        return self.create_user(roll_no, password, **extra_fields)

class User(AbstractUser):
    username = None
    roll_no = models.CharField(max_length=20, unique=True)
    first_name = models.CharField(max_length=100)
    last_name = models.CharField(max_length=100)
    email = models.EmailField(unique=True)
    mob_num = models.CharField(max_length=15)
    gender = models.CharField(max_length=10)
    is_banned = models.BooleanField(default=False)

    USERNAME_FIELD = 'roll_no'
    REQUIRED_FIELDS = ['email', 'first_name', 'last_name']

    objects = UserManager()

    def __str__(self):
        return f"{self.roll_no} - {self.first_name} {self.last_name}"

class Issue(models.Model):
    STATUS_CHOICES = [
        ('Pending', 'Pending'),
        ('In Progress', 'In Progress'),
        ('Resolved', 'Resolved'),
    ]

    issue_id = models.AutoField(primary_key=True)
    user = models.ForeignKey(User, on_delete=models.CASCADE, related_name='issues')
    # Keeping roll_no as FK reference, though typically in Django we link to User ID.
    # Since User PK is ID (default), we should link to User. But legacy data might rely on roll_no.
    # We'll link to User object. To make it seamless, let's just use ForeignKey to User.
    
    issue_type = models.CharField(max_length=100)
    description = models.TextField()
    location = models.CharField(max_length=200)
    status = models.CharField(max_length=20, choices=STATUS_CHOICES, default='Pending')
    date_reported = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return f"{self.issue_type} at {self.location} ({self.status})"

class AuditLog(models.Model):
    action = models.CharField(max_length=100)
    details = models.TextField()
    timestamp = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return f"{self.action} at {self.timestamp}"
