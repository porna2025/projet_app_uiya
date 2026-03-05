from django.contrib import admin
from .models import UserProfile, EncryptionKey, EncryptedFile, ActivityLog


@admin.register(UserProfile)
class UserProfileAdmin(admin.ModelAdmin):
    list_display = ('user', 'security_level', 'two_factor_enabled')
    search_fields = ('user__username',)


@admin.register(EncryptionKey)
class EncryptionKeyAdmin(admin.ModelAdmin):
    list_display = ('name', 'user', 'key_type', 'is_active', 'created_at')
    list_filter = ('key_type', 'is_active')
    search_fields = ('name', 'user__username')


@admin.register(EncryptedFile)
class EncryptedFileAdmin(admin.ModelAdmin):
    list_display = ('original_name', 'user', 'file_size', 'encryption_method', 'encrypted_at', 'is_encrypted')
    search_fields = ('original_name', 'user__username')
    list_filter = ('is_encrypted',)


@admin.register(ActivityLog)
class ActivityLogAdmin(admin.ModelAdmin):
    list_display = ('action', 'user', 'severity', 'timestamp')
    list_filter = ('severity',)
    search_fields = ('action', 'user__username')
