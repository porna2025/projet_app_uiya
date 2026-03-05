from django.db import models
from django.contrib.auth.models import User
import os


def avatar_upload_path(instance, filename):
    ext = filename.split('.')[-1]
    filename = f"avatar_{instance.user.id}.{ext}"
    return os.path.join('avatars', filename)


class UserProfile(models.Model):
    user = models.OneToOneField(User, on_delete=models.CASCADE)
    security_level = models.CharField(max_length=20, default='medium')
    two_factor_enabled = models.BooleanField(default=False)
    avatar = models.ImageField(
        upload_to=avatar_upload_path,
        null=True, blank=True,
        verbose_name="Photo de profil"
    )

    class Meta:
        verbose_name = "Profil utilisateur"
        verbose_name_plural = "Profils utilisateurs"

    def __str__(self):
        return f"Profil de {self.user.username}"


class EncryptionKey(models.Model):
    user = models.ForeignKey(User, on_delete=models.CASCADE)
    name = models.CharField(max_length=100)
    key_type = models.CharField(max_length=20, choices=[
        ('AES', 'AES'), ('RSA', 'RSA'), ('PASSWORD', 'Mot de passe')
    ])
    key_value = models.TextField()
    created_at = models.DateTimeField(auto_now_add=True)
    last_used = models.DateTimeField(null=True, blank=True)
    is_active = models.BooleanField(default=True)

    class Meta:
        verbose_name = "Clé de chiffrement"
        verbose_name_plural = "Clés de chiffrement"
        ordering = ['-created_at']
        indexes = [
            models.Index(fields=['user', '-created_at']),
            models.Index(fields=['user', 'is_active']),
        ]

    def __str__(self):
        return f"{self.name} ({self.key_type})"


class EncryptedFile(models.Model):
    user = models.ForeignKey(User, on_delete=models.CASCADE)
    original_name = models.CharField(max_length=255)
    encrypted_name = models.CharField(max_length=255)
    file_path = models.CharField(max_length=500)
    file_size = models.BigIntegerField()
    encryption_method = models.CharField(max_length=50, default='AES-256-CBC')
    encrypted_at = models.DateTimeField(auto_now_add=True)
    is_encrypted = models.BooleanField(default=True)

    class Meta:
        verbose_name = "Fichier chiffré"
        verbose_name_plural = "Fichiers chiffrés"
        ordering = ['-encrypted_at']
        indexes = [
            models.Index(fields=['user', '-encrypted_at']),
            models.Index(fields=['is_encrypted']),
        ]

    def __str__(self):
        return f"{self.original_name} ({self.get_file_size_display()})"

    def get_file_size_display(self):
        size = self.file_size
        for unit in ['B', 'KB', 'MB', 'GB']:
            if size < 1024.0:
                return f"{size:.2f} {unit}"
            size /= 1024.0
        return f"{size:.2f} TB"

    def delete_file(self):
        if os.path.exists(self.file_path):
            os.remove(self.file_path)


class ActivityLog(models.Model):
    SEVERITY_CHOICES = [
        ('INFO', 'Information'), ('WARNING', 'Avertissement'),
        ('ERROR', 'Erreur'), ('CRITICAL', 'Critique'),
    ]
    user = models.ForeignKey(User, on_delete=models.SET_NULL, null=True, blank=True)
    action = models.CharField(max_length=100)
    description = models.TextField()
    severity = models.CharField(max_length=20, choices=SEVERITY_CHOICES, default='INFO')
    ip_address = models.GenericIPAddressField(null=True, blank=True)
    timestamp = models.DateTimeField(auto_now_add=True)

    class Meta:
        verbose_name = "Journal d'activité"
        verbose_name_plural = "Journaux d'activité"
        ordering = ['-timestamp']
        indexes = [
            models.Index(fields=['user', '-timestamp']),
            models.Index(fields=['severity']),
            models.Index(fields=['action']),
        ]

    def __str__(self):
        return f"{self.action} - {self.user} - {self.timestamp.strftime('%d/%m/%Y %H:%M')}"
