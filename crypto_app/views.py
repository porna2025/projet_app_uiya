from django.shortcuts import render, redirect, get_object_or_404
from django.contrib.auth.decorators import login_required
from django.contrib.auth import login, logout, authenticate, update_session_auth_hash
from django.contrib.auth.models import User as DjangoUser
from django.contrib import messages
from django.http import FileResponse, JsonResponse
from django.utils.text import get_valid_filename
from django.core.paginator import Paginator
from django.db.models import Sum
from django.views.decorators.http import require_POST
from django.utils import timezone
from datetime import timedelta
import logging
import os
import uuid
import json
import base64
from .forms import (
    UserRegistrationForm, EncryptFileForm, DecryptFileForm,
    TextEncryptionForm, KeyGenerationForm,
)
from .models import UserProfile, EncryptionKey, EncryptedFile, ActivityLog
from .utils import CryptoUtils
from .utils_email import send_otp_email, send_welcome_email, send_login_notification_email

logger = logging.getLogger(__name__)


def home(request):
    if request.user.is_authenticated:
        return redirect('dashboard')
    return render(request, 'crypto_app/home.html')


@login_required
def dashboard(request):
    stats = {
        'total_files': EncryptedFile.objects.filter(user=request.user).count(),
        'active_keys': EncryptionKey.objects.filter(user=request.user, is_active=True).count(),
        'recent_activities': ActivityLog.objects.filter(user=request.user).order_by('-timestamp')[:5],
        'recent_files': EncryptedFile.objects.filter(user=request.user).order_by('-encrypted_at')[:5],
    }
    return render(request, 'crypto_app/dashboard.html', {'stats': stats})


@login_required
def encrypt_file(request):
    if request.method == 'POST':
        form = EncryptFileForm(request.POST, request.FILES)
        if form.is_valid():
            try:
                uploaded_file = request.FILES['file']
                safe_name = get_valid_filename(uploaded_file.name)
                password = form.cleaned_data['password']
                user_dir = f"uploads/{request.user.id}"
                os.makedirs(user_dir, exist_ok=True)
                original_path = os.path.join(user_dir, safe_name)
                with open(original_path, 'wb+') as destination:
                    for chunk in uploaded_file.chunks():
                        destination.write(chunk)
                encrypted_filename = f"{uuid.uuid4()}.enc"
                encrypted_path = os.path.join(user_dir, encrypted_filename)
                result = CryptoUtils.encrypt_file(original_path, encrypted_path, password)
                if result['success']:
                    EncryptedFile.objects.create(
                        user=request.user, original_name=uploaded_file.name,
                        encrypted_name=encrypted_filename, file_path=encrypted_path,
                        file_size=os.path.getsize(encrypted_path), is_encrypted=True
                    )
                    ActivityLog.objects.create(
                        user=request.user, action='ENCRYPTION',
                        description=f"Chiffrement de {uploaded_file.name}",
                        severity='INFO', ip_address=request.META.get('REMOTE_ADDR')
                    )
                    os.remove(original_path)
                    messages.success(request, f"Fichier '{uploaded_file.name}' chiffré avec succès !")
                    return redirect('file_list')
                else:
                    messages.error(request, f"Erreur de chiffrement : {result['error']}")
                    if os.path.exists(original_path):
                        os.remove(original_path)
            except Exception as e:
                logger.exception(f"Erreur chiffrement pour {request.user.id}")
                messages.error(request, f"Une erreur est survenue : {str(e)}")
        else:
            for field, errors in form.errors.items():
                for error in errors:
                    messages.error(request, error)
    else:
        form = EncryptFileForm()
    return render(request, 'crypto_app/encrypt.html', {'form': form})


@login_required
def decrypt_file(request):
    if request.method == 'POST':
        form = DecryptFileForm(request.POST, request.FILES)
        if form.is_valid():
            try:
                uploaded_file = request.FILES['file']
                safe_name = get_valid_filename(uploaded_file.name)
                password = form.cleaned_data['password']
                user_dir = f"uploads/{request.user.id}"
                os.makedirs(user_dir, exist_ok=True)
                encrypted_path = os.path.join(user_dir, safe_name)
                with open(encrypted_path, 'wb+') as destination:
                    for chunk in uploaded_file.chunks():
                        destination.write(chunk)
                decrypted_filename = f"decrypted_{uuid.uuid4()}_{uploaded_file.name.replace('.enc', '')}"
                decrypted_path = os.path.join(user_dir, decrypted_filename)
                result = CryptoUtils.decrypt_file(encrypted_path, decrypted_path, password)
                if result['success']:
                    response = FileResponse(
                        open(decrypted_path, 'rb'),
                        as_attachment=True, filename=decrypted_filename
                    )
                    ActivityLog.objects.create(
                        user=request.user, action='DECRYPTION',
                        description=f"Déchiffrement de {uploaded_file.name}",
                        severity='INFO', ip_address=request.META.get('REMOTE_ADDR')
                    )
                    os.remove(encrypted_path)
                    return response
                else:
                    messages.error(request, f"Erreur de déchiffrement : {result['error']}")
                    if os.path.exists(encrypted_path):
                        os.remove(encrypted_path)
            except Exception as e:
                logger.exception(f"Erreur déchiffrement pour {request.user.id}")
                messages.error(request, f"Une erreur est survenue : {str(e)}")
        else:
            for field, errors in form.errors.items():
                for error in errors:
                    messages.error(request, error)
    else:
        form = DecryptFileForm()
    recent_files = EncryptedFile.objects.filter(user=request.user).order_by('-encrypted_at')[:3]
    return render(request, 'crypto_app/decrypt.html', {'form': form, 'recent_files': recent_files})


@login_required
def encrypt_text(request):
    result = None
    action = None
    if request.method == 'POST':
        form = TextEncryptionForm(request.POST)
        if form.is_valid():
            text = form.cleaned_data['text']
            password = form.cleaned_data['password']
            action = form.cleaned_data['action']
            if action == 'encrypt':
                result = CryptoUtils.encrypt_text(text, password)
                messages.success(request, "Texte chiffré avec succès !")
            else:
                result = CryptoUtils.decrypt_text(text, password)
                messages.info(request, "Texte déchiffré !")
    else:
        form = TextEncryptionForm()
    return render(request, 'crypto_app/encrypt_text.html', {
        'form': form, 'result': result, 'action': action,
    })


@login_required
def manage_keys(request):
    if request.method == 'POST':
        form = KeyGenerationForm(request.POST)
        if form.is_valid():
            name = form.cleaned_data['name']
            key_type = form.cleaned_data['key_type']
            if key_type == 'AES':
                key_value = CryptoUtils.generate_aes_key()
            elif key_type == 'RSA':
                key_pair = CryptoUtils.generate_rsa_keypair()
                key_value = json.dumps(key_pair, indent=2)
            else:
                key_value = base64.b64encode(os.urandom(16)).decode()
            EncryptionKey.objects.create(
                user=request.user, name=name, key_type=key_type, key_value=key_value
            )
            messages.success(request, f"Clé '{name}' générée avec succès !")
            return redirect('manage_keys')
    else:
        form = KeyGenerationForm()
    keys = EncryptionKey.objects.filter(user=request.user)
    return render(request, 'crypto_app/keys.html', {'form': form, 'keys': keys})


@login_required
def view_key(request, key_id):
    key = get_object_or_404(EncryptionKey, id=key_id, user=request.user)
    return render(request, 'crypto_app/key_detail.html', {'key': key})


@login_required
def delete_key(request, key_id):
    key = get_object_or_404(EncryptionKey, id=key_id, user=request.user)
    if request.method == 'POST':
        name = key.name
        key.delete()
        ActivityLog.objects.create(
            user=request.user, action='DELETE_KEY',
            description=f"Suppression de la clé {name}",
            severity='INFO', ip_address=request.META.get('REMOTE_ADDR')
        )
        messages.success(request, f"Clé '{name}' supprimée avec succès")
        return redirect('manage_keys')
    return render(request, 'crypto_app/confirm_delete_key.html', {'key': key})


@login_required
def file_list(request):
    qs = EncryptedFile.objects.filter(user=request.user).order_by('-encrypted_at')
    paginator = Paginator(qs, 10)
    files = paginator.get_page(request.GET.get('page'))
    total_size = qs.aggregate(total_size=Sum('file_size'))['total_size'] or 0
    quota = 1024 * 1024 * 1024

    def human_readable_size(size):
        s = float(size)
        for unit in ['B', 'KB', 'MB', 'GB', 'TB']:
            if s < 1024.0:
                return f"{s:.2f} {unit}"
            s /= 1024.0
        return f"{s:.2f} PB"

    return render(request, 'crypto_app/files.html', {
        'files': files,
        'total_size': total_size,
        'total_size_display': human_readable_size(total_size),
        'encrypted_count': qs.filter(is_encrypted=True).count(),
        'decrypted_count': qs.filter(is_encrypted=False).count(),
        'used_percentage': int(min(100, (total_size / quota) * 100)) if quota > 0 else 0,
    })


@login_required
def download_file(request, file_id):
    encrypted_file = get_object_or_404(EncryptedFile, id=file_id, user=request.user)
    if os.path.exists(encrypted_file.file_path):
        return FileResponse(
            open(encrypted_file.file_path, 'rb'),
            as_attachment=True, filename=encrypted_file.encrypted_name
        )
    messages.error(request, "Fichier non trouvé")
    return redirect('file_list')


@login_required
def delete_file(request, file_id):
    encrypted_file = get_object_or_404(EncryptedFile, id=file_id, user=request.user)
    encrypted_file.delete_file()
    encrypted_file.delete()
    messages.success(request, "Fichier supprimé avec succès")
    return redirect('file_list')


@login_required
@require_POST
def delete_multiple_files(request):
    try:
        data = json.loads(request.body)
        file_ids = data.get('file_ids', [])
        if not isinstance(file_ids, list):
            return JsonResponse({'success': False, 'error': 'file_ids must be a list'}, status=400)
        deleted = 0
        for fid in file_ids:
            try:
                ef = EncryptedFile.objects.get(id=int(fid), user=request.user)
                ef.delete_file()
                ef.delete()
                deleted += 1
            except EncryptedFile.DoesNotExist:
                continue
        ActivityLog.objects.create(
            user=request.user, action='DELETE_MULTIPLE',
            description=f"Suppression de {deleted} fichiers",
            severity='INFO', ip_address=request.META.get('REMOTE_ADDR')
        )
        return JsonResponse({'success': True, 'deleted': deleted})
    except Exception as e:
        logger.exception('Erreur suppression multiple')
        return JsonResponse({'success': False, 'error': str(e)}, status=500)


@login_required
@require_POST
def cleanup_old_files(request):
    try:
        cutoff = timezone.now() - timedelta(days=30)
        old_files = EncryptedFile.objects.filter(user=request.user, encrypted_at__lt=cutoff)
        deleted = 0
        for f in old_files:
            f.delete_file()
            f.delete()
            deleted += 1
        ActivityLog.objects.create(
            user=request.user, action='CLEANUP_FILES',
            description=f"Nettoyage de {deleted} fichiers anciens",
            severity='INFO', ip_address=request.META.get('REMOTE_ADDR')
        )
        return JsonResponse({'success': True, 'message': f'{deleted} fichier(s) supprimés.'})
    except Exception as e:
        logger.exception('Erreur nettoyage')
        return JsonResponse({'success': False, 'error': str(e)}, status=500)


def user_login(request):
    """Connexion avec 2FA optionnel"""
    if request.user.is_authenticated:
        return redirect('dashboard')

    if request.method == 'POST':
        username = request.POST.get('username')
        password = request.POST.get('password')
        user = authenticate(request, username=username, password=password)

        if user is not None:
            userprofile, _ = UserProfile.objects.get_or_create(user=user)

            if userprofile.two_factor_enabled:
                if not user.email:
                    messages.error(request, "Aucun email configuré. Contactez l'administrateur.")
                    return render(request, 'crypto_app/login.html')
                otp = userprofile.generate_otp()
                try:
                    send_otp_email(user, otp)
                    request.session['pre_2fa_user_id'] = user.id
                    messages.info(request, f"Code envoyé à {user.email[:3]}***{user.email.split('@')[1]}")
                    return redirect('verify_otp')
                except Exception as e:
                    logger.error(f"Erreur OTP : {e}")
                    messages.error(request, "Erreur envoi du code. Réessayez.")
                    return render(request, 'crypto_app/login.html')
            else:
                login(request, user)
                messages.success(request, f"Bienvenue {username} !")
                if user.email:
                    try:
                        send_login_notification_email(user, request.META.get('REMOTE_ADDR'))
                    except Exception:
                        pass
                ActivityLog.objects.create(
                    user=user, action='LOGIN', description="Connexion réussie",
                    severity='INFO', ip_address=request.META.get('REMOTE_ADDR')
                )
                return redirect('dashboard')
        else:
            logger.warning(f"Tentative échouée : {username}")
            messages.error(request, "Identifiants incorrects")

    return render(request, 'crypto_app/login.html')


def verify_otp(request):
    """Vérification du code OTP"""
    user_id = request.session.get('pre_2fa_user_id')
    if not user_id:
        return redirect('login')

    try:
        user = DjangoUser.objects.get(id=user_id)
        userprofile = UserProfile.objects.get(user=user)
    except (DjangoUser.DoesNotExist, UserProfile.DoesNotExist):
        return redirect('login')

    if request.method == 'POST':
        otp_input = request.POST.get('otp_code', '').strip()
        if userprofile.is_otp_valid(otp_input):
            userprofile.clear_otp()
            del request.session['pre_2fa_user_id']
            login(request, user)
            messages.success(request, f"Bienvenue {user.username} !")
            if user.email:
                try:
                    send_login_notification_email(user, request.META.get('REMOTE_ADDR'))
                except Exception:
                    pass
            ActivityLog.objects.create(
                user=user, action='LOGIN_2FA',
                description="Connexion 2FA réussie",
                severity='INFO', ip_address=request.META.get('REMOTE_ADDR')
            )
            return redirect('dashboard')
        else:
            messages.error(request, "Code incorrect ou expiré.")
            ActivityLog.objects.create(
                user=user, action='LOGIN_2FA_FAILED',
                description="Code OTP incorrect",
                severity='WARNING', ip_address=request.META.get('REMOTE_ADDR')
            )

    # Masquer partiellement l'email
    email = user.email
    masked = f"{email[:2]}***@{email.split('@')[1]}" if '@' in email else email
    return render(request, 'crypto_app/verify_otp.html', {'email': masked})


def user_register(request):
    if request.user.is_authenticated:
        return redirect('dashboard')
    if request.method == 'POST':
        form = UserRegistrationForm(request.POST)
        if form.is_valid():
            try:
                user = form.save()
                login(request, user)
                UserProfile.objects.create(user=user)
                if user.email:
                    try:
                        send_welcome_email(user)
                    except Exception:
                        pass
                ActivityLog.objects.create(
                    user=user, action='REGISTER',
                    description="Nouveau compte créé",
                    severity='INFO', ip_address=request.META.get('REMOTE_ADDR')
                )
                messages.success(request, "Compte créé ! Vérifiez votre email. 🎉")
                return redirect('dashboard')
            except Exception as e:
                logger.exception("Erreur création compte")
                messages.error(request, f"Erreur : {str(e)}")
    else:
        form = UserRegistrationForm()
    return render(request, 'crypto_app/register.html', {'form': form})


@login_required
def user_logout(request):
    logout(request)
    messages.info(request, "Vous avez été déconnecté")
    return redirect('home')


@login_required
def toggle_2fa(request):
    """Activer / désactiver le 2FA"""
    if request.method == 'POST':
        userprofile, _ = UserProfile.objects.get_or_create(user=request.user)
        if not request.user.email:
            messages.error(request, "Configurez un email dans votre profil avant d'activer le 2FA.")
            return redirect('profile')
        userprofile.two_factor_enabled = not userprofile.two_factor_enabled
        userprofile.save()
        if userprofile.two_factor_enabled:
            messages.success(request, "✅ 2FA activé ! Un code sera envoyé à chaque connexion.")
            ActivityLog.objects.create(
                user=request.user, action='2FA_ENABLED',
                description="2FA activé", severity='INFO',
                ip_address=request.META.get('REMOTE_ADDR')
            )
        else:
            messages.info(request, "2FA désactivé.")
            ActivityLog.objects.create(
                user=request.user, action='2FA_DISABLED',
                description="2FA désactivé", severity='WARNING',
                ip_address=request.META.get('REMOTE_ADDR')
            )
    return redirect('profile')


@login_required
def user_profile(request):
    userprofile, _ = UserProfile.objects.get_or_create(user=request.user)

    if request.method == 'POST' and request.POST.get('action') == 'update_profile':

        # Email
        email = request.POST.get('email', '').strip()
        if email and ('@' not in email or '.' not in email):
            messages.error(request, "Adresse email invalide.")
        elif email and email != request.user.email:
            if DjangoUser.objects.filter(email__iexact=email).exclude(pk=request.user.pk).exists():
                messages.error(request, "Email déjà utilisé.")
            else:
                request.user.email = email
                request.user.save()
                messages.success(request, "Email mis à jour !")

        # Avatar
        if 'avatar' in request.FILES:
            avatar_file = request.FILES['avatar']
            if avatar_file.size > 2 * 1024 * 1024:
                messages.error(request, "La photo ne doit pas dépasser 2MB.")
            elif avatar_file.content_type not in ['image/jpeg', 'image/png', 'image/gif', 'image/webp']:
                messages.error(request, "Format non supporté. Utilisez JPG, PNG, GIF ou WebP.")
            else:
                if userprofile.avatar:
                    try:
                        if os.path.exists(userprofile.avatar.path):
                            os.remove(userprofile.avatar.path)
                    except Exception:
                        pass
                userprofile.avatar = avatar_file
                userprofile.save()
                messages.success(request, "Photo de profil mise à jour !")

        # Mot de passe
        current_password = request.POST.get('current_password', '')
        new_password = request.POST.get('new_password', '')
        confirm_new_password = request.POST.get('confirm_new_password', '')

        if current_password or new_password or confirm_new_password:
            if not current_password:
                messages.error(request, "Saisissez votre mot de passe actuel.")
            elif not request.user.check_password(current_password):
                messages.error(request, "Mot de passe actuel incorrect.")
                ActivityLog.objects.create(
                    user=request.user, action='PASSWORD_CHANGE_FAILED',
                    description="Tentative échouée de changement de mot de passe",
                    severity='WARNING', ip_address=request.META.get('REMOTE_ADDR')
                )
            elif new_password != confirm_new_password:
                messages.error(request, "Les mots de passe ne correspondent pas.")
            elif len(new_password) < 8:
                messages.error(request, "Minimum 8 caractères.")
            else:
                request.user.set_password(new_password)
                request.user.save()
                update_session_auth_hash(request, request.user)
                ActivityLog.objects.create(
                    user=request.user, action='PASSWORD_CHANGED',
                    description="Mot de passe modifié",
                    severity='INFO', ip_address=request.META.get('REMOTE_ADDR')
                )
                messages.success(request, "Mot de passe modifié avec succès !")

        ActivityLog.objects.create(
            user=request.user, action='PROFILE_UPDATE',
            description="Mise à jour du profil",
            severity='INFO', ip_address=request.META.get('REMOTE_ADDR')
        )
        return redirect('profile')

    return render(request, 'crypto_app/profile.html', {
        'userprofile': userprofile,
        'total_files': EncryptedFile.objects.filter(user=request.user).count(),
        'active_keys': EncryptionKey.objects.filter(user=request.user, is_active=True).count(),
        'recent_activities': ActivityLog.objects.filter(user=request.user).order_by('-timestamp')[:10],
    })
