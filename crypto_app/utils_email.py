from django.core.mail import send_mail
from django.conf import settings
from django.utils import timezone


def send_otp_email(user, otp_code):
    """Envoyer le code OTP par email"""
    subject = "🔐 CryptoSafe — Votre code de vérification"
    message = f"Bonjour {user.username},\n\nVotre code : {otp_code}\n\nValable 10 minutes."
    html_message = f"""
    <div style="font-family:Arial,sans-serif;max-width:500px;margin:0 auto;background:#f8fafc;padding:30px;border-radius:16px;">
        <div style="background:linear-gradient(135deg,#0f3460,#4fc3f7);padding:20px;border-radius:12px;text-align:center;margin-bottom:24px;">
            <h1 style="color:white;margin:0;font-size:24px;">🔐 CryptoSafe</h1>
        </div>
        <h2 style="color:#1a1a2e;">Bonjour {user.username},</h2>
        <p style="color:#64748b;">Votre code de vérification à usage unique :</p>
        <div style="background:white;border:2px solid #4fc3f7;border-radius:12px;padding:24px;text-align:center;margin:20px 0;">
            <span style="font-size:40px;font-weight:bold;color:#0f3460;letter-spacing:10px;">{otp_code}</span>
        </div>
        <p style="color:#64748b;font-size:14px;">⏱️ Ce code expire dans <strong>10 minutes</strong>.</p>
        <div style="background:#fffbeb;border:1px solid #fde68a;border-radius:10px;padding:12px;margin-top:16px;">
            <p style="color:#92400e;margin:0;font-size:13px;">
                ⚠️ Si vous n'avez pas demandé ce code, ignorez cet email et sécurisez votre compte.
            </p>
        </div>
        <hr style="border:1px solid #e2e8f0;margin:20px 0;">
        <p style="color:#94a3b8;font-size:12px;text-align:center;">© CryptoSafe — Chiffrement AES-256</p>
    </div>
    """
    send_mail(
        subject=subject,
        message=message,
        from_email=settings.DEFAULT_FROM_EMAIL,
        recipient_list=[user.email],
        html_message=html_message,
        fail_silently=False,
    )


def send_welcome_email(user):
    """Email de bienvenue à l'inscription"""
    subject = "🎉 Bienvenue sur CryptoSafe !"
    message = f"Bienvenue {user.username} sur CryptoSafe ! Votre compte a été créé avec succès."
    html_message = f"""
    <div style="font-family:Arial,sans-serif;max-width:500px;margin:0 auto;background:#f8fafc;padding:30px;border-radius:16px;">
        <div style="background:linear-gradient(135deg,#0f3460,#4fc3f7);padding:20px;border-radius:12px;text-align:center;margin-bottom:24px;">
            <h1 style="color:white;margin:0;font-size:24px;">🔐 CryptoSafe</h1>
        </div>
        <h2 style="color:#1a1a2e;">Bienvenue, {user.username} ! 🎉</h2>
        <p style="color:#64748b;">Votre compte CryptoSafe a été créé avec succès le {timezone.now().strftime('%d/%m/%Y à %H:%M')}.</p>
        <div style="background:#eff6ff;border:1px solid #bfdbfe;border-radius:12px;padding:16px;margin:20px 0;">
            <h3 style="color:#0f3460;margin-top:0;">Ce que vous pouvez faire :</h3>
            <ul style="color:#3b82f6;padding-left:20px;">
                <li>🔒 Chiffrer vos fichiers avec AES-256</li>
                <li>📝 Chiffrer vos messages texte</li>
                <li>🔑 Gérer vos clés de chiffrement</li>
                <li>🛡️ Activer l'authentification 2FA</li>
            </ul>
        </div>
        <div style="background:#f0fdf4;border:1px solid #6ee7b7;border-radius:10px;padding:12px;">
            <p style="color:#065f46;margin:0;font-size:13px;">
                💡 Conseil : Activez le 2FA dans votre profil pour renforcer la sécurité.
            </p>
        </div>
        <hr style="border:1px solid #e2e8f0;margin:20px 0;">
        <p style="color:#94a3b8;font-size:12px;text-align:center;">© CryptoSafe — Vos données restent privées</p>
    </div>
    """
    send_mail(
        subject=subject,
        message=message,
        from_email=settings.DEFAULT_FROM_EMAIL,
        recipient_list=[user.email],
        html_message=html_message,
        fail_silently=True,
    )


def send_login_notification_email(user, ip_address):
    """Notification de connexion par email"""
    now = timezone.now().strftime("%d/%m/%Y à %H:%M")
    subject = "🔔 CryptoSafe — Nouvelle connexion détectée"
    message = f"Nouvelle connexion sur votre compte CryptoSafe le {now} depuis {ip_address}."
    html_message = f"""
    <div style="font-family:Arial,sans-serif;max-width:500px;margin:0 auto;background:#f8fafc;padding:30px;border-radius:16px;">
        <div style="background:linear-gradient(135deg,#0f3460,#4fc3f7);padding:20px;border-radius:12px;text-align:center;margin-bottom:24px;">
            <h1 style="color:white;margin:0;font-size:24px;">🔐 CryptoSafe</h1>
        </div>
        <h2 style="color:#1a1a2e;">Nouvelle connexion détectée</h2>
        <p style="color:#64748b;">Bonjour <strong>{user.username}</strong>, une connexion a été effectuée sur votre compte.</p>
        <div style="background:white;border:1px solid #e2e8f0;border-radius:12px;padding:16px;margin:20px 0;">
            <p style="margin:6px 0;color:#64748b;">📅 <strong>Date :</strong> {now}</p>
            <p style="margin:6px 0;color:#64748b;">🌐 <strong>Adresse IP :</strong> {ip_address}</p>
            <p style="margin:6px 0;color:#64748b;">👤 <strong>Compte :</strong> {user.username}</p>
        </div>
        <div style="background:#fffbeb;border:1px solid #fde68a;border-radius:10px;padding:14px;">
            <p style="color:#92400e;margin:0;font-size:14px;">
                ⚠️ Si ce n'est pas vous, changez immédiatement votre mot de passe et activez le 2FA.
            </p>
        </div>
        <hr style="border:1px solid #e2e8f0;margin:20px 0;">
        <p style="color:#94a3b8;font-size:12px;text-align:center;">© CryptoSafe — Chiffrement AES-256</p>
    </div>
    """
    send_mail(
        subject=subject,
        message=message,
        from_email=settings.DEFAULT_FROM_EMAIL,
        recipient_list=[user.email],
        html_message=html_message,
        fail_silently=True,
    )
