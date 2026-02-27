from django import forms
from django.contrib.auth.forms import UserCreationForm
from django.contrib.auth.models import User
from .utils import CryptoUtils


class UserRegistrationForm(UserCreationForm):
    """Formulaire d'inscription avec validation de sécurité"""
    email = forms.EmailField(
        required=True,
        help_text="Adresse email valide requise",
        widget=forms.EmailInput(attrs={'class': 'form-control'})
    )
    password1 = forms.CharField(
        label="Mot de passe",
        widget=forms.PasswordInput(attrs={'class': 'form-control'}),
        help_text="Minimum 12 caractères avec majuscules, minuscules, chiffres et caractères spéciaux"
    )
    password2 = forms.CharField(
        label="Confirmer le mot de passe",
        widget=forms.PasswordInput(attrs={'class': 'form-control'})
    )
    
    class Meta:
        model = User
        fields = ['username', 'email', 'password1', 'password2']
        widgets = {
            'username': forms.TextInput(attrs={'class': 'form-control'}),
        }
    
    def clean_password1(self):
        password = self.cleaned_data.get('password1')
        if password:
            is_valid, message = CryptoUtils.validate_password(password)
            if not is_valid:
                raise forms.ValidationError(message)
        return password
    
    def clean_email(self):
        email = self.cleaned_data.get('email')
        if User.objects.filter(email__iexact=email).exists():
            raise forms.ValidationError("Cette adresse email est déjà utilisée.")
        # Validation basique du format
        if not ('@' in email and '.' in email):
            raise forms.ValidationError("Adresse email invalide.")
        return email
    
    def clean_username(self):
        username = self.cleaned_data.get('username')
        if len(username) < 3:
            raise forms.ValidationError("Le nom d'utilisateur doit contenir au moins 3 caractères.")
        if not username.isalnum() and '_' not in username:
            raise forms.ValidationError("Le nom d'utilisateur peut contenir des lettres, chiffres et underscores.")
        return username


class EncryptFileForm(forms.Form):
    """Formulaire pour chiffrer un fichier"""
    file = forms.FileField(
        label="Fichier à chiffrer",
        help_text="Fichiers supportés: tous les formats (max 100MB)",
        widget=forms.FileInput(attrs={'class': 'form-control', 'accept': '*/*'})
    )
    password = forms.CharField(
        label="Mot de passe de chiffrement",
        widget=forms.PasswordInput(attrs={'class': 'form-control'}),
        help_text="Utilisez un mot de passe fort (min 12 caractères)"
    )
    confirm_password = forms.CharField(
        label="Confirmer le mot de passe",
        widget=forms.PasswordInput(attrs={'class': 'form-control'})
    )
    
    def clean(self):
        cleaned_data = super().clean()
        password = cleaned_data.get('password')
        confirm_password = cleaned_data.get('confirm_password')
        file = cleaned_data.get('file')
        
        # Vérifier que les mots de passe correspondent
        if password and confirm_password and password != confirm_password:
            raise forms.ValidationError("Les mots de passe ne correspondent pas")
        
        # Valider la force du mot de passe
        if password:
            is_valid, message = CryptoUtils.validate_password(password)
            if not is_valid:
                raise forms.ValidationError(f"Mot de passe faible: {message}")
        
        # Vérifier la taille du fichier (max 100MB)
        if file and file.size > 100 * 1024 * 1024:
            raise forms.ValidationError("Le fichier dépasse la limite de 100MB")
        
        return cleaned_data


class DecryptFileForm(forms.Form):
    """Formulaire pour déchiffrer un fichier"""
    file = forms.FileField(
        label="Fichier chiffré",
        help_text="Sélectionnez un fichier .enc",
        widget=forms.FileInput(attrs={'class': 'form-control', 'accept': '.enc,application/octet-stream'})
    )
    password = forms.CharField(
        label="Mot de passe de déchiffrement",
        widget=forms.PasswordInput(attrs={'class': 'form-control'}),
        help_text="Entrez le mot de passe utilisé pour le chiffrement"
    )
    
    def clean_file(self):
        file = self.cleaned_data.get('file')
        if file:
            # Vérifier la taille maximale
            if file.size > 100 * 1024 * 1024:
                raise forms.ValidationError("Le fichier dépasse la limite de 100MB")
            # Optionnel: vérifier l'extension
            if not file.name.endswith('.enc'):
                raise forms.ValidationError("Le fichier doit avoir l'extension .enc")
        return file


class TextEncryptionForm(forms.Form):
    """Formulaire pour chiffrer/déchiffrer du texte"""
    text = forms.CharField(
        label="Texte à chiffrer/déchiffrer",
        widget=forms.Textarea(attrs={
            'rows': 5,
            'class': 'form-control',
            'placeholder': 'Entrez le texte à traiter...'
        })
    )
    password = forms.CharField(
        label="Mot de passe",
        widget=forms.PasswordInput(attrs={'class': 'form-control'})
    )
    action = forms.ChoiceField(
        label="Action",
        choices=[('encrypt', 'Chiffrer'), ('decrypt', 'Déchiffrer')],
        widget=forms.RadioSelect(attrs={'class': 'form-check-input'})
    )
    
    def clean_text(self):
        text = self.cleaned_data.get('text')
        if not text or len(text.strip()) == 0:
            raise forms.ValidationError("Le texte ne peut pas être vide")
        if len(text) > 1000000:  # 1MB de texte max
            raise forms.ValidationError("Le texte est trop long (max 1MB)")
        return text
    
    def clean_password(self):
        password = self.cleaned_data.get('password')
        if not password or len(password) < 4:
            raise forms.ValidationError("Le mot de passe doit contenir au moins 4 caractères")
        return password


class KeyGenerationForm(forms.Form):
    """Formulaire pour générer une clé de chiffrement"""
    name = forms.CharField(
        label="Nom de la clé",
        max_length=100,
        widget=forms.TextInput(attrs={
            'class': 'form-control',
            'placeholder': 'Ex: Ma clé personnelle'
        }),
        help_text="Donnez un nom descriptif à votre clé"
    )
    key_type = forms.ChoiceField(
        label="Type de clé",
        choices=[
            ('AES', 'Clé AES (256 bits) - Recommandé pour les fichiers'),
            ('RSA', 'Paire de clés RSA (2048 bits) - Pour la signature'),
            ('PASSWORD', 'Mot de passe fort - Simple et rapide')
        ],
        widget=forms.Select(attrs={'class': 'form-control'})
    )
    
    def clean_name(self):
        name = self.cleaned_data.get('name')
        if not name or len(name.strip()) == 0:
            raise forms.ValidationError("Le nom de la clé ne peut pas être vide")
        if len(name) < 3:
            raise forms.ValidationError("Le nom doit contenir au moins 3 caractères")
        return name
