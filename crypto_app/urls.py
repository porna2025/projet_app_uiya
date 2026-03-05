from django.urls import path
from . import views

urlpatterns = [
    path('', views.home, name='home'),
    path('login/', views.user_login, name='login'),
    path('login/verify-otp/', views.verify_otp, name='verify_otp'),
    path('register/', views.user_register, name='register'),
    path('logout/', views.user_logout, name='logout'),

    path('dashboard/', views.dashboard, name='dashboard'),
    path('profile/', views.user_profile, name='profile'),
    path('profile/toggle-2fa/', views.toggle_2fa, name='toggle_2fa'),

    path('encrypt/', views.encrypt_file, name='encrypt_file'),
    path('decrypt/', views.decrypt_file, name='decrypt_file'),
    path('encrypt-text/', views.encrypt_text, name='encrypt_text'),

    path('files/', views.file_list, name='file_list'),
    path('files/download/<int:file_id>/', views.download_file, name='download_file'),
    path('files/delete/<int:file_id>/', views.delete_file, name='delete_file'),
    path('files/delete-multiple/', views.delete_multiple_files, name='delete_multiple_files'),
    path('files/cleanup/', views.cleanup_old_files, name='cleanup_old_files'),

    path('keys/', views.manage_keys, name='manage_keys'),
    path('keys/<int:key_id>/', views.view_key, name='view_key'),
    path('keys/delete/<int:key_id>/', views.delete_key, name='delete_key'),
]
