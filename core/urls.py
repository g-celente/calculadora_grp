from django.urls import path
from . import views

urlpatterns = [
    path('register/', views.register, name='register'),
    path('login/', views.login, name='login'),
    path('logout/', views.logout, name='logout'),
    path('meu_perfil/', views.getUser, name='getUser'),
    path('alterarSenha/', views.alterarSenha, name='alterarSenha'),
    path('forgotPassword/', views.forgotPassword, name='forgotPassword'),
    path('', views.home, name='home'),
    # Outras rotas...
]