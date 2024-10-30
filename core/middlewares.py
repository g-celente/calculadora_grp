from django.shortcuts import redirect
from django.conf import settings
import jwt

class TokenRequiredMiddleware:
    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        # Rotas que redirecionam para 'home' caso o token esteja nos cookies
        public_routes = ['/login/', '/register/', '/forgotPassword/']
        
        # Verificar se a rota atual está em 'public_routes'
        if request.path in public_routes:
            token = request.COOKIES.get('auth-token')
            # Se o token estiver nos cookies, redirecionar para 'home'
            if token:
                try:
                    jwt.decode(token, settings.SECRET_KEY, algorithms=['HS256'])
                    return redirect('home')  # Redireciona para a página 'home'
                except jwt.ExpiredSignatureError:
                    print('Token expirado, redirecionando para login.')
                    return redirect('login')
                except jwt.InvalidTokenError:
                    print('Token inválido, redirecionando para login.')
                    return redirect('login')
        
        # Para outras rotas, exige o token se necessário
        if request.path not in public_routes + ['/logout/']:
            token = request.COOKIES.get('auth-token')
            if not token:
                return redirect('login')  # Redireciona para 'login' caso não tenha token
            try:
                jwt.decode(token, settings.SECRET_KEY, algorithms=['HS256'])
            except jwt.ExpiredSignatureError:
                return redirect('login')
            except jwt.InvalidTokenError:
                return redirect('login')
        
        # Chama a próxima middleware ou view
        response = self.get_response(request)
        return response