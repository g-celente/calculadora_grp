from django.shortcuts import redirect
import jwt
from django.conf import settings

class TokenRequiredMiddleware:
    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        print(request.path)
        if request.path not in ['/login/', '/register/', '/logout/', '/forgotPassword/']:  # Ajuste as URLs que não requerem token
            token = request.COOKIES.get('auth-token')
            print(token)  # Obtendo o token dos cookies

            if not token:
                print('Token não encontrado, redirecionando para login.')
                return redirect('login')  # Redireciona para a página de login
            
            try:
                jwt.decode(token, settings.SECRET_KEY, algorithms=['HS256'])
                print('deu boa')
            except jwt.ExpiredSignatureError:
                print('Token expirado, redirecionando para login.')
                return redirect('login')  # Token expirado
            except jwt.InvalidTokenError:
                print('Token inválido, redirecionando para login.')
                return redirect('login')  # Token inválido
            
        
        response = self.get_response(request)
        print(response)  # Aqui, chama a próxima middleware/view
        return response  # Retorna a resposta final
