from django.shortcuts import render, redirect
from django.contrib.auth.models import User  # Usando o User padrão do Django
from django.contrib import messages
from django.contrib.auth.hashers import make_password
import jwt
from datetime import datetime, timedelta
from django.conf import settings
from django.http import JsonResponse
from django.contrib.auth import authenticate, login as auth_login
from reportlab.pdfgen import canvas
from django.contrib import messages
import matplotlib.pyplot as plt
import io
import os
from django.http import HttpResponse, FileResponse
from django.core.files.storage import default_storage
from django.core.files.base import ContentFile
import pdfplumber



def forgotPassword(request):
    if request.method == 'POST':
        email = request.POST['email']
        new_senha = request.POST['new_senha']
        confirm_senha = request.POST['confirm_senha']

        # Aqui a verificação está corrigida para verificar se o email não existe
        if not User.objects.filter(email=email).exists():
            email_error = 'Email não encontrado'
            return render(request, 'auth/forgotPassword.html', {'email_error': email_error})

        if new_senha != confirm_senha:
            senha_error = 'As Senhas não coincidem'
            return render(request, 'auth/forgotPassword.html', {'senha_error': senha_error})

        # Obter o usuário
        user = User.objects.get(email=email)

        # Atualizando a senha do usuário
        user.password = make_password(new_senha)
        user.save()

        return redirect('login')

    return render(request, 'auth/forgotPassword.html')

def register(request):
    if request.method == 'POST':
        name = request.POST['name']
        email = request.POST['email']
        password = request.POST['password']
        password_confirmation = request.POST['password_confirmation']

        # Verifica se as senhas coincidem
        if password != password_confirmation:
            password_error = 'As senhas não coincidem'
            return render(request, 'auth/register.html', {'password_error': password_error})

        # Verifica se o email já existe
        if User.objects.filter(email=email).exists():
            user_error = 'Usuário já está cadastrado'
            return render(request, 'auth/register.html', {'user_error': user_error})

        # Cria o novo usuário
        user = User.objects.create(
            username=email,  # Usamos o email como o campo username
            first_name=name,
            email=email,
            password=make_password(password)  # Criptografa a senha
        )
        messages.success(request, 'Registro realizado com sucesso!')
        return redirect('login')

    return render(request, 'auth/register.html')


def login(request):
    if request.method == 'POST':
        email = request.POST['email']
        password = request.POST['password']

        # Autenticação usando o campo username (que será o email)
        user = authenticate(request, username=email, password=password)

        if user is not None:
            auth_login(request, user)  # Faz login na sessão
            
            # Gera o token JWT
            token = jwt.encode({
                'user_id': user.id,
                'exp': datetime.utcnow() + timedelta(days=7)  # Expira em 7 dias
            }, settings.SECRET_KEY, algorithm='HS256')
            print('user auth', user)
            response = redirect('home')  # Redireciona após login bem-sucedido
            response.set_cookie('auth-token', token, httponly=True)
            return response

        # Se as credenciais forem inválidas
        login_error = 'Credenciais Inválidas'
        return render(request, 'auth/login.html', {'login_error': login_error})

    return render(request, 'auth/login.html')

def logout(request):
    # Redireciona o usuário para a página de login
    response = redirect('login')
    # Remove o cookie 'auth-token' definindo seu valor para vazio e expirando-o
    response.set_cookie('auth-token', '', expires=0)
    return response

def getUser(request):
    try:
        # Obtendo o usuário logado
        user = request.user

        print(user)
        
        # Renderiza o template com os dados do usuário
        return render(request, 'perfil.html', {'user': user})

    except User.DoesNotExist:
        messages.error(request, 'Usuário não encontrado.')
        return render(request, 'perfil.html')

    except Exception as e:
        messages.error(request, 'Ocorreu um erro: ' + str(e))
        return render(request, 'perfil.html')
    

def alterarSenha(request):
    if request.method == 'POST':
        # Obtendo o token dos cookies
        token = request.COOKIES.get('auth-token')
        nova_senha = request.POST['new_password']
        confirmar_senha = request.POST['confirm_password']

        if not token or not nova_senha or not confirmar_senha:
            messages.error(request, 'Token ou senhas não fornecidos.')
            return redirect('getUser')

        if nova_senha != confirmar_senha:
            messages.error(request, 'As senhas não coincidem.')
            return redirect('getUser')

        try:
            # Decodificando o token JWT
            decoded_data = jwt.decode(token, settings.SECRET_KEY, algorithms=['HS256'])
            user_id = decoded_data.get('user_id')

            # Obtendo o usuário pelo ID
            user = User.objects.get(id=user_id)

            # Atualizando a senha do usuário
            user.password = make_password(nova_senha)
            user.save()

            messages.success(request, 'Senha alterada com sucesso!')
            return redirect('getUser')

        except User.DoesNotExist:
            messages.error(request, 'Usuário não encontrado.')
            return redirect('getUser')

        except jwt.ExpiredSignatureError:
            messages.error(request, 'O token de autenticação expirou.')
            return redirect('getUser')

        except jwt.DecodeError:
            messages.error(request, 'Token inválido.')
            return redirect('getUser')

        except Exception as e:
            messages.error(request, f'Ocorreu um erro: {str(e)}')
            return redirect('getUser')
    else:
        return render(request, 'perfil.html')

def criar_relat_pdf(request):
    if request.method == 'POST':
        salario_bruto = request.POST.get('salario_bruto')
        try:
            salario_bruto = float(salario_bruto)
        except ValueError:
            messages.error(request, 'O salário bruto deve ser um número válido.')
            return redirect('home')

        beneficio1 = salario_bruto * 0.70
        beneficio2 = salario_bruto * 0.80

        # Criar gráfico
        fig, ax = plt.subplots()
        ax.bar(['Aposentadoria 1 (70%)', 'Aposentadoria 2 (80%)'], [beneficio1, beneficio2])
        ax.set_ylabel('Valor do Benefício (R$)')
        ax.set_title('Simulação de Benefícios de Aposentadoria')

        img_buf = io.BytesIO()
        plt.savefig(img_buf, format='png')
        img_buf.seek(0)

        # Criar PDF
        response = HttpResponse(content_type='application/pdf')
        response['Content-Disposition'] = 'attachment; filename="relatorio_inss.pdf"'

        p = canvas.Canvas(response)
        p.drawString(100, 750, "Relatório de Benefício INSS")
        p.drawString(100, 730, f"Salário Bruto: R$ {salario_bruto:.2f}")
        p.drawString(100, 710, f"Alternativa 1 (70%): R$ {beneficio1:.2f}")
        p.drawString(100, 690, f"Alternativa 2 (80%): R$ {beneficio2:.2f}")

        p.showPage()
        p.save()
        return response
    else:
        return redirect('home')

def gerar_grafico_pdf(request):
    if request.method == 'POST':
        salario_bruto = request.POST.get('salario_bruto')
        try:
            salario_bruto = float(salario_bruto)
        except ValueError:
            messages.error(request, 'O salário bruto deve ser um número válido.')
            return redirect('home')

        beneficios = [salario_bruto * 0.70, salario_bruto * 0.80]
        alternativas = ['Aposentadoria 1', 'Aposentadoria 2']

        fig, ax = plt.subplots()
        ax.bar(alternativas, beneficios, color=['blue', 'green'])
        ax.set_ylabel('Valor do Benefício (R$)')
        ax.set_title('Comparação das Opções de Aposentadoria')

        response = HttpResponse(content_type='application/pdf')
        response['Content-Disposition'] = 'attachment; filename="grafico_beneficio.pdf"'
        
        buffer = io.BytesIO()
        fig.savefig(buffer, format='pdf')
        buffer.seek(0)
        return HttpResponse(buffer, content_type='application/pdf')
    else:
        return redirect('home')
    
def upload_cnis(request):
    if request.method == 'POST':
        if 'cnis_pdf' not in request.FILES:
            messages.error(request, 'Nenhum arquivo foi enviado.')
            return redirect('home')

        file = request.FILES['cnis_pdf']
        if file.name == '':
            messages.error(request, 'Nenhum arquivo selecionado.')
            return redirect('home')

        if file.name.endswith('.pdf'):
            file_path = default_storage.save(file.name, ContentFile(file.read()))
            if verifica_cnis(file_path):
                messages.success(request, 'CNIS verificado com sucesso!')
            else:
                messages.error(request, 'O arquivo não contém um CNIS válido.')
            return redirect('home')
        else:
            messages.error(request, 'Por favor, faça o upload de um arquivo PDF válido.')
            return redirect('home')

def verifica_cnis(file_path):
    with pdfplumber.open(file_path) as pdf:
        first_page = pdf.pages[0]
        text = first_page.extract_text()
        return "CNIS" in text
    
def calcular_beneficio(request):
    if request.method == 'POST':
        sexo = request.POST.get('sexo')
        salario_bruto = request.POST.get('salario_bruto')

        if not sexo or not salario_bruto:
            messages.error(request, 'Preencha todos os campos corretamente!')
            return redirect('home')

        try:
            salario_bruto = float(salario_bruto)
        except ValueError:
            messages.error(request, 'O salário bruto deve ser um número válido.')
            return redirect('home')

        if salario_bruto <= 1212.00:
            beneficio = salario_bruto * 0.75
        elif salario_bruto <= 2427.35:
            beneficio = salario_bruto * 0.80
        else:
            beneficio = salario_bruto * 0.85

        return render(request, 'resultado.html', {'beneficio': beneficio})
    else:
        return redirect('home')
    
def download_pdf(request):
    pdf_path = os.path.join('path_to_pdf_folder', 'RelatInss.pdf')
    if os.path.exists(pdf_path):
        return FileResponse(open(pdf_path, 'rb'), as_attachment=True)
    else:
        messages.error(request, 'Arquivo PDF não encontrado.')
        return redirect('home')

def download_graph_pdf(request):
    graph_pdf_path = os.path.join('path_to_graph_folder', 'grafico.pdf')
    if os.path.exists(graph_pdf_path):
        return FileResponse(open(graph_pdf_path, 'rb'), as_attachment=True)
    else:
        messages.error(request, 'Arquivo gráfico PDF não encontrado.')
        return redirect('home')

def home(request):
    return render(request, 'home.html') 
