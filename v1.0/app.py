import traceback
from flask import Flask, redirect, url_for, render_template, request, session, flash, send_file, jsonify
from datetime import timedelta
from flask_sqlalchemy import SQLAlchemy
import os
from sqlalchemy.exc import IntegrityError
from datetime import datetime
import fitz
import bcrypt
import json
from io import BytesIO
import requests
from sqlalchemy.exc import SQLAlchemyError

app = Flask(__name__)
basedir = os.path.abspath(os.path.dirname(__file__))
app.secret_key = "hello"
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///'+ os.path.join(basedir,'db1.sqlite')
#app.config['SQLALCHEMY_DATABASE_URI'] = 'mysql+pymysql://ta23te69hsyhqxm7:uv97ys4i15p5dwcf@tviw6wn55xwxejwj.cbetxkdyhwsb.us-east-1.rds.amazonaws.com:3306/w7xdru9bfegzw76e'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.permanent_session_lifetime = timedelta(minutes=35)
app.config['UPLOAD_FOLDER'] = '/uploads'

db = SQLAlchemy(app)

# Modelo Users
class users(db.Model):
    __bind_key__ = None  # Usar o banco SQLite (padrão)
    _id = db.Column("id", db.Integer, primary_key=True)
    name = db.Column(db.String(100))
    telefone = db.Column(db.String(100))
    email = db.Column(db.String(100))
    senha = db.Column(db.String(100))  # Armazena o hash da senha
    data = db.Column(db.String(10))
    hora = db.Column(db.String(8))
    situacao = db.Column(db.String(8))
    nivel_acesso = db.Column(db.String(100))
    genero = db.Column(db.String(100))
    cpf = db.Column(db.String(100))
    data_nascimento = db.Column(db.String(100))
    matricula = db.Column(db.String(100))
    usuario = db.Column(db.String(100))
    lotacao = db.Column(db.String(100))
    cargo = db.Column(db.String(100))
    local_trabalho = db.Column(db.String(100))
    logradouro = db.Column(db.String(100))
    numero = db.Column(db.String(100))
    bairro = db.Column(db.String(100))
    cidade = db.Column(db.String(100))
    estado = db.Column(db.String(100))
    cep = db.Column(db.String(100))

    def __init__(self, name, telefone, email, senha, data, hora, genero, cpf, data_nascimento, matricula, usuario, lotacao, cargo, local_trabalho, situacao, nivel_acesso, logradouro, numero, bairro, cidade, estado, cep):
        self.name = name
        self.telefone = telefone
        self.email = email
        self.senha = self.generate_password_hash(senha)  # Gera e armazena o hash da senhagenerate_password_hash(senha)  # Gera e armazena o hash da senha
        self.data = data
        self.hora = hora
        self.situacao = situacao
        self.nivel_acesso = nivel_acesso
        self.genero = genero
        self.cpf = cpf
        self.data_nascimento = data_nascimento
        self.matricula = matricula
        self.usuario = usuario
        self.lotacao = lotacao
        self.cargo = cargo
        self.local_trabalho = local_trabalho
        self.logradouro = logradouro
        self.numero = numero
        self.bairro = bairro
        self.cidade = cidade
        self.estado = estado
        self.cep = cep

    def generate_password_hash(self, senha):
        return bcrypt.hashpw(senha.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')

    def check_senha(self, senha):
        return bcrypt.checkpw(senha.encode('utf-8'), self.senha.encode('utf-8'))

class LoginHistory(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    login_date = db.Column(db.String(10))  # Data do login
    login_time = db.Column(db.String(8))   # Hora do login

    user = db.relationship('users', backref=db.backref('logins', lazy=True))

# Definindo o modelo de dados
class Alert(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    message = db.Column(db.String(100))
    escola = db.Column(db.String(100))  # Adicionando escola
    solicitante = db.Column(db.String(100))  # Adicionando solicitante
    is_seen = db.Column(db.Boolean, default=False)  # Flag para saber se o alerta foi exibido
    data_hora = db.Column(db.DateTime, default=datetime.utcnow)  # Campo para data e hora do alerta

@app.route('/send_alert', methods=['POST'])
def send_alert():
    try:
        # Pega os dados da requisição
        data = request.json
        message = data.get("message")
        escola = data.get("escola")  # Campo escola
        solicitante = data.get("solicitante")  # Campo solicitante
        timestamp = data.get("timestamp")  # Campo timestamp (já enviado do lado do Android)

        # Verifica se todos os campos obrigatórios foram enviados
        if not all([message, escola, solicitante, timestamp]):
            return jsonify({"error": "Todos os campos são obrigatórios!"}), 400

        # Converte o timestamp para o formato datetime
        try:
            data_hora = datetime.strptime(timestamp, "%Y-%m-%d %H:%M:%S")
        except ValueError:
            return jsonify({"error": "Formato de data inválido!"}), 400

        # Cria um novo alerta no banco de dados com os dados fornecidos
        new_alert = Alert(
            message=message,
            escola=escola,
            solicitante=solicitante,
            data_hora=data_hora
        )
        db.session.add(new_alert)
        db.session.commit()

        return jsonify({"success": True, "message": "Alerta enviado com sucesso!"}), 200

    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route('/get_alerts', methods=['GET'])
def get_alerts():
    try:
        print("Iniciando requisição GET /get_alerts")
        
        # Log para verificar o tipo de dado de 'is_seen'
        first_alert = Alert.query.first()  # Pega o primeiro alerta para inspecionar o tipo de dado
        if first_alert:
            print(f"Tipo de dado de 'is_seen' do primeiro alerta: {type(first_alert.is_seen)}")
            print(f"Valor de 'is_seen' do primeiro alerta: {first_alert.is_seen}")

        alerts = Alert.query.filter_by(is_seen=False).all()  # Alterado para buscar False
        
        if not alerts:
            print("Nenhum alerta encontrado com 'is_seen=False'.")
        
        alerts_list = [
            {
                'id': alert.id,
                'message': alert.message,
                'escola': alert.escola,
                'solicitante': alert.solicitante,
                'data_hora': alert.data_hora.strftime("%Y-%m-%d %H:%M:%S") if alert.data_hora else None
            }
            for alert in alerts
        ]
        
        print(f"Alertas encontrados: {len(alerts)}")
        
        return jsonify(alerts_list)
    
    except Exception as e:
        import traceback
        print("Erro ao processar requisição:", str(e))
        print("Traceback:", traceback.format_exc())
        
        return jsonify({"error": str(e)}), 500

# Rota para marcar o alerta como visto
@app.route('/api/alerta/marcar_visto', methods=['POST'])
def marcar_visto():
    try:
        data = request.json  # Obtém os dados enviados pelo frontend
        print(f"Dados recebidos: {data}")  # Verifique o que está sendo recebido
        alerta_id = data.get('alerta_id')  # Recebe o alerta_id (id do alerta)

        if not alerta_id:
            return jsonify({'error': 'alerta_id é obrigatório'}), 400  # Caso o alerta_id não seja enviado

        alerta = Alert.query.get(alerta_id)  # Busca o alerta no banco pelo id

        if alerta:
            if alerta.is_seen:  # Verifica se já está marcado como "visto"
                print(f"Alerta {alerta_id} já foi marcado como visto")
                return jsonify({'success': True, 'message': 'Alerta já está marcado como visto'}), 200

            alerta.is_seen = True  # Marca o alerta como visto (True)
            db.session.commit()  # Salva a mudança no banco
            print(f"Alerta {alerta_id} marcado como visto")
            return jsonify({'success': True})  # Retorna sucesso
        else:
            return jsonify({'error': 'Alerta não encontrado'}), 404  # Caso o alerta não seja encontrado

    except SQLAlchemyError as e:
        db.session.rollback()  # Faz rollback caso haja erro no banco de dados
        return jsonify({'error': 'Erro ao acessar o banco de dados: ' + str(e)}), 500

    except Exception as e:
        return jsonify({'error': 'Erro ao processar a requisição: ' + str(e)}), 500  # Tratamento de erros

# Função para criar o usuário Admin
def create_admin_user():
    # Verifica se o usuário admin já existe
    admin_user = users.query.filter_by(usuario="admin").first()
    if admin_user:
        print("Usuário admin já existe!")
    else:
        # Cria o novo usuário admin
        admin = users(
            name="Administrador",
            telefone="000000000",
            email="admin@ubatuba.sp.gov.br",
            senha="admin",  # A senha que será criptografada
            data="03/10/2024",
            hora="23:55:09",
            genero="Masculino",
            cpf="00000000000",
            data_nascimento="1990-01-01",
            matricula="000000",
            usuario="admin",
            lotacao="Administração",
            cargo="Administrador",
            local_trabalho="Administração",
            situacao="Ativo",
            nivel_acesso="Administrador",
            logradouro="Rua Maria Alves",
            numero="865",
            bairro="Centro",
            cidade="Ubatuba",
            estado="SP",
            cep="00000-000"
        )

        # Adiciona o usuário admin ao banco
        db.session.add(admin)
        db.session.commit()
        print("Usuário admin criado com sucesso!")

@app.route("/user/painel")
def painel():
    if "user_id" in session:   
        # Consultar o total de escolas, alunos e usuários e etc.
        total_usuarios = users.query.count()

        # Últimos 5 alertas
        ultimos_alertas = Alert.query.order_by(Alert.id.desc()).limit(5).all()
        ultimos_alertas_list = [
            {"titulo": f"Alerta {alert.id}", "escola": alert.escola, "solicitante": alert.solicitante, "descricao": alert.message, "data_hora": alert.data_hora} 
            for alert in ultimos_alertas
        ]
        # Lista de escolas que mais solicitam alertas
        escolas_mais_solicitadas = [
            {"nome": "Escola Municipal CEI Sumaré", "quantidade_alertas": 10},
            {"nome": "Escola Municipal Presidente Tancredo Neves", "quantidade_alertas": 8},
            {"nome": "Escola Municipal Bellarmino", "quantidade_alertas": 6}
        ]
        return render_template("painel.html", total_usuarios=total_usuarios,ultimos_alertas=ultimos_alertas_list,
                            escolas_mais_solicitadas=escolas_mais_solicitadas ,current_page='painel')
    else:
        flash("Você não está logado!")
        return redirect(url_for("login"))
    
@app.route('/api/ultimos_alertas', methods=['GET'])
def ultimos_alertas():
    # Buscando os últimos 5 alertas no banco de dados
    ultimos_alertas = Alert.query.order_by(Alert.id.desc()).limit(5).all()
    # Criando a lista de alertas no formato JSON
    ultimos_alertas_list = [
        {
            "titulo": f"Alerta {alert.id}",
            "escola": alert.escola,
            "solicitante": alert.solicitante,
            "descricao": alert.message,
            "data_hora": alert.data_hora.strftime("%d/%m/%Y às %H:%M")
        }
        for alert in ultimos_alertas
    ]
    # Retornando os alertas em formato JSON
    return jsonify(ultimos_alertas_list)

# Endpoint para obter as escolas que mais solicitaram alertas
@app.route('/api/escolas_mais_solicitantes', methods=['GET'])
def escolas_mais_solicitantes():
    escolas = db.session.query(
        Alert.escola,
        db.func.count(Alert.id).label('quantidade_alertas')
    ).group_by(Alert.escola).having(db.func.count(Alert.id) > 1).all()
    
    escolas_json = [
        {
            'nome': escola[0],
            'quantidade_alertas': escola[1]
        }
        for escola in escolas
    ]
    
    return jsonify(escolas_json)

@app.route("/user/pag1")
def pag1():
    if "user_id" in session:
        return render_template("pag1.html", current_page='pag1')
    else:
        flash("Você não está logado!")
        return redirect(url_for("login"))

@app.route("/user/pag2")
def pag2():
    if "user_id" in session:
        return render_template("pag2.html", current_page='pag2')
    else:
        flash("Você não está logado!")
        return redirect(url_for("login"))

@app.route("/user/pag3")
def pag3():
    if "user_id" in session:
        return render_template("pag3.html", current_page='pag3')
    else:
        flash("Você não está logado!")
        return redirect(url_for("login"))

@app.route("/user/pag4")
def pag4():
    if "user_id" in session:
        return render_template("pag4.html", current_page='pag4')
    else:
        flash("Você não está logado!")
        return redirect(url_for("login"))

@app.route("/user/usuarios")
def usuarios():
     # Consulta todas os usuários
    #usuarios = users.query.all()
    return render_template("usuarios.html", usuarios=usuarios, current_page='usuarios')

##API USUARIOS
@app.route('/api/usuarios', methods=['GET'])
def get_usuarios():
    # Consulta todos os usuários
    usuarios = users.query.all()

    # Converte os usuários para um formato JSON
    usuarios_json = [{
        'nome': usuario.name,
        'matricula': usuario.matricula,
        'nivel': usuario.nivel_acesso,
        'cadastro': usuario.data,
        'trabalho': usuario.local_trabalho,
        'status': usuario.situacao,
        'id': usuario._id
    } for usuario in usuarios]

    return jsonify(usuarios_json)

@app.route('/api/alertas', methods=['GET'])
def get_alertas():
    try:
        # Consulta todos os alertas do banco de dados
        alertas = Alert.query.all()

        # Converte os alertas para um formato JSON
        alertas_json = [{
            'id': alerta.id,
            'message': alerta.message,
            'escola': alerta.escola,
            'solicitante': alerta.solicitante,
            'data_hora': alerta.data_hora.strftime("%Y-%m-%d %H:%M:%S") if alerta.data_hora else None,  # Formatação de data
            'is_seen': alerta.is_seen
        } for alerta in alertas]
        # Retorna os alertas em formato JSON
        return jsonify(alertas_json)
    
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route("/check_user_logged_in", methods=["GET"])
def check_user_logged_in():
    if "user_id" in session:
        return {"logged_in": True}
    else:
        return {"logged_in": False}

@app.route("/user/documentos")
def documentos():
    return render_template("documentos.html", current_page='documentos' )

@app.route("/cadastro", methods=["POST", "GET"])
def cadastro():
    if "user_id" in session:
        if request.method == "POST":
            # Seu código de processamento do formulário
            nome = request.form["cd_user_nome"]
            telefone = request.form["cd_user_telefone"]
            genero = request.form["cd_user_genero"]
            cpf = request.form["cd_user_cpf"]
            email = request.form["cd_user_email"]
            data_nasc = request.form["cd_user_nascimento"]
            matricula = request.form["cd_user_matricula"]
            usuario = request.form["cd_user_usuario"]
            trabalho = request.form["cd_user_trabalho"]
            cargo = request.form["cd_user_cargo"]
            nivel_acesso = request.form["cd_user_nivel_acesso"]
            senha = request.form["cd_user_senha"]
            rua = request.form["cd_user_rua"]
            numero = request.form["cd_user_numero"]
            bairro = request.form["cd_user_bairro"]
            cidade = request.form["cd_user_municipio"]
            estado = request.form["cd_user_estado"]
            cep = request.form["cd_user_cep"]

            # Verifica se o email já está em uso
            existing_user = users.query.filter_by(email=email).first()

            if existing_user:
                flash("Email já está em uso. Por favor, escolha outro.")
            else:
                try:
                    # Obtém a data e hora atuais
                    data_atual = datetime.now().strftime('%d/%m/%Y')
                    hora_atual = datetime.now().strftime('%H:%M:%S')

                    # Crie um novo usuário com os dados fornecidos
                    usr = users(name=nome, telefone=telefone, email=email, senha=senha, data=data_atual, hora=hora_atual, genero=genero, cpf=cpf, data_nascimento=data_nasc, matricula=matricula, usuario=usuario, lotacao="Secretaria Municipal de Educação", local_trabalho=trabalho, situacao="Ativo", nivel_acesso=nivel_acesso, cargo=cargo, logradouro=rua, numero=numero, bairro=bairro, cidade=cidade, estado=estado, cep=cep)
                    db.session.add(usr)
                    db.session.commit()
                    flash("Cadastrado com Sucesso!", "success")
                    return redirect(url_for("usuarios"))
                except IntegrityError:
                    # Captura a exceção caso haja um problema de integridade (por exemplo, violação de chave única)
                    db.session.rollback()
                    flash("Erro ao cadastrar. Por favor, tente novamente.")
            # Redireciona para a página de cadastro após a tentativa de cadastro
            return redirect(url_for("cadastro"))
        else:
            # Se o método da requisição não for POST, apenas renderize o template de cadastro
            return render_template("cadastro.html")
    else:
        flash("Você não está conectado.")
        return redirect(url_for("login"))
    
@app.route("/", methods=["POST", "GET"])
def login():
    if "user_id" in session:
        flash("Você já está logado!")
        return redirect(url_for("painel"))
    else:
        if request.method == "POST":
            user = request.form["nm"]
            password = request.form["senha"]
            found_user = users.query.filter_by(usuario=user).first()

            if found_user:
                # Verifica se a senha fornecida é igual à senha armazenada
                if bcrypt.checkpw(password.encode('utf-8'), found_user.senha.encode('utf-8')):
                    # Armazena o ID do usuário na sessão
                    session["user_id"] = found_user._id
                    
                    # Captura a data e hora atuais para o histórico de login
                    now = datetime.now()
                    login_entry = LoginHistory(
                        user_id=found_user._id,
                        login_date=now.strftime("%Y-%m-%d"),
                        login_time=now.strftime("%H:%M:%S")
                    )
                    
                    # Salva o login no histórico
                    db.session.add(login_entry)
                    db.session.commit()
                    
                    return redirect(url_for("painel"))
                else:
                    flash("Usuário ou senha incorretos. Por favor, verifique suas credenciais.")
                    return redirect(url_for("login"))
            else:
                flash("Usuário não encontrado. Por favor, entre em contato com a TI.")
                return redirect(url_for("login"))
        else:
            return render_template("login.html")
      
@app.route("/user/perfil", methods=["GET"])
def user():
    if "user_id" in session:
        user_id = session["user_id"]

        # Recupera os dados do usuário do banco de dados
        found_user = users.query.get(user_id)

        if found_user:
            # Adiciona os dados do usuário ao contexto do template
            return render_template("user.html", user=found_user)
        else:
            flash("Usuário não encontrado!")
            return redirect(url_for("login"))
    else:
        flash("Você não está logado!")
        return redirect(url_for("login"))
      
@app.route("/user/editar", methods=["POST", "GET"])
def editar():
    if "user_id" in session:
        user_id = session["user_id"]

        # Busca o usuário pelo ID
        found_user = users.query.get(user_id)

        if request.method == "POST":
            # Atualiza os dados com base no formulário
            found_user.email = request.form["email"]
            found_user.telefone = request.form["telefone"]
            found_user.genero = request.form["genero"]
            found_user.data_nascimento = request.form["edit_user_nascimento"]
            found_user.logradouro = request.form["edit_user_rua"]
            found_user.numero = request.form["edit_user_numero"]
            found_user.bairro = request.form["edit_user_bairro"]
            found_user.cidade = request.form["edit_user_cidade"]
            found_user.estado = request.form["edit_user_estado"]
            found_user.cep = request.form["edit_user_cep"]

            # Se a senha foi fornecida no formulário, atualiza o hash da senha
            senha = request.form["senha"]
            if senha:
                # Gera o hash da senha usando bcrypt
                found_user.senha = bcrypt.hashpw(senha.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')
                # Verifica o hash gerado (opcional)
                senha_valida = bcrypt.checkpw(senha.encode('utf-8'), found_user.senha.encode('utf-8'))
                print(f"Senha válida? {senha_valida}")

            # Salva as alterações no banco de dados
            db.session.commit()

            # Atualiza os valores na sessão, se necessário
            session["email"] = found_user.email
            session["telefone"] = found_user.telefone
            session["genero"] = found_user.genero
            session["data_nascimento"] = found_user.data_nascimento
            session["logradouro"] = found_user.logradouro
            session["numero"] = found_user.numero
            session["bairro"] = found_user.bairro
            session["cidade"] = found_user.cidade
            session["estado"] = found_user.estado
            session["cep"] = found_user.cep

            flash("Informações do usuário foram salvas com sucesso!")
            
            # Redireciona para a página do usuário após a edição
            return redirect(url_for("user"))

        # Se for uma requisição GET, preenche o formulário com os dados do usuário
        return render_template("editarconta.html", user=found_user)
    else:
        flash("Você não está logado!")
        return redirect(url_for("login"))
    
@app.route("/user/usuarios/usuario/<int:usuario_id>", methods=["GET"])
def mostrar_usuario(usuario_id):
    if "user_id" in session:
        # Obtém o ID do usuário logado
        user_id_logado = session["user_id"]

        if user_id_logado == usuario_id:
                    # Redireciona para o próprio perfil, se não for o mesmo usuário
                    flash("Você só pode acessar o seu próprio perfil!")
                    return redirect(url_for("user"))

        # Busca o aluno pelo ID
        usuario= users.query.get(usuario_id)
        
        if not usuario:
            flash("Usuario não encontrado!")
            return redirect(url_for("user"))
        
        # Busca o último acesso do usuário na tabela LoginHistory
        ultimo_acesso = LoginHistory.query.filter_by(user_id=usuario_id).order_by(LoginHistory.login_date.desc(), LoginHistory.login_time.desc()).first()
        
        # Renderiza o template com os dados do aluno
        return render_template("mostrar_usuario.html", usuario=usuario, ultimo_acesso=ultimo_acesso)
    else:
        flash("Você não está logado!")
        return redirect(url_for("login"))
    
@app.route("/user/usuarios/usuario/editar/<int:usuario_id>", methods=["POST", "GET"])
def editar_usuario(usuario_id):
    if "user_id" in session:
        # Busca o usuário pelo ID
        usuario = users.query.get(usuario_id)
        
        if not usuario:
            flash("Usuário não encontrado!")
            return redirect(url_for("user"))
        
        if request.method == "POST":
            # Atualiza os dados do usuário com base no formulário
            usuario.name = request.form["nome"]
            usuario.telefone = request.form["telefone"]
            usuario.genero = request.form["genero"]
            usuario.cpf = request.form["cpf"]
            usuario.email = request.form["email"]
            usuario.data_nascimento = request.form["data_nascimento"]
            usuario.matricula = request.form["matricula"]
            usuario.usuario = request.form["usuario"]
            usuario.lotacao = request.form["lotacao"]
            usuario.cargo = request.form["cargo"]
            usuario.local_trabalho = request.form["local_trabalho"]
            usuario.logradouro = request.form["logradouro"]
            usuario.numero = request.form["numero"]
            usuario.bairro = request.form["bairro"]
            usuario.cidade = request.form["cidade"]
            usuario.estado = request.form["estado"]
            usuario.cep = request.form["cep"]
            usuario.situacao = request.form["situacao"]
            usuario.nivel_acesso = request.form["nivel_acesso"]

            # Se a senha foi fornecida no formulário, atualiza o hash da senha
            senha = request.form.get("senha")
            if senha:
                # Gera o hash da senha usando bcrypt
                usuario.senha = bcrypt.hashpw(senha.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')

            # Salva as alterações no banco de dados
            db.session.commit()

            # Atualiza os valores na sessão, se necessário
            session["email"] = usuario.email
            session["telefone"] = usuario.telefone
            session["genero"] = usuario.genero
            session["data_nascimento"] = usuario.data_nascimento
            session["logradouro"] = usuario.logradouro
            session["numero"] = usuario.numero
            session["bairro"] = usuario.bairro
            session["cidade"] = usuario.cidade
            session["estado"] = usuario.estado
            session["cep"] = usuario.cep

            flash("Informações do usuário foram salvas com sucesso!")
            
            # Redireciona para a página do usuário
            return redirect(url_for("mostrar_usuario", usuario_id=usuario_id))

        # Se for uma requisição GET, preenche o formulário com os dados do usuário
        return render_template("editar_usuario.html", usuario=usuario)
    else:
        flash("Você não está logado!")
        return redirect(url_for("login"))
    
    
@app.route("/user/logout")
def logout():
    flash("Voce saiu do sistema!")
    session.pop("user_id", None)
    return redirect(url_for("login"))

from io import BytesIO

@app.route("/documentos/comprovante_escolar", methods=["GET"])
def gerar_pdf_comprovante_escolar():
    if "user_id" in session:
       
        # Renderiza o template HTML com os dados do aluno e a data atual
        html_content = render_template("model_comprovante_escolar.html")

        # Cria um buffer de memória
        pdf_buffer = BytesIO()

        # Cria um novo documento PDF
        doc = fitz.open()

        # Adiciona uma nova página
        page = doc.new_page()
        rect = page.rect + (36, 36, -36, -36)

        # Insere o HTML modificado na página
        page.insert_htmlbox(rect, html_content, archive=fitz.Archive("."))
        # Define os metadados do documento (incluindo o título)
        metadata = {
            "title": "Comprovante Escolar"
        }
        doc.set_metadata(metadata)

        # Salva o PDF diretamente no buffer de memória
        doc.save(pdf_buffer)

        # Move o cursor para o início do buffer
        pdf_buffer.seek(0)

        # Retorna o arquivo PDF gerado sem salvá-lo no disco
        return send_file(pdf_buffer, mimetype='application/pdf', as_attachment=False)
    else:
        return redirect(url_for("login"))

@app.route("/documentos/conclusao_escolar", methods=["GET"])
def gerar_pdf_conclusao_escolar():
    if "user_id" in session:
        # Renderiza o template HTML com os dados do usuário
        html_content = render_template("model_declaracao_conclusao.html")

        # Cria um buffer de memória
        pdf_buffer = BytesIO()

        # Cria um novo documento PDF
        doc = fitz.open()

        # Adiciona uma nova página
        page = doc.new_page()
        rect = page.rect + (36, 36, -36, -36)

        # Insere o HTML modificado na página
        page.insert_htmlbox(rect, html_content, archive=fitz.Archive("."))
        # Define os metadados do documento (incluindo o título)
        metadata = {
            "title": "Conclusão de Vaga"
        }
        doc.set_metadata(metadata)

        # Salva o PDF diretamente no buffer de memória
        doc.save(pdf_buffer)

        # Move o cursor para o início do buffer
        pdf_buffer.seek(0)

        # Retorna o arquivo PDF gerado sem salvá-lo no disco
        return send_file(pdf_buffer, mimetype='application/pdf', as_attachment=False)
    else:
        return redirect(url_for("login"))
    
@app.route("/documentos/solicitacao_vaga", methods=["GET"])
def gerar_pdf_solicitacao_vaga():
    if "user_id" in session:
        # Renderiza o template HTML com os dados do usuário
        html_content = render_template("model_solicitacao_vaga.html")

        # Cria um buffer de memória
        pdf_buffer = BytesIO()

        # Cria um novo documento PDF
        doc = fitz.open()

        # Adiciona uma nova página
        page = doc.new_page()
        rect = page.rect + (36, 36, -36, -36)

        # Insere o HTML modificado na página
        page.insert_htmlbox(rect, html_content, archive=fitz.Archive("."))
        # Define os metadados do documento (incluindo o título)
        metadata = {
            "title": "Solicitação de Vaga"
        }
        doc.set_metadata(metadata)

        # Salva o PDF diretamente no buffer de memória
        doc.save(pdf_buffer)

        # Move o cursor para o início do buffer
        pdf_buffer.seek(0)

        # Retorna o arquivo PDF gerado sem salvá-lo no disco
        return send_file(pdf_buffer, mimetype='application/pdf', as_attachment=False)
    else:
        return redirect(url_for("login"))

@app.route("/documentos/declaracao_transferencia", methods=["GET"])
def gerar_pdf_declaracao_transferencia():
    if "user_id" in session:   
        # Renderiza o template HTML com os dados do usuário
        html_content = render_template("model_declaracao_transferencia.html")

        # Cria um buffer de memória
        pdf_buffer = BytesIO()

        # Cria um novo documento PDF
        doc = fitz.open()

        # Adiciona uma nova página
        page = doc.new_page()
        rect = page.rect + (36, 36, -36, -36)

        # Insere o HTML modificado na página
        page.insert_htmlbox(rect, html_content, archive=fitz.Archive("."))
        # Define os metadados do documento (incluindo o título)
        metadata = {
            "title": "Transferência Escolar"
        }
        doc.set_metadata(metadata)

        # Salva o PDF diretamente no buffer de memória
        doc.save(pdf_buffer)

        # Move o cursor para o início do buffer
        pdf_buffer.seek(0)

        # Retorna o arquivo PDF gerado sem salvá-lo no disco
        return send_file(pdf_buffer, mimetype='application/pdf', as_attachment=False)
    else:
        return redirect(url_for("login"))
    
@app.route('/consulta_cep/<cep>', methods=['GET'])
def consulta_cep(cep):
    url = f'https://viacep.com.br/ws/{cep}/json/'
    response = requests.get(url)
    
    # Verifica se o CEP foi encontrado
    if response.status_code == 200:
        dados_cep = response.json()
        # Verifica se o CEP é válido
        if 'erro' not in dados_cep:
            return jsonify(dados_cep)
        else:
            return jsonify({'erro': 'CEP inválido'}), 404
    else:
        return jsonify({'erro': 'Falha na consulta ao CEP'}), 500
    
# Executando o aplicativo com configuração para o Heroku
if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    with app.app_context():
        #db.drop_all()
        db.create_all()  # Cria todas as tabelas do banco de dados
        #create_admin_user()
    app.run(host="0.0.0.0", port=port)

