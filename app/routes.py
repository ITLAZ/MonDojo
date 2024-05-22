from flask import render_template, redirect, url_for, request, flash,session
from werkzeug.security import generate_password_hash, check_password_hash
from functools import wraps
from app import app, db
from .models import Usuario, RegistroActividad
from sqlalchemy.exc import SQLAlchemyError
from flask import redirect, url_for, flash
from flask_dance.contrib.google import google
from .models import Usuario
import datetime
from flask_login import login_user, logout_user, login_required, current_user
from datetime import datetime as dt

#funcion para asignar permiso de acceso a rol
def redirect_based_on_role(user):
    if user.rol_id_rol == 'cliente':
        return redirect(url_for('inicio_usuario'))
    elif user.rol_id_rol == 'admin':
        return redirect(url_for('adminpanel'))
    else:
        flash('Rol no reconocido, acceso denegado.', 'error')
        return redirect(url_for('login'))

#panel user - ruta progetida
@app.route('/inicio_usuario')
@login_required
def inicio_usuario():
    return render_template('inicio_usuario.html')

#panel admi - ruta protegida
@app.route('/adminpanel')
@login_required
def adminpanel():
    return render_template('adminpanel.html')

# Ruta principal que muestra la página de inicio
@app.route('/')
# @login_required protege la ruta
def index():
    return render_template('inicio.html')

# Ruta de registro de usuarios con manejo de errores en la creacicn y validacion
@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        nombre = request.form['name']
        correo = request.form['email']
        telefono = request.form['phone']
        password = request.form['password']
        pregunta_seguridad = request.form['pregunta']
        respuesta_seguridad = request.form['respuesta']

        hashed_password = generate_password_hash(password)
        try:
            telefono = int(telefono)
        except ValueError:
            flash('El teléfono debe ser un número válido.', 'error')
            return redirect(url_for('register'))

        new_user = Usuario(nombre=nombre, correo=correo, telefono=telefono,
                           password=hashed_password, pregunta_seguridad=pregunta_seguridad,
                           respuesta_seguridad=generate_password_hash(respuesta_seguridad),
                           rol_id_rol='cliente')        
        try:
            db.session.add(new_user)
            db.session.commit()
            flash('Registro exitoso. Bienvenido!', 'success')
            return redirect(url_for('login'))
        except SQLAlchemyError as e:
            db.session.rollback()
            app.logger.error(f'Error de base de datos: {str(e)}')
            flash('Un error de base de datos ha ocurrido.', 'error')
            return render_template('error.html'), 500
        except Exception as e:
            db.session.rollback()
            print(f'Error al registrar el usuario: {str(e)}')  
            flash(f'Error al registrar el usuario: {str(e)}', 'error')

    return render_template('register.html')



def registro_actividad(user_id):
    actividad = RegistroActividad(usuario_id=user_id, fecha_hora=dt.utcnow())
    db.session.add(actividad)
    db.session.commit()


# Ruta de inicio de sesion que limita los intentos fallidos 
#y gestiona las excepciones
@app.route('/login', methods=['GET', 'POST'])
def login():
    if 'login_attempts' not in session:
        session['login_attempts'] = 0

    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']
        user = Usuario.query.filter_by(correo=email).first()

        if user and check_password_hash(user.password, password):
            session.pop('login_attempts', None)  
            session['user_id'] = user.id_usuario
            session.permanent = True
            return redirect(url_for('verify_security_question'))
        else:
            session['login_attempts'] += 1
            if session['login_attempts'] >= 3:
                session.pop('login_attempts', None) 
                return redirect(url_for('reset_password'))  
            flash('Correo electrónico o contraseña incorrectos.', 'error')

    return render_template('login.html', login_attempts=session.get('login_attempts', 0))

# Ruta para peticion de restablecer el password verificando primero la pregunta de seguridad
@app.route('/reset_password', methods=['GET', 'POST'])
def reset_password():
    if request.method == 'POST':
        email = request.form['email']
        user = Usuario.query.filter_by(correo=email).first()
        if user:
            session['reset_email'] = email  
            return redirect(url_for('reset_security_question'))
        else:
            flash('No existe una cuenta asociada a este correo.', 'error')
    return render_template('reset_password.html')


#verificacion de dos pasos 
# Ruta que verifica la pregunta de seguridad del usuario para permitir el inicio de sesión
@app.route('/verify_security_question', methods=['GET', 'POST'])
def verify_security_question():
    user_id = session.get('user_id')
    if not user_id:
        return redirect(url_for('login'))

    user = Usuario.query.get(user_id)
    if request.method == 'POST':
        respuesta = request.form['respuesta']
        if check_password_hash(user.respuesta_seguridad, respuesta):
            login_user(user, remember=True)  
            registro_actividad(user.id_usuario)
            flash('Inicio de sesión exitoso.', 'success')
            return redirect_based_on_role(user)
        else:
            flash('Respuesta incorrecta.', 'error')
            return redirect(url_for('verify_security_question'))

    return render_template('verify_security_question.html', pregunta=user.pregunta_seguridad)


#Registro con Google OAuth con manejo de errores
@app.route('/register_google')
def register_google():
    if not google.authorized:
        return redirect(url_for('google.login'))

    resp = google.get("/oauth2/v2/userinfo")
    if resp.ok:
        userinfo = resp.json()
        correo = userinfo['email']
        nombre = userinfo.get('name', '')
        telefono = userinfo.get('phone', None)  

        user = Usuario.query.filter_by(correo=correo).first()
        if not user:
            user = Usuario(
                nombre=nombre, 
                correo=correo, 
                telefono=telefono, 
                password='', 
                pregunta_seguridad='',  
                respuesta_seguridad='',  
                rol_id_rol='cliente'
            )
            db.session.add(user)
            try:
                db.session.commit()
                login_user(user) 
                flash('Registro exitoso con Google. Bienvenido!', 'success')
                return redirect(url_for('inicio_usuario'))
            except Exception as e:
                db.session.rollback()
                flash('Error al guardar en la base de datos.', 'error')
                print(e)
                return redirect(url_for('register'))
        else:
            login_user(user)  
            return redirect(url_for('login'))

    flash('No se pudo acceder a la información de Google.', 'error')
    return redirect(url_for('register'))


from datetime import datetime as dt

#inicio de sesion con google
@app.route('/login_google')
def login_google():
    if not google.authorized:
        return redirect(url_for('google.login'))
    resp = google.get("/oauth2/v2/userinfo")
    if resp.ok:
        userinfo = resp.json()
        correo = userinfo['email']
        nombre = userinfo.get('name', '')
        user = Usuario.query.filter_by(correo=correo).first()
        if user:
            login_user(user)
            actividad = RegistroActividad(usuario_id=user.id_usuario, fecha_hora=dt.utcnow())
            db.session.add(actividad)
            db.session.commit()
            flash('Inicio de sesión exitoso con Google.', 'success')
            return redirect(url_for('inicio_usuario'))
        else:
            # Aquí podrías manejar el caso en que el usuario no esté registrado aún
            flash('No existe una cuenta asociada a este correo de Google.', 'error')
            return redirect(url_for('register'))
    flash('No se pudo acceder a la información de Google.', 'error')
    return redirect(url_for('login'))


# Ruta para restablecer la contrasena, verificando con pregunta de seguridad
@app.route('/reset_security_question', methods=['GET', 'POST'])
def reset_security_question():
    email = session.get('reset_email')
    if not email:
        flash('No se ha proporcionado ningún correo electrónico.', 'error')
        return redirect(url_for('reset_password'))

    user = Usuario.query.filter_by(correo=email).first()
    if not user:
        flash('No se encontró ningún usuario con ese correo.', 'error')
        return redirect(url_for('reset_password'))

    if request.method == 'POST':
        respuesta = request.form['respuesta']
        if check_password_hash(user.respuesta_seguridad, respuesta):
            return redirect(url_for('new_password'))
        else:
            flash('Respuesta incorrecta a la pregunta de seguridad.', 'error')
    
    return render_template('reset_security_question.html', pregunta=user.pregunta_seguridad)

# Ruta para definir el nuevo password despues de la verificacion de seguridad
@app.route('/new_password', methods=['GET', 'POST'])
def new_password():
    if request.method == 'POST':
        new_password = request.form['new-password']
        confirm_password = request.form['confirm-password']

        if new_password != confirm_password:
            flash('Las contraseñas no coinciden.', 'error')
            return render_template('new_password.html')

        user_email = session.get('reset_email')
        if not user_email:
            flash('No hay una sesión de restablecimiento activa.', 'error')
            return redirect(url_for('reset_password'))

        user = Usuario.query.filter_by(correo=user_email).first()
        if user:
            user.password = generate_password_hash(new_password)
            db.session.commit()
            registro_actividad(user.id_usuario)

            flash('Tu contraseña ha sido actualizada.', 'success')
            return redirect_based_on_role(user)
        
        else:
            flash('Usuario no encontrado.', 'error')

    return render_template('new_password.html')


# proteger rutas - utilizado para proteger rutas que requieren login y autenticacion del usuario
def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            flash('Tu sesión ha expirado, por favor inicia sesión de nuevo.', 'info')
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function

# ver tabla usuarios 
@app.route('/userspanel', methods=['GET'])
@login_required
def list_users():
    # Filtrar usuarios por el atributo rol_id_rol con valor "usuario"
    users = Usuario.query.filter_by(rol_id_rol='cliente').with_entities(Usuario.id_usuario, Usuario.nombre, Usuario.correo, Usuario.telefono).all()
    return render_template('userspanel.html', users=users)




from flask import redirect, url_for, flash
from functools import wraps
from flask_login import current_user

