import os
from flask import render_template, redirect, url_for, request, flash,session
from werkzeug.security import generate_password_hash, check_password_hash
from functools import wraps
from app import app, db
from .models import Usuario, RegistroActividad
from sqlalchemy.exc import SQLAlchemyError
from flask import redirect, url_for, flash
from flask_dance.contrib.google import google
from .models import Usuario, CategoriaProducto, Producto
import datetime
from flask_login import login_user, logout_user, login_required, current_user
from flask_login import login_required as flask_login_required
from datetime import datetime as dt
from flask import jsonify  
from werkzeug.utils import secure_filename
from sqlalchemy import or_
#funcion para asignar permiso de acceso a rol
def redirect_based_on_role(user):
    if user.rol_id_rol == 'cliente':
        return redirect(url_for('inicio_usuario'))
    elif user.rol_id_rol == 'admin':
        return redirect(url_for('adminpanel'))
    else:
        flash('Rol no reconocido, acceso denegado.', 'error')
        return redirect(url_for('login'))

#logout con seguridad
@app.route('/logout')
@login_required
def logout():
    logout_user()  
    session.clear()  
    flash('Has cerrado sesión correctamente.', 'info')
    return redirect(url_for('inicio'))  


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
def inicio():
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



# ver tabla usuarios, busqueda y filtrados
@app.route('/userspanel', methods=['GET'])
@login_required
def list_users():
    search_query = request.args.get('search', '').strip()
    sort_by = request.args.get('sort_by', 'nombre')
    sort_order = request.args.get('sort_order', 'asc')

    query = Usuario.query.filter(Usuario.rol_id_rol == 'cliente')

    if search_query:
        query = query.filter(Usuario.nombre.ilike(f"{search_query}%"))
    
    if sort_by and sort_order:
        if sort_order == 'asc':
            query = query.order_by(getattr(Usuario, sort_by).asc())
        else:
            query = query.order_by(getattr(Usuario, sort_by).desc())
    
    users = query.with_entities(Usuario.id_usuario, Usuario.nombre, Usuario.correo, Usuario.telefono).all()

    return render_template('userspanel.html', users=users)


# Actualizar la información de un usuario - vista ADMIN
@app.route('/update_user/<int:user_id>', methods=['POST'])
@login_required
def update_user(user_id):
    user = Usuario.query.get_or_404(user_id)  

    new_name = request.form.get('name')
    new_email = request.form.get('email')
    new_phone = request.form.get('phone')
    
    print("Datos recibidos:", new_name, new_email, new_phone)  # Depurar

    if not new_name or not new_email:
        flash('Nombre y correo son campos obligatorios.', 'error')
        return redirect(url_for('edit_user', user_id=user_id))
    
    if new_phone and not new_phone.isdigit():
        flash('El teléfono debe ser numérico.', 'error')
        return redirect(url_for('edit_user', user_id=user_id))
    
    user.nombre = new_name
    user.correo = new_email
    user.telefono = int(new_phone) if new_phone else None

    try:
        db.session.commit()
        flash('Usuario actualizado exitosamente.', 'success')
        print("Usuario actualizado en la base de datos")  # Depurar

    except SQLAlchemyError as e:
        db.session.rollback()
        flash('Error al actualizar el usuario: ' + str(e), 'error')
        print("Error al actualizar el usuario:", str(e))  # Depurar
        return redirect(url_for('edit_user', user_id=user_id))
    
    return redirect(url_for('list_users'))

#mostrar datos del usuario en editar usuario - vista ADMIN
@app.route('/get_user/<int:user_id>')
def get_user(user_id):
    user = Usuario.query.get(user_id)
    if user:
        return jsonify({
            "nombre": user.nombre,
            "correo": user.correo,
            "telefono": user.telefono
        })
    else:
        return jsonify({"error": "Usuario no encontrado"}), 404

#ver y editar datos del ADMIN
@app.route('/update_profile', methods=['POST'])
@login_required
def update_profile():
    user = Usuario.query.get(current_user.id_usuario)
    if user:
        try:
            user.nombre = request.form['name']
            user.correo = request.form['email']
            user.telefono = request.form['phone']
            db.session.commit()
            flash('Perfil actualizado correctamente.', 'success')
        except SQLAlchemyError as e:
            db.session.rollback()
            flash('Error al actualizar el perfil.', 'error')
            app.logger.error(f'Error de base de datos: {str(e)}')
        return redirect(url_for('perfil_admin'))
    else:
        flash('Usuario no encontrado.', 'error')
        return redirect(url_for('login'))
    

#ver perfil - ADMIN 
@app.route('/perfil_admin')
@login_required
def perfil_admin():
    return render_template('perfil_admin.html')

#ver y editar datos de usuario - vista USER
@app.route('/update_profileUser', methods=['POST'])
@login_required
def update_profileUser():
    user = Usuario.query.get(current_user.id_usuario)
    if user:
        try:
            user.nombre = request.form['name']
            user.correo = request.form['email']
            user.telefono = request.form['phone']
            db.session.commit()
            flash('Perfil actualizado correctamente.', 'success')
        except SQLAlchemyError as e:
            db.session.rollback()
            flash('Error al actualizar el perfil.', 'error')
            app.logger.error(f'Error de base de datos: {str(e)}')
        return redirect(url_for('perfil_user'))
    else:
        flash('Usuario no encontrado.', 'error')
        return redirect(url_for('login'))
    

#ver perfil - vista USER
@app.route('/perfil_user')
@login_required
def perfil_user():
    return render_template('perfil_usuario.html')


#-----------------productos - vista ADMIN-----------------------
# Configuración para subir archivos
UPLOAD_FOLDER = 'static/uploads/'
ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg'}
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER

# Crear el directorio de subida si no existe
if not os.path.exists(UPLOAD_FOLDER):
    os.makedirs(UPLOAD_FOLDER)

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

# Ruta para registrar una nueva categoría
@app.route('/add_category', methods=['POST'])
@login_required
def add_category():
    nombre_categoria = request.form.get('nombre')
    
    if not nombre_categoria:
        flash('El nombre de la categoría es obligatorio.', 'error')
        return redirect(url_for('food_panel'))

    nueva_categoria = CategoriaProducto(nombre=nombre_categoria)
    
    try:
        db.session.add(nueva_categoria)
        db.session.commit()
        flash('Categoría registrada con éxito.', 'success')
    except SQLAlchemyError as e:
        db.session.rollback()
        flash('Error al registrar la categoría: ' + str(e), 'error')

    return redirect(url_for('food_panel'))

# Ruta para renderizar el panel de productos/comida
@app.route('/food_panel', methods=['GET'])
@login_required
def food_panel():
    search_query = request.args.get('search', '').strip()
    sort_by = request.args.get('sort_by', 'nombre')
    sort_order = request.args.get('sort_order', 'asc')
    group_by = request.args.get('group_by', '')

    query = Producto.query

    if search_query:
        query = query.filter(Producto.nombre.ilike(f"%{search_query}%"))

    if group_by == "archivados":
        query = query.filter(Producto.activo == False)
    elif group_by:
        query = query.filter(Producto.categoria_producto_id_catProducto == group_by)
    else:
        query = query.filter((Producto.activo == True) | (Producto.activo == None))

    if sort_by and sort_order:
        if sort_order == 'asc':
            query = query.order_by(getattr(Producto, sort_by).asc())
        else:
            query = query.order_by(getattr(Producto, sort_by).desc())

    productos = query.all()
    categorias = CategoriaProducto.query.all()

    return render_template('food-panel.html', productos=productos, categorias=categorias, selected_category=group_by)


#agregar un nuevo producto
@app.route('/add_producto', methods=['POST'])
@login_required
def add_producto():
    nombre = request.form.get('nombre')
    descripcion = request.form.get('descripcion')
    precio = request.form.get('precio')
    max_personas = request.form.get('max_personas')
    categoria_id = request.form.get('categoria')
    imagen = request.files.get('imagen')

    if not nombre or not descripcion or not precio or not max_personas or not categoria_id or not imagen:
        flash('Todos los campos son obligatorios.', 'error')
        return redirect(url_for('food_panel'))

    if not allowed_file(imagen.filename):
        flash('Solo se permiten archivos de imagen con extensión .png, .jpg, .jpeg.', 'error')
        return redirect(url_for('food_panel'))

    # Guardar la imagen
    filename = secure_filename(imagen.filename)
    filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
    imagen.save(filepath)

    nuevo_producto = Producto(
        nombre=nombre,
        descripcion=descripcion,
        precio=float(precio),
        max_personas=int(max_personas),
        imagen=filepath,
        categoria_producto_id_catProducto=int(categoria_id),
        activo=True  # Establecer el producto como activo
    )
    try:
        db.session.add(nuevo_producto)
        db.session.commit()
        flash('Producto registrado exitosamente.', 'success')
    except SQLAlchemyError as e:
        db.session.rollback()
        flash('Error al registrar el producto: ' + str(e), 'error')

    return redirect(url_for('food_panel'))

# Ruta para obtener la información de un producto específico
@app.route('/get_producto/<int:producto_id>')
@login_required
def get_producto(producto_id):
    producto = Producto.query.get_or_404(producto_id)
    return jsonify({
        'nombre': producto.nombre,
        'descripcion': producto.descripcion,
        'precio': producto.precio,
        'max_personas': producto.max_personas,
        'categoria_producto_id_catProducto': producto.categoria_producto_id_catProducto
    })

# Ruta para actualizar un producto
@app.route('/update_producto/<int:producto_id>', methods=['POST'])
@login_required
def update_producto(producto_id):
    producto = Producto.query.get_or_404(producto_id)

    producto.nombre = request.form.get('nombre')
    producto.descripcion = request.form.get('descripcion')
    producto.precio = float(request.form.get('precio'))
    producto.max_personas = int(request.form.get('max_personas'))
    producto.categoria_producto_id_catProducto = int(request.form.get('categoria'))

    imagen = request.files.get('imagen')
    if imagen and allowed_file(imagen.filename):
        # Guardar la nueva imagen
        filename = secure_filename(imagen.filename)
        filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
        imagen.save(filepath)
        producto.imagen = filepath

    try:
        db.session.commit()
        flash('Producto actualizado exitosamente.', 'success')
    except SQLAlchemyError as e:
        db.session.rollback()
        flash('Error al actualizar el producto: ' + str(e), 'error')
    
    return redirect(url_for('food_panel'))

#ruta para eliminar un producto de manera logica(arhivar)
@app.route('/delete_producto/<int:producto_id>', methods=['POST'])
@login_required
def delete_producto(producto_id):
    producto = Producto.query.get_or_404(producto_id)
    producto.activo = False  # Baja lógica
    try:
        db.session.commit()
        flash('Producto eliminado exitosamente.', 'success')
    except SQLAlchemyError as e:
        db.session.rollback()
        flash('Error al eliminar el producto: ' + str(e), 'error')
    
    return redirect(url_for('food_panel'))

# desarchivar un producto
@app.route('/unarchive_producto/<int:producto_id>', methods=['POST'])
@login_required
def unarchive_producto(producto_id):
    producto = Producto.query.get_or_404(producto_id)
    producto.activo = True
    try:
        db.session.commit()
        flash('Producto desarchivado exitosamente.', 'success')
    except SQLAlchemyError as e:
        db.session.rollback()
        flash('Error al desarchivar el producto: ' + str(e), 'error')
    
    return redirect(url_for('food_panel'))
#-----------------------------------------------------------------













# proteger rutas - utilizado para proteger rutas que requieren login y autenticacion del usuario
#decorador
def login_required(f):
    @wraps(f)
    @flask_login_required  
    
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            flash('Tu sesión ha expirado, por favor inicia sesión de nuevo.', 'info')
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function



from flask import redirect, url_for, flash
from functools import wraps
from flask_login import current_user

