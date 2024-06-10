import os
from flask import render_template, redirect, url_for, request, flash,session
from werkzeug.security import generate_password_hash, check_password_hash
from functools import wraps
from app import app, db
from .models import Usuario, RegistroActividad
from sqlalchemy.exc import SQLAlchemyError
from flask import redirect, url_for, flash
from flask_dance.contrib.google import google
from .models import Usuario, CategoriaProducto, Producto, CategoriaJuego, Juego, Mesa, Reserva, DetalleReserva, RegistroJuego, Pedido, DetallePedido
import datetime
from flask_login import login_user, logout_user, login_required, current_user
from flask_login import login_required as flask_login_required
from datetime import datetime as dt
from datetime import datetime, timedelta

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

#-----------------juegos - vista ADMIN-----------------------
# Configuración para subir archivos
UPLOAD_FOLDER2 = 'static/uploads/games'
ALLOWED_EXTENSIONS2 = {'png', 'jpg', 'jpeg'}
app.config['UPLOAD_FOLDER2'] = UPLOAD_FOLDER2

# Crear el directorio de subida si no existe
if not os.path.exists(UPLOAD_FOLDER2):
    os.makedirs(UPLOAD_FOLDER2)

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS2

# Ruta para registrar una nueva categoría
@app.route('/add_categoryGame', methods=['POST'])
@login_required
def add_categoryGame():
    nombre_categoria = request.form.get('nombre')
    
    if not nombre_categoria:
        flash('El nombre de la categoría es obligatorio.', 'error')
        return redirect(url_for('game_panel'))

    nueva_categoria = CategoriaJuego(nombre=nombre_categoria)
    
    try:
        db.session.add(nueva_categoria)
        db.session.commit()
        flash('Categoría registrada con éxito.', 'success')
    except SQLAlchemyError as e:
        db.session.rollback()
        flash('Error al registrar la categoría: ' + str(e), 'error')

    return redirect(url_for('game_panel'))


# Ruta para renderizar el panel de juegos
@app.route('/game_panel', methods=['GET'])
@login_required
def game_panel():
    search_query = request.args.get('search', '').strip()
    sort_by = request.args.get('sort_by', 'nombre')
    sort_order = request.args.get('sort_order', 'asc')
    group_by = request.args.get('group_by', '')

    query = Juego.query

    if search_query:
        query = query.filter(Juego.nombre.ilike(f"%{search_query}%"))

    if group_by == "archivados":
        query = query.filter(Juego.activo == False)
    elif group_by:
        query = query.filter(Juego.categoria_juego_id_catJuego == group_by)
    else:
        query = query.filter((Juego.activo == True) | (Juego.activo == None))

    if sort_by and sort_order:
        if sort_order == 'asc':
            query = query.order_by(getattr(Juego, sort_by).asc())
        else:
            query = query.order_by(getattr(Juego, sort_by).desc())

    juegos = query.all()
    categorias = CategoriaJuego.query.all()

    return render_template('games-panel.html', juegos=juegos, categorias=categorias, selected_category=group_by)

# Ruta para agregar un nuevo juego
@app.route('/add_game', methods=['POST'])
@login_required
def add_game():
    nombre = request.form.get('nombre')
    descripcion = request.form.get('descripcion')
    precio_alquiler = request.form.get('precio_alquiler')
    precio_venta = request.form.get('precio_venta')
    disponible_venta = request.form.get('disponible_venta') == 'on'
    categoria_id = request.form.get('categoria')
    imagen = request.files.get('imagen')

    if not nombre or not descripcion or not precio_alquiler or not precio_venta or not categoria_id or not imagen:
        flash('Todos los campos son obligatorios.', 'error')
        return redirect(url_for('game_panel'))

    if not allowed_file(imagen.filename):
        flash('Solo se permiten archivos de imagen con extensión .png, .jpg, .jpeg.', 'error')
        return redirect(url_for('game_panel'))

    # Guardar la imagen
    filename = secure_filename(imagen.filename)
    filepath = os.path.join(app.config['UPLOAD_FOLDER2'], filename)
    imagen.save(filepath)

    nuevo_game = Juego(
        nombre=nombre,
        descripcion=descripcion,
        precio_alquiler=float(precio_alquiler),
        precio_venta=float(precio_venta),
        disponible_venta=disponible_venta,
        imagen=filepath,
        categoria_juego_id_catJuego=int(categoria_id),
        activo=True  # Establecer el juego como activo
    )
    try:
        db.session.add(nuevo_game)
        db.session.commit()
        flash('Juego registrado exitosamente.', 'success')
    except SQLAlchemyError as e:
        db.session.rollback()
        flash('Error al registrar el juego: ' + str(e), 'error')

    return redirect(url_for('game_panel'))

# Ruta para obtener la información de un juego específico
@app.route('/get_game/<int:juego_id>')
@login_required
def get_game(juego_id):
    juego = Juego.query.get_or_404(juego_id)
    return jsonify({
        'nombre': juego.nombre,
        'descripcion': juego.descripcion,
        'precio_alquiler': juego.precio_alquiler,
        'precio_venta': juego.precio_venta,
        'disponible_venta': juego.disponible_venta,
        'categoria_juego_id_catJuego': juego.categoria_juego_id_catJuego
    })

# Ruta para actualizar un juego
@app.route('/update_game/<int:game_id>', methods=['POST'])
@login_required
def update_game(game_id):
    game = Juego.query.get_or_404(game_id)

    game.nombre = request.form.get('nombre')
    game.descripcion = request.form.get('descripcion')
    game.precio_alquiler = float(request.form.get('precio_alquiler'))
    game.precio_venta = float(request.form.get('precio_venta'))
    game.disponible_venta = request.form.get('disponible_venta') == 'on'
    game.categoria_juego_id_catJuego = int(request.form.get('categoria'))

    imagen = request.files.get('imagen')
    if imagen and allowed_file(imagen.filename):
        # Guardar la nueva imagen
        filename = secure_filename(imagen.filename)
        filepath = os.path.join(app.config['UPLOAD_FOLDER2'], filename)
        imagen.save(filepath)
        game.imagen = filepath

    try:
        db.session.commit()
        flash('Juego actualizado exitosamente.', 'success')
    except SQLAlchemyError as e:
        db.session.rollback()
        flash('Error al actualizar el juego: ' + str(e), 'error')

    return redirect(url_for('game_panel'))


# Ruta para eliminar un juego de manera lógica (archivar)
@app.route('/delete_game/<int:juego_id>', methods=['POST'])
@login_required
def delete_game(juego_id):
    juego = Juego.query.get_or_404(juego_id)
    juego.activo = False  # Baja lógica
    try:
        db.session.commit()
        flash('Juego archivado exitosamente.', 'success')
    except SQLAlchemyError as e:
        db.session.rollback()
        flash('Error al archivar el juego: ' + str(e), 'error')
    
    return redirect(url_for('game_panel'))

# Desarchivar un juego
@app.route('/unarchive_game/<int:juego_id>', methods=['POST'])
@login_required
def unarchive_game(juego_id):
    juego = Juego.query.get_or_404(juego_id)
    juego.activo = True
    try:
        db.session.commit()
        flash('Juego desarchivado exitosamente.', 'success')
    except SQLAlchemyError as e:
        db.session.rollback()
        flash('Error al desarchivar el juego: ' + str(e), 'error')
    
    return redirect(url_for('game_panel'))

#-----------------------------ver menus -VISTA USUARIO------------------------------

#mostrar categorias y productos vista usuario 
@app.route('/food-menu')
@login_required
def mostrar_menu():
    categorias = db.session.query(CategoriaProducto).all()
    productos = db.session.query(Producto).filter_by(activo=True).all()

    # Agrupar productos por categoría
    productos_por_categoria = {}
    for producto in productos:
        categoria_id = producto.categoria_producto_id_catProducto
        if categoria_id not in productos_por_categoria:
            productos_por_categoria[categoria_id] = []
        productos_por_categoria[categoria_id].append(producto)

    return render_template('food-menu.html', categorias=categorias, productos_por_categoria=productos_por_categoria)



#mostrar categorias y juegos 
@app.route('/game-menu')
@login_required
def mostrar_menu_juegos():
    categoria_filtro = request.args.get('category', 'all')
    search_query = request.args.get('search', '')

    categorias = db.session.query(CategoriaJuego).all()
    query = db.session.query(Juego).filter_by(activo=True)

    if categoria_filtro != 'all':
        categoria = db.session.query(CategoriaJuego).filter_by(nombre=categoria_filtro).first()
        if categoria:
            query = query.filter_by(categoria_juego_id_catJuego=categoria.id_catJuego)

    if search_query:
        query = query.filter(Juego.nombre.ilike(f'%{search_query}%'))

    juegos = query.all()
    return render_template('game-menu.html', juegos=juegos, categorias=categorias, categoria_filtro=categoria_filtro, search_query=search_query)
#--------------------------------------------------------------------
#------------------REGISTRO MESA - admin ---------------------------

# Ruta para renderizar el panel de productos/comida
@app.route('/registro_mesa', methods=['GET'])
@login_required
def registro_mesa():
    search_query = request.args.get('search', '').strip()
    sort_by = request.args.get('sort_by', 'ubicacion')
    sort_order = request.args.get('sort_order', 'asc')
    group_by = request.args.get('group_by', '')

    query = Mesa.query

    if search_query:
        query = query.filter(Mesa.ubicacion.ilike(f"%{search_query}%"))

    if group_by == "archivados":
        query = query.filter(Mesa.activo == False)
    else:
        query = query.filter((Mesa.activo == True) | (Mesa.activo == None))

    if sort_by and sort_order:
        if sort_order == 'asc':
            query = query.order_by(getattr(Mesa, sort_by).asc())
        else:
            query = query.order_by(getattr(Mesa, sort_by).desc())

    mesas = query.all()

    return render_template('registrar-mesas.html', mesas=mesas, selected_mesa=group_by)


#agregar un nuevo producto
@app.route('/add_mesa', methods=['POST'])
@login_required
def add_mesa():
    capacidad = request.form.get('capacidad')
    ubicacion = request.form.get('ubicacion')

    if not capacidad or not ubicacion:
        flash('Todos los campos son obligatorios.', 'error')
        return redirect(url_for('registro_mesa'))

    nuevo_mesa = Mesa(
        capacidad=int(capacidad),
        ubicacion=ubicacion,
        activo=True  # Establecer el producto como activo
    )
    try:
        db.session.add(nuevo_mesa)
        db.session.commit()
        flash('mesa registrado exitosamente.', 'success')
    except SQLAlchemyError as e:
        db.session.rollback()
        flash('Error al registrar el producto: ' + str(e), 'error')

    return redirect(url_for('registro_mesa'))

# Ruta para obtener la información de un producto específico
@app.route('/get_mesa/<int:mesa_id>')
@login_required
def get_mesa(mesa_id):
    mesa = Mesa.query.get_or_404(mesa_id)
    return jsonify({
        'capacidad': mesa.capacidad,
        'ubicacion': mesa.ubicacion,
    })

# Ruta para actualizar un producto
@app.route('/update_mesa/<int:mesa_id>', methods=['POST'])
@login_required
def update_mesa(mesa_id):
    mesa = Mesa.query.get_or_404(mesa_id)

    mesa.capacidad = int(request.form.get('capacidad'))
    mesa.ubicacion = request.form.get('ubicacion')

    try:
        db.session.commit()
        flash('Producto actualizado exitosamente.', 'success')
    except SQLAlchemyError as e:
        db.session.rollback()
        flash('Error al actualizar el producto: ' + str(e), 'error')
    
    return redirect(url_for('registro_mesa'))

#ruta para eliminar un producto de manera logica(arhivar)
@app.route('/delete_mesa/<int:mesa_id>', methods=['POST'])
@login_required
def delete_mesa(mesa_id):
    mesa = Mesa.query.get_or_404(mesa_id)
    mesa.activo = False  # Baja lógica
    try:
        db.session.commit()
        flash('Producto eliminado exitosamente.', 'success')
    except SQLAlchemyError as e:
        db.session.rollback()
        flash('Error al eliminar el producto: ' + str(e), 'error')
    
    return redirect(url_for('registro_mesa'))

# desarchivar un producto
@app.route('/unarchive_mesa/<int:mesa_id>', methods=['POST'])
@login_required
def unarchive_mesa(mesa_id):
    mesa = Mesa.query.get_or_404(mesa_id)
    mesa.activo = True
    try:
        db.session.commit()
        flash('Producto desarchivado exitosamente.', 'success')
    except SQLAlchemyError as e:
        db.session.rollback()
        flash('Error al desarchivar el producto: ' + str(e), 'error')
    
    return redirect(url_for('registro_mesa'))


@app.route('/form_reserva')
@login_required
def form_reserva():
    return render_template('form-reserva.html')

@app.route('/continuar_reserva', methods=['GET'])
@login_required
def continuar_reserva():
    fecha = request.args.get('date')
    hora_inicio = request.args.get('start_time')
    hora_fin = request.args.get('end_time')
    usuario_id = current_user.id_usuario

    # Verificar si el usuario ya tiene una reserva en la misma fecha
    reservas_usuario = Reserva.query.filter_by(usuario_id_usuario=usuario_id).all()
    for reserva in reservas_usuario:
        if reserva.fecha_hora.date() == datetime.strptime(fecha, '%Y-%m-%d').date():
            flash('Elige otra fecha, ya tienes una reserva en esta fecha', 'error')
            return redirect(url_for('form_reserva'))

    fecha_hora_inicio = datetime.strptime(f'{fecha} {hora_inicio}', '%Y-%m-%d %H:%M')
    fecha_hora_fin = datetime.strptime(f'{fecha} {hora_fin}', '%Y-%m-%d %H:%M')

    mesas_disponibles = []
    mesas = Mesa.query.all()
    for mesa in mesas:
        reservas = Reserva.query.filter(
            Reserva.mesa_id_mesa == mesa.id_mesa,
            Reserva.fecha_hora.between(fecha_hora_inicio, fecha_hora_fin)
        ).all()
        if reservas:
            proxima_disponibilidad = max([r.fecha_hora for r in reservas]) + timedelta(hours=2, minutes=30)
            mesas_disponibles.append({
                'mesa': mesa,
                'disponible': False,
                'proxima_disponibilidad': proxima_disponibilidad
            })
        else:
            mesas_disponibles.append({
                'mesa': mesa,
                'disponible': True,
                'proxima_disponibilidad': None
            })

    categorias_productos = CategoriaProducto.query.all()
    categorias_juegos = CategoriaJuego.query.all()
    productos = Producto.query.filter_by(activo=True).all()
    juegos = Juego.query.filter_by(activo=True).all()

    return render_template('form-reserva.html', 
                           mesas_disponibles=mesas_disponibles, 
                           productos=productos, 
                           juegos=juegos, 
                           categorias_productos=categorias_productos, 
                           categorias_juegos=categorias_juegos, 
                           fecha=fecha, 
                           hora_inicio=hora_inicio, 
                           hora_fin=hora_fin)

@app.route('/confirmar_reserva', methods=['POST'])
@login_required
def confirmar_reserva():
    fecha = request.form.get('date')
    hora_inicio = request.form.get('start_time')
    hora_fin = request.form.get('end_time')
    mesa_id = request.form.get('mesa')
    productos_seleccionados = request.form.get('productos').split(',')
    juego_seleccionado = request.form.get('juego')

    print("Fecha:", fecha)
    print("Hora inicio:", hora_inicio)
    print("Hora fin:", hora_fin)
    print("Mesa ID:", mesa_id)
    print("Productos seleccionados:", productos_seleccionados)
    print("Juego seleccionado:", juego_seleccionado)

    fecha_hora_inicio = datetime.strptime(f'{fecha} {hora_inicio}', '%Y-%m-%d %H:%M')

    try:
        reserva = Reserva(
            fecha_hora=fecha_hora_inicio,
            estado='Reservado',
            usuario_id_usuario=current_user.id_usuario,
            mesa_id_mesa=int(mesa_id)
        )
        db.session.add(reserva)
        db.session.commit()

        for producto in productos_seleccionados:
            if producto:
                producto_id, cantidad = map(int, producto.split(':'))
                prod = Producto.query.get(producto_id)
                detalle_reserva = DetalleReserva(
                    cantidad=cantidad,
                    precio=prod.precio,
                    producto_id_producto=producto_id,
                    reserva_id_reserva=reserva.id_reserva
                )
                db.session.add(detalle_reserva)

        if juego_seleccionado:
            juego_id, cantidad = map(int, juego_seleccionado.split(':'))
            juego = Juego.query.get(juego_id)
            registro_juego = RegistroJuego(
                cantidad=cantidad,
                precio=juego.precio_alquiler,
                tipo=1,  # Asumir un tipo, ya que no está definido en el contexto
                juego_id_juego=juego_id,
                usuario_id_usuario=current_user.id_usuario,
                reserva_id_reserva=reserva.id_reserva
            )
            db.session.add(registro_juego)

        db.session.commit()
        flash('Reserva confirmada con éxito.', 'success')
        return redirect(url_for('user_reservations'))

    except Exception as e:
        db.session.rollback()
        flash(f'Error al confirmar la reserva: {str(e)}', 'danger')
        return redirect(url_for('form_reserva'))


@app.route('/user_reservations')
@login_required
def user_reservations():
    group_by = request.args.get('group_by', 'todas')

    query = Reserva.query.filter_by(usuario_id_usuario=current_user.id_usuario)

    if group_by == 'reservados':
        query = query.filter_by(estado='Reservado')
    elif group_by == 'cancelado':
        query = query.filter_by(estado='Cancelado')

    reservas = query.all()

    reservas_info = []
    for reserva in reservas:
        detalle_reservas = DetalleReserva.query.filter_by(reserva_id_reserva=reserva.id_reserva).all()
        registro_juego = RegistroJuego.query.filter_by(reserva_id_reserva=reserva.id_reserva).first()

        monto_total = sum(detalle.cantidad * detalle.precio for detalle in detalle_reservas)
        if registro_juego:
            monto_total += registro_juego.cantidad * registro_juego.precio

        reservas_info.append({
            'id_reserva': reserva.id_reserva,
            'fecha_hora': reserva.fecha_hora,
            'estado': reserva.estado,
            'monto_total': monto_total
        })

    return render_template('user-reservations.html', reservas=reservas_info, selected_group=group_by)




@app.route('/cancelar_reserva/<int:id_reserva>', methods=['POST'])
@login_required
def cancelar_reserva(id_reserva):
    reserva = Reserva.query.get_or_404(id_reserva)
    if reserva.usuario_id_usuario != current_user.id_usuario:
        flash('No tienes permiso para cancelar esta reserva.', 'danger')
        return redirect(url_for('user_reservations'))

    reserva.estado = 'Cancelado'
    db.session.commit()
    flash('Reserva cancelada con éxito.', 'success')
    return redirect(url_for('user_reservations'))
from datetime import datetime, timedelta

@app.route('/editar_reserva/<int:reserva_id>', methods=['GET', 'POST'])
@login_required
def editar_reserva(reserva_id):
    if request.method == 'POST':
        try:
            productos_seleccionados = request.form.get('productos').split(',')
            juego_seleccionado = request.form.get('juego')

            reserva = Reserva.query.get(reserva_id)
            DetalleReserva.query.filter_by(reserva_id_reserva=reserva.id_reserva).delete()
            RegistroJuego.query.filter_by(reserva_id_reserva=reserva.id_reserva).delete()

            for producto in productos_seleccionados:
                if producto:
                    producto_id, cantidad = map(int, producto.split(':'))
                    prod = Producto.query.get(producto_id)
                    detalle_reserva = DetalleReserva(
                        cantidad=cantidad,
                        precio=prod.precio,
                        producto_id_producto=producto_id,
                        reserva_id_reserva=reserva.id_reserva
                    )
                    db.session.add(detalle_reserva)

            if juego_seleccionado:
                juego_id, cantidad = map(int, juego_seleccionado.split(':'))
                juego = Juego.query.get(juego_id)
                registro_juego = RegistroJuego(
                    cantidad=cantidad,
                    precio=juego.precio_alquiler,
                    tipo=1,
                    juego_id_juego=juego_id,
                    usuario_id_usuario=current_user.id_usuario,
                    reserva_id_reserva=reserva.id_reserva
                )
                db.session.add(registro_juego)

            db.session.commit()
            flash('Reserva actualizada con éxito.', 'success')
            return redirect(url_for('user_reservations'))

        except Exception as e:
            db.session.rollback()
            flash(f'Error al actualizar la reserva: {str(e)}', 'danger')
            return redirect(url_for('editar_reserva', reserva_id=reserva_id))

    reserva = Reserva.query.get_or_404(reserva_id)
    detalle_reservas = DetalleReserva.query.filter_by(reserva_id_reserva=reserva.id_reserva).all()
    registro_juego = RegistroJuego.query.filter_by(reserva_id_reserva=reserva.id_reserva).first()
    productos = Producto.query.filter_by(activo=True).all()
    juegos = Juego.query.filter_by(activo=True).all()
    return render_template('editar-reserva.html', reserva=reserva, productos=productos, juegos=juegos, detalle_reservas=detalle_reservas, registro_juego=registro_juego, timedelta=timedelta)


@app.route('/actualizar_reserva', methods=['POST'])
@login_required
def actualizar_reserva():
    reserva_id = request.form.get('id_reserva')
    productos_seleccionados = request.form.get('productos').split(',')
    juego_seleccionado = request.form.get('juego')

    reserva = Reserva.query.get(reserva_id)

    try:
        # Actualizar detalles de la reserva
        DetalleReserva.query.filter_by(reserva_id_reserva=reserva_id).delete()
        RegistroJuego.query.filter_by(reserva_id_reserva=reserva_id).delete()

        for producto in productos_seleccionados:
            if producto:
                producto_id, cantidad = map(int, producto.split(':'))
                prod = Producto.query.get(producto_id)
                detalle_reserva = DetalleReserva(
                    cantidad=cantidad,
                    precio=prod.precio,
                    producto_id_producto=producto_id,
                    reserva_id_reserva=reserva.id_reserva
                )
                db.session.add(detalle_reserva)

        if juego_seleccionado:
            juego_id, cantidad = map(int, juego_seleccionado.split(':'))
            juego = Juego.query.get(juego_id)
            registro_juego = RegistroJuego(
                cantidad=cantidad,
                precio=juego.precio_alquiler,
                tipo=1,  # Asumir un tipo, ya que no está definido en el contexto
                juego_id_juego=juego_id,
                usuario_id_usuario=current_user.id_usuario,
                reserva_id_reserva=reserva.id_reserva
            )
            db.session.add(registro_juego)

        db.session.commit()
        flash('Reserva actualizada con éxito.', 'success')
        return redirect(url_for('user_reservations'))

    except Exception as e:
        db.session.rollback()
        flash(f'Error al actualizar la reserva: {str(e)}', 'danger')
        return redirect(url_for('editar_reserva', reserva_id=reserva_id))








#----------------------vista admin
def calcular_monto_total(reserva):
    productos = DetalleReserva.query.filter_by(reserva_id_reserva=reserva.id_reserva).all()
    juegos = RegistroJuego.query.filter_by(reserva_id_reserva=reserva.id_reserva).all()
    monto_total = sum([p.precio * p.cantidad for p in productos]) + sum([j.precio * j.cantidad for j in juegos])
    return monto_total

@app.route('/reservas_panel', methods=['GET'])
@login_required
def reservas_panel():
    group_by = request.args.get('group_by', 'todas')
    search_query = request.args.get('search', '')
    sort_by = request.args.get('sort_by', 'id_reserva')
    sort_order = request.args.get('sort_order', 'asc')

    reservas_query = Reserva.query.join(Usuario).filter(
        Usuario.nombre.ilike(f'%{search_query}%')
    )

    if group_by == 'reservados':
        reservas_query = reservas_query.filter(Reserva.estado == 'Reservado')
    elif group_by == 'cancelado':
        reservas_query = reservas_query.filter(Reserva.estado == 'Cancelado')

    if sort_order == 'asc':
        reservas_query = reservas_query.order_by(getattr(Reserva, sort_by).asc())
    else:
        reservas_query = reservas_query.order_by(getattr(Reserva, sort_by).desc())

    reservas = reservas_query.all()

    # Calcular monto total de cada reserva
    for reserva in reservas:
        reserva.monto_total = calcular_monto_total(reserva)

    return render_template('reservas-panel.html', reservas=reservas, selected_group=group_by, search_query=search_query, sort_by=sort_by, sort_order=sort_order)

@app.route('/cancel_reserva/<int:id_reserva>', methods=['POST'])
@login_required
def cancel_reserva(id_reserva):
    reserva = Reserva.query.get_or_404(id_reserva)
    reserva.estado = 'Cancelado'
    db.session.commit()
    flash('Reserva cancelada con éxito.', 'success')
    return redirect(url_for('reservas_panel'))


@app.route('/verDetalle-reserva/<int:id_reserva>', methods=['GET'])
@login_required
def ver_detalle_reserva(id_reserva):
    reserva = Reserva.query.get_or_404(id_reserva)
    cliente = reserva.usuario
    mesa = reserva.mesa
    detalle_reservas = DetalleReserva.query.filter_by(reserva_id_reserva=id_reserva).all()
    registro_juego = RegistroJuego.query.filter_by(reserva_id_reserva=id_reserva).first()

    productos = []
    for detalle in detalle_reservas:
        producto = {
            'nombre': detalle.producto_rel.nombre,
            'cantidad': detalle.cantidad,
            'precio_unitario': detalle.precio,
            'total': detalle.cantidad * detalle.precio
        }
        productos.append(producto)

    print("Productos:", productos)

    total_reserva = sum([producto['total'] for producto in productos])

    if registro_juego:
        juego = {
            'nombre': registro_juego.juego_rel.nombre,
            'cantidad': 1,  # Supongo que la cantidad de juegos es siempre 1 por reserva
            'precio_unitario': registro_juego.precio,
            'total': registro_juego.precio
        }
        productos.append(juego)
        total_reserva += juego['total']
        print("Juego agregado:", juego)
    else:
        print("No se encontró juego para esta reserva.")

    print("Productos finales:", productos)
    print("Total reserva:", total_reserva)

    return render_template('verDetalle-reserva.html', reserva=reserva, cliente=cliente, mesa=mesa, productos=productos, total_reserva=total_reserva)



@app.route('/agregar_pedido', methods=['GET', 'POST'])
@login_required
def agregar_pedido():
    # Verificar si el usuario tiene una reserva activa en la fecha y hora actual
    now = datetime.now()
    reserva_activa = Reserva.query.filter(
        Reserva.usuario_id_usuario == current_user.id_usuario,
        Reserva.fecha_hora <= now,
        Reserva.fecha_hora + timedelta(hours=2, minutes=30) >= now,
        Reserva.estado == 'Reservado'
    ).first()

    if not reserva_activa:
        flash('No tienes una reserva activa en este momento. No puedes realizar pedidos.', 'danger')
        return render_template('sin_reserva.html')

    if request.method == 'POST':
        # Lógica para agregar un pedido
        productos_seleccionados = request.form.get('productos').split(',')
        pedido = Pedido(
            tipo='Mesa',
            estado='Pendiente',
            fecha_hora=datetime.now(),
            usuario_id_usuario=current_user.id_usuario,
            mesa_id_mesa=reserva_activa.mesa_id_mesa
        )
        db.session.add(pedido)
        db.session.commit()

        for producto in productos_seleccionados:
            if producto:
                producto_id, cantidad = map(int, producto.split(':'))
                prod = Producto.query.get(producto_id)
                detalle_pedido = DetallePedido(
                    cantidad=cantidad,
                    precio=prod.precio,
                    producto_id_producto=producto_id,
                    pedido_id_pedido=pedido.id_pedido
                )
                db.session.add(detalle_pedido)
        db.session.commit()

        flash('Pedido realizado con éxito.', 'success')
        return redirect(url_for('inicio_usuario'))

    productos = Producto.query.filter_by(activo=True).all()
    return render_template('agregar-pedido.html', productos=productos, reserva_activa=reserva_activa)









#ver pedidos - usuario
@app.route('/ver_pedidos', methods=['GET'])
@login_required
def ver_pedidos():
    group_by = request.args.get('group_by', 'Pendiente')
    pedidos = Pedido.query.filter_by(usuario_id_usuario=current_user.id_usuario, estado=group_by).all()

    pedidos_con_totales = []
    for pedido in pedidos:
        total_pedido = sum(detalle.cantidad * detalle.precio for detalle in pedido.detalles_pedido)
        pedido_info = {
            'id_pedido': pedido.id_pedido,
            'fecha_hora': pedido.fecha_hora,
            'estado': pedido.estado,
            'monto_total': total_pedido
        }
        pedidos_con_totales.append(pedido_info)

    return render_template('ver-pedidos.html', pedidos=pedidos_con_totales, selected_group=group_by)


#cancelar un pedido - usuario
@app.route('/cancelar_pedido/<int:id_pedido>', methods=['POST'])
@login_required
def cancelar_pedido(id_pedido):
    pedido = Pedido.query.get_or_404(id_pedido)
    if pedido.estado == 'Pendiente':
        pedido.estado = 'Cancelado'
        db.session.commit()
        return jsonify({'status': 'success'})
    return jsonify({'status': 'error'}), 400



@app.route('/userpedidos/<int:pedido_id>', methods=['GET'])
@login_required
def userspedidos(pedido_id):
    pedido = Pedido.query.get_or_404(pedido_id)
    detalles_pedido = DetallePedido.query.filter_by(pedido_id_pedido=pedido_id).all()

    productos = []
    for detalle in detalles_pedido:
        producto = {
            'nombre': detalle.producto_rel.nombre,
            'cantidad': detalle.cantidad,
            'precio_unitario': detalle.precio,
            'total': detalle.cantidad * detalle.precio
        }
        productos.append(producto)

    total_pedido = sum([producto['total'] for producto in productos])

    mesa = Mesa.query.get_or_404(pedido.mesa_id_mesa)

    return render_template('userpedidos.html', pedido=pedido, productos=productos, total_pedido=total_pedido, mesa=mesa)


















from sqlalchemy import asc, desc, or_

@app.route('/pedidos_panel', methods=['GET'])
@login_required
def pedidos_panel():
    group_by = request.args.get('group_by', 'todos')
    search_query = request.args.get('search', '')
    sort_by = request.args.get('sort_by', 'fecha_hora')
    sort_order = request.args.get('sort_order', 'asc')

    pedidos_query = Pedido.query.join(Usuario)

    if group_by != 'todos':
        pedidos_query = pedidos_query.filter(Pedido.estado.ilike(group_by))

    if search_query:
        search = f"%{search_query}%"
        pedidos_query = pedidos_query.filter(
            or_(
                Usuario.nombre.ilike(search),
                Pedido.estado.ilike(search)
            )
        )

    if sort_order == 'asc':
        pedidos_query = pedidos_query.order_by(asc(getattr(Pedido, sort_by)))
    else:
        pedidos_query = pedidos_query.order_by(desc(getattr(Pedido, sort_by)))

    pedidos = pedidos_query.all()

    pedidos_con_totales = []
    for pedido in pedidos:
        total_pedido = sum([detalle.precio * detalle.cantidad for detalle in pedido.detalles_pedido])
        pedidos_con_totales.append({'pedido': pedido, 'total': total_pedido})

    return render_template('pedidos-panel.html', pedidos=pedidos_con_totales, selected_group=group_by, search_query=search_query, sort_by=sort_by, sort_order=sort_order)

@app.route('/cambiar_estado_pedido/<int:pedido_id>/<string:nuevo_estado>', methods=['POST'])
@login_required
def cambiar_estado_pedido(pedido_id, nuevo_estado):
    pedido = Pedido.query.get_or_404(pedido_id)
    pedido.estado = nuevo_estado
    db.session.commit()
    return redirect(url_for('pedidos_panel'))


@app.route('/cancel_pedido/<int:id_pedido>', methods=['POST'])
@login_required
def cancel_pedido(id_pedido):
    pedido = Pedido.query.get_or_404(id_pedido)
    if pedido.estado == 'Pendiente':
        pedido.estado = 'Cancelado'
        db.session.commit()
        return jsonify({'message': 'Pedido cancelado con éxito.'}), 200
    return jsonify({'message': 'No se puede cancelar el pedido.'}), 400

@app.route('/verDetalle-pedido/<int:pedido_id>', methods=['GET'])
@login_required
def ver_detalle_pedido(pedido_id):
    pedido = Pedido.query.get_or_404(pedido_id)
    detalles_pedido = DetallePedido.query.filter_by(pedido_id_pedido=pedido_id).all()

    productos = []
    for detalle in detalles_pedido:
        producto = {
            'nombre': detalle.producto_rel.nombre,
            'cantidad': detalle.cantidad,
            'precio_unitario': detalle.precio,
            'total': detalle.cantidad * detalle.precio
        }
        productos.append(producto)

    total_pedido = sum([producto['total'] for producto in productos])

    return render_template('verDetalle-pedido.html', pedido=pedido, productos=productos, total_pedido=total_pedido)




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

