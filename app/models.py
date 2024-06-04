from app import db
from datetime import datetime
from flask_login import UserMixin
from sqlalchemy.dialects.postgresql import JSON
from werkzeug.security import generate_password_hash, check_password_hash
class Usuario(db.Model,UserMixin):
    __tablename__ = 'usuario'
    id_usuario = db.Column(db.Integer, primary_key=True)
    nombre = db.Column(db.String(50), nullable=False)
    correo = db.Column(db.String(50), nullable=False)
    telefono = db.Column(db.Integer, nullable=True)
    password = db.Column(db.String(256), nullable=False)
    is_active = db.Column(db.Boolean, default=True)
    pregunta_seguridad = db.Column(db.String(255), nullable=False)
    respuesta_seguridad = db.Column(db.String(255), nullable=False)
    activo = db.Column(db.Boolean, default=True)
    rol_id_rol = db.Column(db.String(50), db.ForeignKey('rol.id_rol'), nullable=False)
    pagos = db.relationship('Pago', backref='usuario', lazy=True)
    registros_juego = db.relationship('RegistroJuego', backref='usuario', lazy=True)
    reservas = db.relationship('Reserva', backref='usuario', lazy=True)
    actividades = db.relationship('RegistroActividad', backref='usuario', lazy=True)

    def __repr__(self):
        return '<Usuario {}>'.format(self.nombre)
    def get_id(self):
        """Return the email address to satisfy Flask-Login's requirements."""
        return str(self.id_usuario)  # Convertir a string para cumplir con Flask-Login
    def set_password(self, password):
        self.password = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password, password)

class Rol(db.Model):
    __tablename__ = 'rol'
    id_rol = db.Column(db.String(50), primary_key=True)
    nombre = db.Column(db.String(50), nullable=False)
    usuarios = db.relationship('Usuario', backref='rol', lazy=True)

class CategoriaJuego(db.Model):
    __tablename__ = 'categoria_juego'
    id_catJuego = db.Column(db.Integer, primary_key=True)
    nombre = db.Column(db.String(200), nullable=False)
    juegos = db.relationship('Juego', backref='categoria_juego', lazy=True)

class CategoriaProducto(db.Model):
    __tablename__ = 'categoria_producto'
    id_catProducto = db.Column(db.Integer, primary_key=True)
    nombre = db.Column(db.String(200), nullable=False)
    productos = db.relationship('Producto', backref='categoria_producto', lazy=True)

class Juego(db.Model):
    __tablename__ = 'juego'
    id_juego = db.Column(db.Integer, primary_key=True)
    nombre = db.Column(db.String(50), nullable=False)
    descripcion = db.Column(db.String(500), nullable=False)
    precio_alquiler = db.Column(db.Float, nullable=False)
    precio_venta = db.Column(db.Float, nullable=False)
    disponible_venta = db.Column(db.Boolean, nullable=False)
    imagen = db.Column(db.String(255), nullable=False)  
    activo = db.Column(db.Boolean, default=True)

    categoria_juego_id_catJuego = db.Column(db.Integer, db.ForeignKey('categoria_juego.id_catJuego'), nullable=False)

class Mesa(db.Model):
    __tablename__ = 'mesa'
    id_mesa = db.Column(db.Integer, primary_key=True)
    capacidad = db.Column(db.Integer, nullable=False)
    ubicacion = db.Column(db.String(200), nullable=False)
    activo = db.Column(db.Boolean, default=True)


class Pedido(db.Model):
    __tablename__ = 'pedido'
    id_pedido = db.Column(db.Integer, primary_key=True)
    tipo = db.Column(db.String(50), nullable=False)
    estado = db.Column(db.String(50), nullable=False)
    fecha_hora = db.Column(db.DateTime, nullable=False)
    usuario_id_usuario = db.Column(db.Integer, db.ForeignKey('usuario.id_usuario'), nullable=False)
    mesa_id_mesa = db.Column(db.Integer, db.ForeignKey('mesa.id_mesa'), nullable=False)

class Producto(db.Model):
    __tablename__ = 'producto'
    id_producto = db.Column(db.Integer, primary_key=True)
    nombre = db.Column(db.String(50), nullable=False)
    descripcion = db.Column(db.String(500), nullable=False)
    precio = db.Column(db.Float, nullable=False)
    max_personas = db.Column(db.Integer, nullable=False)
    imagen = db.Column(db.String(255), nullable=False)  
    activo = db.Column(db.Boolean, default=True)

    categoria_producto_id_catProducto = db.Column(db.Integer, db.ForeignKey('categoria_producto.id_catProducto'), nullable=False)


class RegistroJuego(db.Model):
    __tablename__ = 'registro_juego'
    id_regJuego = db.Column(db.Integer, primary_key=True)
    cantidad = db.Column(db.Integer, nullable=False)
    precio = db.Column(db.Float, nullable=False)
    tipo = db.Column(db.Integer, nullable=False)
    juego_id_juego = db.Column(db.Integer, db.ForeignKey('juego.id_juego'), nullable=False)
    usuario_id_usuario = db.Column(db.Integer, db.ForeignKey('usuario.id_usuario'), nullable=False)
    reserva_id_reserva = db.Column(db.Integer, db.ForeignKey('reserva.id_reserva'), nullable=False)

class Reserva(db.Model):
    __tablename__ = 'reserva'
    id_reserva = db.Column(db.Integer, primary_key=True)
    fecha_hora = db.Column(db.DateTime, nullable=False)
    estado = db.Column(db.String(50), nullable=False)
    usuario_id_usuario = db.Column(db.Integer, db.ForeignKey('usuario.id_usuario'), nullable=False)
    mesa_id_mesa = db.Column(db.Integer, db.ForeignKey('mesa.id_mesa'), nullable=False)

class Pago(db.Model):
    __tablename__ = 'pago'
    id_pago = db.Column(db.Integer, primary_key=True)
    fecha = db.Column(db.DateTime, nullable=False)
    monto = db.Column(db.Float, nullable=False)
    detalle_pedido_id_detallePed = db.Column(db.Integer, db.ForeignKey('detalle_pedido.id_detallePed'), nullable=False)
    detalle_reserva_id_detalleReserva = db.Column(db.Integer, db.ForeignKey('detalle_reserva.id_detalleReserva'), nullable=False)
    registro_juego_id_regJuego = db.Column(db.Integer, db.ForeignKey('registro_juego.id_regJuego'), nullable=False)
    usuario_id_usuario = db.Column(db.Integer, db.ForeignKey('usuario.id_usuario'), nullable=False)

class DetallePedido(db.Model):
    __tablename__ = 'detalle_pedido'
    id_detallePed = db.Column(db.Integer, primary_key=True)
    cantidad = db.Column(db.Integer, nullable=False)
    precio = db.Column(db.Float, nullable=False)
    producto_id_producto = db.Column(db.Integer, db.ForeignKey('producto.id_producto'), nullable=False)
    pedido_id_pedido = db.Column(db.Integer, db.ForeignKey('pedido.id_pedido'), nullable=False)

class DetalleReserva(db.Model):
    __tablename__ = 'detalle_reserva'
    id_detalleReserva = db.Column(db.Integer, primary_key=True)
    cantidad = db.Column(db.Integer, nullable=False)
    precio = db.Column(db.Float, nullable=False)
    producto_id_producto = db.Column(db.Integer, db.ForeignKey('producto.id_producto'), nullable=False)
    reserva_id_reserva = db.Column(db.Integer, db.ForeignKey('reserva.id_reserva'), nullable=False)

class RegistroActividad(db.Model):
    __tablename__ = 'registro_actividad'
    id_registro_actividad = db.Column(db.Integer, primary_key=True, autoincrement=True)
    usuario_id = db.Column(db.Integer, db.ForeignKey('usuario.id_usuario'), nullable=False)
    fecha_hora = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
