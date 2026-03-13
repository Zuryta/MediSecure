import pyotp
import qrcode
import io
import base64
import logging
import re
import os
from datetime import timedelta, date

from flask import Flask, render_template, request, redirect, url_for, flash, session
from flask_sqlalchemy import SQLAlchemy
from flask_login import (UserMixin, login_user, LoginManager,
                         login_required, logout_user, current_user)
from werkzeug.security import generate_password_hash, check_password_hash
from cryptography.fernet import Fernet


# ── Logging ────────────────────────────────────────────────────────────────
logging.basicConfig(
    filename='medisecure_audit.log',
    level=logging.INFO,
    format='%(asctime)s | %(levelname)s | %(message)s',
    datefmt='%Y-%m-%d %H:%M:%S',
)
logger = logging.getLogger(__name__)


# ── App config ─────────────────────────────────────────────────────────────
app = Flask(__name__)

app.config['SECRET_KEY']                     = os.environ.get('SECRET_KEY', 'dev-solo-local-cambiar-en-prod')
app.config['SQLALCHEMY_DATABASE_URI']        = os.environ.get('DATABASE_URL', 'sqlite:///hospital_futuro.db')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SESSION_COOKIE_HTTPONLY']        = True
app.config['SESSION_COOKIE_SAMESITE']        = 'Lax'
app.config['SESSION_COOKIE_SECURE']          = (os.environ.get('FLASK_ENV') == 'production')
app.config['PERMANENT_SESSION_LIFETIME']     = timedelta(hours=1)

db = SQLAlchemy(app)


# ── Inicialización de BD al cargar el módulo (compatible con Gunicorn) ─────
# IMPORTANTE: db.create_all() debe correr ANTES del primer request.
# Ponerlo solo en `if __name__ == '__main__':` hace que falle con Gunicorn
# porque ese bloque nunca se ejecuta en producción (Render, Railway, etc.).
# La función _inicializar_bd() se registra con @app.before_request usando
# una bandera para que solo corra una vez.
_bd_inicializada = False

@app.before_request
def _inicializar_bd():
    global _bd_inicializada
    if not _bd_inicializada:
        try:
            db.create_all()
            migrar_bd()
            crear_admin()
            _bd_inicializada = True
            logger.info('Base de datos inicializada correctamente.')
        except Exception:
            logger.exception('ERROR al inicializar la base de datos.')


# ── Cifrado en reposo ──────────────────────────────────────────────────────
# NOTA: Render con generateValue produce strings genéricos que NO son claves
# Fernet válidas (requieren exactamente 32 bytes en base64 URL-safe).
# Intentamos usar la clave del entorno; si es inválida, generamos una nueva
# y registramos una advertencia clara.
_fernet_key = os.environ.get('FERNET_KEY')
if _fernet_key:
    try:
        CLAVE_CIFRADO = _fernet_key.encode()
        Fernet(CLAVE_CIFRADO)   # validar antes de usarla
    except Exception:
        logger.warning('FERNET_KEY del entorno es inválida — generando clave en memoria. '
                       'Define FERNET_KEY con: python -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())"')
        CLAVE_CIFRADO = Fernet.generate_key()
else:
    CLAVE_CIFRADO = Fernet.generate_key()
    logger.warning('FERNET_KEY no definida - clave generada en memoria (solo dev)')

cipher_suite = Fernet(CLAVE_CIFRADO)


def encriptar(texto: str) -> str:
    return cipher_suite.encrypt(texto.encode()).decode()


def desencriptar(texto: str) -> str:
    return cipher_suite.decrypt(texto.encode()).decode()


# ── Validacion y sanitizacion ──────────────────────────────────────────────
ROLES_PERMITIDOS = {'paciente', 'doctor'}


def sanitizar(texto: str, max_len: int = 500) -> str:
    if not texto:
        return ''
    texto = texto.strip()
    texto = re.sub(r'[\x00-\x08\x0b-\x0c\x0e-\x1f\x7f]', '', texto)
    return texto[:max_len]


def validar_username(username: str) -> str | None:
    if not username or not (3 <= len(username) <= 50):
        return 'El nombre de usuario debe tener entre 3 y 50 caracteres.'
    if not re.fullmatch(r'[A-Za-z0-9._\-]+', username):
        return 'El usuario solo puede contener letras, numeros, puntos, guiones y guiones bajos.'
    return None


def validar_password(password: str) -> str | None:
    if not password or len(password) < 8:
        return 'La contrasena debe tener al menos 8 caracteres.'
    if not re.search(r'[A-Z]', password):
        return 'La contrasena debe incluir al menos una letra mayuscula.'
    if not re.search(r'[a-z]', password):
        return 'La contrasena debe incluir al menos una letra minuscula.'
    if not re.search(r'\d', password):
        return 'La contrasena debe incluir al menos un numero.'
    if not re.search(r'[!@#$%^&*()\-_=+\[\]{};:\'",./<>?\\|`~]', password):
        return 'La contrasena debe incluir al menos un caracter especial.'
    return None


def validar_fecha(fecha: str) -> str | None:
    try:
        d = date.fromisoformat(fecha)
        hoy    = date.today()
        limite = hoy + timedelta(days=30)
        if d < hoy:
            return 'La fecha no puede ser anterior a hoy.'
        if d > limite:
            return 'Solo puedes agendar con hasta 30 dias de anticipacion.'
    except (ValueError, TypeError):
        return 'Formato de fecha invalido.'
    return None


# ── Modelos ────────────────────────────────────────────────────────────────
class User(UserMixin, db.Model):
    id          = db.Column(db.Integer,     primary_key=True)
    username    = db.Column(db.String(50),  unique=True, nullable=False)
    password    = db.Column(db.String(256), nullable=False)
    role        = db.Column(db.String(20),  nullable=False)
    is_approved = db.Column(db.Boolean,     default=False, nullable=True)
    mfa_secret  = db.Column(db.String(32),  nullable=True)


class Cita(db.Model):
    id                             = db.Column(db.Integer,     primary_key=True)
    paciente_id                    = db.Column(db.Integer,     db.ForeignKey('user.id'))
    doctor_id                      = db.Column(db.Integer,     db.ForeignKey('user.id'), nullable=True)
    fecha                          = db.Column(db.String(10))
    sintomas                       = db.Column(db.Text)
    receta_cifrada                 = db.Column(db.Text,        nullable=True)
    nombre_completo                = db.Column(db.String(150), nullable=True)
    edad                           = db.Column(db.Integer,     nullable=True)
    fecha_nacimiento               = db.Column(db.String(10),  nullable=True)
    genero                         = db.Column(db.String(20),  nullable=True)
    estado_civil                   = db.Column(db.String(30),  nullable=True)
    ocupacion                      = db.Column(db.String(100), nullable=True)
    telefono                       = db.Column(db.String(20),  nullable=True)
    email                          = db.Column(db.String(120), nullable=True)
    curp                           = db.Column(db.String(18),  nullable=True)
    direccion                      = db.Column(db.String(250), nullable=True)
    ciudad                         = db.Column(db.String(100), nullable=True)
    estado                         = db.Column(db.String(50),  nullable=True)
    tipo_consulta                  = db.Column(db.String(50),  nullable=True)
    tipo_sangre                    = db.Column(db.String(5),   nullable=True)
    peso                           = db.Column(db.Float,       nullable=True)
    talla                          = db.Column(db.Integer,     nullable=True)
    seguro_medico                  = db.Column(db.String(50),  nullable=True)
    num_afiliacion                 = db.Column(db.String(30),  nullable=True)
    alergias                       = db.Column(db.Text,        nullable=True)
    medicamentos                   = db.Column(db.Text,        nullable=True)
    antecedentes                   = db.Column(db.Text,        nullable=True)
    contacto_emergencia_nombre     = db.Column(db.String(150), nullable=True)
    contacto_emergencia_parentesco = db.Column(db.String(50),  nullable=True)
    contacto_emergencia_tel        = db.Column(db.String(20),  nullable=True)
    status                         = db.Column(db.String(20),  nullable=False, default='pendiente')


# ── Login Manager ──────────────────────────────────────────────────────────
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'


@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))


# ── Rutas ──────────────────────────────────────────────────────────────────
@app.route('/')
def index():
    return render_template('home.html')


@app.route('/registro', methods=['GET', 'POST'])
def registro():
    if request.method == 'POST':
        try:
            username = sanitizar(request.form.get('username', ''), max_len=50)
            password = request.form.get('password', '')
            role     = sanitizar(request.form.get('role', ''), max_len=20)

            err = validar_username(username)
            if err:
                flash(err)
                return render_template('registro.html', last_username=username, last_role=role)

            err = validar_password(password)
            if err:
                flash(err)
                return render_template('registro.html', last_username=username, last_role=role)

            if role not in ROLES_PERMITIDOS:
                flash('Rol no valido.')
                return render_template('registro.html', last_username=username, last_role=role)

            if User.query.filter_by(username=username).first():
                flash('Ese nombre de usuario ya esta registrado.')
                return render_template('registro.html', last_username=username, last_role=role)

            hashed   = generate_password_hash(password, method='scrypt')
            secret   = pyotp.random_base32()
            approved = (role == 'paciente')

            new_user = User(username=username, password=hashed,
                            role=role, is_approved=approved, mfa_secret=secret)
            db.session.add(new_user)
            db.session.commit()

            logger.info('REGISTRO | usuario="%s" rol="%s"', username, role)
            return redirect(url_for('setup_mfa', user_id=new_user.id))

        except Exception:
            db.session.rollback()
            logger.exception('ERROR en /registro')
            flash('Ocurrio un problema al registrar el usuario. Intentelo de nuevo.')
            return render_template('registro.html',
                                   last_username=request.form.get('username',''),
                                   last_role=request.form.get('role',''))

    return render_template('registro.html')


@app.route('/setup_mfa/<int:user_id>')
def setup_mfa(user_id):
    try:
        user = User.query.get(user_id)
        if not user:
            flash('Usuario no encontrado.')
            return redirect(url_for('registro'))

        uri     = pyotp.totp.TOTP(user.mfa_secret).provisioning_uri(
                      name=user.username, issuer_name='MediSecure')
        img     = qrcode.make(uri)
        buf     = io.BytesIO()
        img.save(buf, format='PNG')
        img_str = base64.b64encode(buf.getvalue()).decode()
        return render_template('mfa_setup.html', qr_image=img_str, secret=user.mfa_secret)

    except Exception:
        logger.exception('ERROR en /setup_mfa/%s', user_id)
        flash('Error al generar el codigo MFA.')
        return redirect(url_for('login'))


@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        try:
            username     = sanitizar(request.form.get('username', ''), max_len=50)
            password     = request.form.get('password', '')
            token        = sanitizar(request.form.get('token', ''), max_len=10)
            user         = User.query.filter_by(username=username).first()
            MSG_GENERICO = 'Credenciales incorrectas o codigo MFA invalido.'

            if not user or not check_password_hash(user.password, password):
                logger.warning('LOGIN FALLIDO (creds) | usuario="%s" ip=%s',
                               username, request.remote_addr)
                flash(MSG_GENERICO)
                return render_template('login.html', last_username=username)

            if not pyotp.TOTP(user.mfa_secret).verify(token):
                logger.warning('LOGIN FALLIDO (MFA) | usuario="%s" ip=%s',
                               username, request.remote_addr)
                flash(MSG_GENERICO)
                return render_template('login.html', last_username=username)

            if user.role == 'doctor' and not user.is_approved:
                flash('Tu cuenta de doctor aun no ha sido aprobada por el administrador.')
                return render_template('login.html', last_username=username)

            session.permanent = True
            login_user(user)
            logger.info('LOGIN OK | usuario="%s" rol="%s" ip=%s',
                        username, user.role, request.remote_addr)
            return redirect(url_for('dashboard'))

        except Exception:
            logger.exception('ERROR en /login')
            flash('Error interno. Intentelo de nuevo.')

    return render_template('login.html')


@app.route('/dashboard')
@login_required
def dashboard():
    try:
        if current_user.role == 'admin':
            doctores = User.query.filter_by(role='doctor', is_approved=False).all()
            return render_template('dashboard_admin.html', doctores=doctores)

        elif current_user.role == 'doctor':
            citas     = Cita.query.all()
            pacientes = {u.id: u.username for u in User.query.filter_by(role='paciente').all()}
            return render_template('dashboard_doctor.html', citas=citas, pacientes=pacientes)

        else:
            _auto_expirar_citas()
            citas     = Cita.query.filter_by(paciente_id=current_user.id).all()
            form_cita = session.pop('form_cita', {})
            hoy       = date.today()
            max_fecha = hoy + timedelta(days=30)
            return render_template('dashboard_paciente.html',
                                   citas=citas, form_cita=form_cita,
                                   today=hoy.isoformat(), max_date=max_fecha.isoformat())

    except Exception:
        logger.exception('ERROR en /dashboard | usuario="%s"', current_user.username)
        flash('Error al cargar el panel. Intentelo de nuevo.')
        return redirect(url_for('login'))


@app.route('/aprobar_doctor/<int:id>')
@login_required
def aprobar_doctor(id):
    try:
        if current_user.role != 'admin':
            logger.warning('ACCESO DENEGADO /aprobar_doctor | usuario="%s"', current_user.username)
            flash('Acceso no autorizado.')
            return redirect(url_for('dashboard'))

        doctor = User.query.get(id)
        if not doctor or doctor.role != 'doctor':
            flash('Doctor no encontrado.')
            return redirect(url_for('dashboard'))

        doctor.is_approved = True
        db.session.commit()
        logger.info('DOCTOR APROBADO | doctor="%s" por admin="%s"',
                    doctor.username, current_user.username)

    except Exception:
        db.session.rollback()
        logger.exception('ERROR al aprobar doctor id=%s', id)
        flash('Error al aprobar el doctor.')

    return redirect(url_for('dashboard'))


def _guardar_form_en_session(form):
    campos = [
        'fecha', 'sintomas', 'tipo_consulta', 'nombre_completo', 'edad',
        'fecha_nacimiento', 'genero', 'estado_civil', 'ocupacion',
        'telefono', 'email', 'curp', 'direccion', 'ciudad', 'estado',
        'tipo_sangre', 'peso', 'talla', 'seguro_medico', 'num_afiliacion',
        'alergias', 'medicamentos', 'antecedentes',
        'contacto_emergencia_nombre', 'contacto_emergencia_parentesco',
        'contacto_emergencia_tel',
    ]
    session['form_cita'] = {c: form.get(c, '') for c in campos}


@app.route('/crear_cita', methods=['POST'])
@login_required
def crear_cita():
    try:
        fecha            = sanitizar(request.form.get('fecha', ''),            max_len=10)
        sintomas         = sanitizar(request.form.get('sintomas', ''),         max_len=500)
        tipo_consulta    = sanitizar(request.form.get('tipo_consulta', ''),    max_len=50)
        nombre_completo  = sanitizar(request.form.get('nombre_completo', ''),  max_len=150)
        edad_raw         = sanitizar(request.form.get('edad', ''),             max_len=3)
        fecha_nacimiento = sanitizar(request.form.get('fecha_nacimiento', ''), max_len=10)
        genero           = sanitizar(request.form.get('genero', ''),           max_len=20)
        estado_civil     = sanitizar(request.form.get('estado_civil', ''),     max_len=30)
        ocupacion        = sanitizar(request.form.get('ocupacion', ''),        max_len=100)
        telefono         = sanitizar(request.form.get('telefono', ''),         max_len=20)
        email            = sanitizar(request.form.get('email', ''),            max_len=120)
        curp             = sanitizar(request.form.get('curp', ''),             max_len=18).upper()
        direccion        = sanitizar(request.form.get('direccion', ''),        max_len=250)
        ciudad           = sanitizar(request.form.get('ciudad', ''),           max_len=100)
        estado           = sanitizar(request.form.get('estado', ''),           max_len=50)
        tipo_sangre      = sanitizar(request.form.get('tipo_sangre', ''),      max_len=5)
        peso_raw         = sanitizar(request.form.get('peso', ''),             max_len=6)
        talla_raw        = sanitizar(request.form.get('talla', ''),            max_len=5)
        seguro_medico    = sanitizar(request.form.get('seguro_medico', ''),    max_len=50)
        num_afiliacion   = sanitizar(request.form.get('num_afiliacion', ''),   max_len=30)
        alergias         = sanitizar(request.form.get('alergias', ''),         max_len=500)
        medicamentos     = sanitizar(request.form.get('medicamentos', ''),     max_len=500)
        antecedentes     = sanitizar(request.form.get('antecedentes', ''),     max_len=500)
        cont_nombre      = sanitizar(request.form.get('contacto_emergencia_nombre', ''),      max_len=150)
        cont_parentesco  = sanitizar(request.form.get('contacto_emergencia_parentesco', ''),  max_len=50)
        cont_tel         = sanitizar(request.form.get('contacto_emergencia_tel', ''),         max_len=20)

        _guardar_form_en_session(request.form)

        err = validar_fecha(fecha)
        if err:
            flash(err)
            return redirect(url_for('dashboard'))

        if not sintomas:
            flash('Debe describir sus sintomas o motivo de consulta.')
            return redirect(url_for('dashboard'))

        if not nombre_completo:
            flash('El nombre completo es obligatorio.')
            return redirect(url_for('dashboard'))

        edad = None
        if edad_raw:
            try:
                edad = int(edad_raw)
                if not (0 <= edad <= 130):
                    flash('Edad fuera de rango valido.')
                    return redirect(url_for('dashboard'))
            except ValueError:
                flash('La edad debe ser un numero entero.')
                return redirect(url_for('dashboard'))

        peso = None
        if peso_raw:
            try:
                peso = float(peso_raw)
            except ValueError:
                peso = None

        talla = None
        if talla_raw:
            try:
                talla = int(talla_raw)
            except ValueError:
                talla = None

        if genero not in ('masculino', 'femenino', 'otro', 'prefiero_no_decir', ''):
            genero = ''

        nueva = Cita(
            paciente_id=current_user.id,
            fecha=fecha, sintomas=sintomas, tipo_consulta=tipo_consulta,
            nombre_completo=nombre_completo, edad=edad,
            fecha_nacimiento=fecha_nacimiento or None,
            genero=genero, estado_civil=estado_civil, ocupacion=ocupacion,
            telefono=telefono, email=email, curp=curp or None,
            direccion=direccion, ciudad=ciudad, estado=estado,
            tipo_sangre=tipo_sangre, peso=peso, talla=talla,
            seguro_medico=seguro_medico, num_afiliacion=num_afiliacion,
            alergias=alergias, medicamentos=medicamentos, antecedentes=antecedentes,
            contacto_emergencia_nombre=cont_nombre,
            contacto_emergencia_parentesco=cont_parentesco,
            contacto_emergencia_tel=cont_tel,
        )
        db.session.add(nueva)
        db.session.commit()
        logger.info('CITA CREADA | paciente="%s" fecha="%s"', current_user.username, fecha)
        session.pop('form_cita', None)
        flash('Solicitud de consulta enviada correctamente.')

    except Exception:
        db.session.rollback()
        logger.exception('ERROR al crear cita | usuario="%s"', current_user.username)
        flash('Error al crear la cita. Intentelo de nuevo.')

    return redirect(url_for('dashboard'))


@app.route('/recetar/<int:cita_id>', methods=['POST'])
@login_required
def recetar(cita_id):
    try:
        if current_user.role != 'doctor':
            logger.warning('ACCESO DENEGADO /recetar | usuario="%s"', current_user.username)
            flash('Acceso no autorizado.')
            return redirect(url_for('dashboard'))

        contenido = sanitizar(request.form.get('receta', ''), max_len=2000)
        if not contenido:
            flash('La receta no puede estar vacia.')
            return redirect(url_for('dashboard'))

        cita = Cita.query.get(cita_id)
        if not cita:
            flash('Cita no encontrada.')
            return redirect(url_for('dashboard'))

        cita.receta_cifrada = encriptar(contenido)
        cita.doctor_id      = current_user.id
        db.session.commit()
        logger.info('RECETA EMITIDA | doctor="%s" cita_id=%s', current_user.username, cita_id)
        flash('Receta cifrada y almacenada con exito.')

    except Exception:
        db.session.rollback()
        logger.exception('ERROR al recetar cita_id=%s', cita_id)
        flash('Error al procesar la receta. Intentelo de nuevo.')

    return redirect(url_for('dashboard'))


@app.route('/ver_receta/<int:cita_id>')
@login_required
def ver_receta(cita_id):
    try:
        cita = Cita.query.get(cita_id)
        if not cita:
            flash('Cita no encontrada.')
            return redirect(url_for('dashboard'))

        if cita.paciente_id != current_user.id and current_user.role != 'doctor':
            logger.warning('ACCESO NO AUTORIZADO a receta | cita_id=%s usuario="%s"',
                           cita_id, current_user.username)
            flash('No tiene permiso para ver esta receta.')
            return redirect(url_for('dashboard'))

        if not cita.receta_cifrada:
            flash('La receta aun no esta disponible.')
            return redirect(url_for('dashboard'))

        texto_receta  = desencriptar(cita.receta_cifrada)
        doctor_nombre = 'sin asignar'
        if cita.doctor_id:
            doc = User.query.get(cita.doctor_id)
            if doc:
                doctor_nombre = doc.username

        logger.info('RECETA VISTA | usuario="%s" cita_id=%s', current_user.username, cita_id)
        return render_template('receta.html', cita=cita,
                               texto_receta=texto_receta, doctor_nombre=doctor_nombre)

    except Exception:
        logger.exception('ERROR al ver receta cita_id=%s', cita_id)
        flash('Error al recuperar la receta.')
        return redirect(url_for('dashboard'))


@app.route('/completar_cita/<int:cita_id>', methods=['POST'])
@login_required
def completar_cita(cita_id):
    try:
        if current_user.role not in ('doctor', 'admin'):
            flash('Acceso no autorizado.')
            return redirect(url_for('dashboard'))

        cita = Cita.query.get(cita_id)
        if not cita:
            flash('Cita no encontrada.')
            return redirect(url_for('dashboard'))

        nuevo_status = sanitizar(request.form.get('nuevo_status', 'completada'), max_len=20)
        if nuevo_status not in ('en_proceso', 'completada', 'cancelada'):
            nuevo_status = 'completada'

        cita.status = nuevo_status
        db.session.commit()
        logger.info('CITA STATUS | cita_id=%s status=%s por doctor=%s',
                    cita_id, nuevo_status, current_user.username)
        flash(f'Cita marcada como {nuevo_status} correctamente.')

    except Exception:
        db.session.rollback()
        logger.exception('ERROR al actualizar status cita_id=%s', cita_id)
        flash('Error al actualizar la cita.')

    return redirect(url_for('dashboard'))


@app.route('/logout')
@login_required
def logout():
    logger.info('LOGOUT | usuario="%s"', current_user.username)
    logout_user()
    session.clear()
    return redirect(url_for('login'))


# ── Helpers internos ───────────────────────────────────────────────────────
def _auto_expirar_citas():
    try:
        limite     = date.today() - timedelta(days=2)
        pendientes = Cita.query.filter(
            Cita.status.in_(['pendiente', 'en_proceso']),
            Cita.receta_cifrada == None
        ).all()
        cambiadas = 0
        for c in pendientes:
            try:
                if date.fromisoformat(c.fecha) < limite:
                    c.status  = 'expirada'
                    cambiadas += 1
            except Exception:
                pass
        if cambiadas:
            db.session.commit()
            logger.info('AUTO-EXPIRAR | %s citas marcadas como expiradas', cambiadas)
    except Exception:
        db.session.rollback()
        logger.exception('ERROR en _auto_expirar_citas')


def migrar_bd():
    from sqlalchemy import inspect, text
    inspector = inspect(db.engine)
    cols_user = [c['name'] for c in inspector.get_columns('user')]

    for col, ddl in [
        ('mfa_secret',  'ALTER TABLE user ADD COLUMN mfa_secret VARCHAR(32)'),
        ('is_approved', 'ALTER TABLE user ADD COLUMN is_approved BOOLEAN DEFAULT 0'),
    ]:
        if col not in cols_user:
            with db.engine.connect() as conn:
                conn.execute(text(ddl))
                conn.commit()

    try:
        cols_cita   = [c['name'] for c in inspector.get_columns('cita')]
        nuevas_cols = {
            'nombre_completo':               'VARCHAR(150)',
            'edad':                          'INTEGER',
            'fecha_nacimiento':              'VARCHAR(10)',
            'genero':                        'VARCHAR(20)',
            'estado_civil':                  'VARCHAR(30)',
            'ocupacion':                     'VARCHAR(100)',
            'telefono':                      'VARCHAR(20)',
            'email':                         'VARCHAR(120)',
            'curp':                          'VARCHAR(18)',
            'direccion':                     'VARCHAR(250)',
            'ciudad':                        'VARCHAR(100)',
            'estado':                        'VARCHAR(50)',
            'tipo_consulta':                 'VARCHAR(50)',
            'tipo_sangre':                   'VARCHAR(5)',
            'peso':                          'FLOAT',
            'talla':                         'INTEGER',
            'seguro_medico':                 'VARCHAR(50)',
            'num_afiliacion':                'VARCHAR(30)',
            'alergias':                      'TEXT',
            'medicamentos':                  'TEXT',
            'antecedentes':                  'TEXT',
            'contacto_emergencia_nombre':    'VARCHAR(150)',
            'contacto_emergencia_parentesco':'VARCHAR(50)',
            'contacto_emergencia_tel':       'VARCHAR(20)',
            'status':                        'VARCHAR(20) DEFAULT "pendiente"',
        }
        for col, tipo in nuevas_cols.items():
            if col not in cols_cita:
                with db.engine.connect() as conn:
                    conn.execute(text(f'ALTER TABLE cita ADD COLUMN {col} {tipo}'))
                    conn.commit()
    except Exception:
        pass

    sin_mfa = User.query.filter(
        (User.mfa_secret == None) | (User.mfa_secret == '')).all()
    for u in sin_mfa:
        if u.username != 'admin':
            u.mfa_secret  = pyotp.random_base32()
            u.is_approved = True
    if sin_mfa:
        db.session.commit()


def crear_admin():
    admin = User.query.filter_by(username='admin').first()
    if not admin:
        db.session.add(User(
            username='admin',
            password=generate_password_hash('Admin@Hospital1!', method='scrypt'),
            role='admin',
            is_approved=True,
            mfa_secret='JBSWY3DPEHPK3PXP',
        ))
        db.session.commit()
        print('\n' + '='*52)
        print('  ADMIN CREADO')
        print('  Usuario  : admin')
        print('  Password : Admin@Hospital1!')
        print('  MFA      : JBSWY3DPEHPK3PXP')
        print('='*52 + '\n')
    elif not admin.mfa_secret:
        admin.mfa_secret  = 'JBSWY3DPEHPK3PXP'
        admin.is_approved = True
        db.session.commit()


# ── Arranque ───────────────────────────────────────────────────────────────
if __name__ == '__main__':
    with app.app_context():
        db.create_all()
        migrar_bd()
        crear_admin()

    import socket
    hostname = socket.gethostname()
    try:
        local_ip = socket.gethostbyname(hostname)
    except Exception:
        local_ip = '127.0.0.1'

    print(f'\n{"="*52}')
    print('  MEDISECURE — SERVIDOR INICIADO')
    print(f'{"="*52}')
    print(f'  Local   : http://127.0.0.1:5000')
    print(f'  Red LAN : http://{local_ip}:5000')
    print(f'{"="*52}\n')

    app.run(
        host='0.0.0.0',
        port=5000,
        debug=os.environ.get('FLASK_DEBUG', 'false').lower() == 'true',
    )
