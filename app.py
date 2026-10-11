import os
import secrets
from datetime import datetime
from functools import wraps
from io import BytesIO
from pathlib import Path
from werkzeug.utils import secure_filename

import qrcode
from flask import (
    Flask, render_template, request, redirect, url_for,
    session, flash, abort, send_file
)
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy import inspect, text
from werkzeug.security import generate_password_hash, check_password_hash


# ============================================================
# APP CONFIGURATION
# ============================================================

app = Flask(__name__)

app.config["SECRET_KEY"] = os.environ.get("SECRET_KEY")
if not app.config["SECRET_KEY"]:
    raise RuntimeError("SECRET_KEY environment variable is not set")

database_url = os.environ.get(
    "DATABASE_URL",
    "sqlite:///medical_qr.db"
)

if database_url.startswith("postgres://"):
    database_url = database_url.replace(
        "postgres://", "postgresql://", 1
    )

app.config["SQLALCHEMY_DATABASE_URI"] = database_url
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False

# Maximum request size: 10 MB
app.config["MAX_CONTENT_LENGTH"] = 10 * 1024 * 1024

db = SQLAlchemy(app)

ALLOWED_EXTENSIONS = {"pdf", "jpg", "jpeg", "png"}

RECORD_TYPES = [
    "blood_test",
    "ct_scan",
    "mri_scan",
    "prescription",
    "certificate",
    "other",
]

EDITABLE_FIELDS = [
    "name", "age", "weight", "blood_group", "allergies",
    "conditions", "medications", "emergency_contact",
    "emergency_phone", "private_notes",
]


# ============================================================
# DATABASE MODELS
# ============================================================

class Patient(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    patient_id = db.Column(db.String(32), unique=True,
                           nullable=False, index=True)
    name = db.Column(db.String(120), nullable=False)
    age = db.Column(db.Integer, nullable=True)
    weight = db.Column(db.String(30), nullable=True)
    blood_group = db.Column(db.String(10), nullable=True)
    allergies = db.Column(db.Text, nullable=True)
    conditions = db.Column(db.Text, nullable=True)
    medications = db.Column(db.Text, nullable=True)
    emergency_contact = db.Column(db.String(120), nullable=True)
    emergency_phone = db.Column(db.String(40), nullable=True)
    private_notes = db.Column(db.Text, nullable=True)
    password_hash = db.Column(db.String(255), nullable=False)
    qr_token = db.Column(db.String(64), unique=True,
                         nullable=False, index=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)


class Doctor(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    doctor_id = db.Column(db.String(32), unique=True,
                          nullable=False, index=True)
    name = db.Column(db.String(120), nullable=False)
    hospital = db.Column(db.String(160), nullable=True)
    password_hash = db.Column(db.String(255), nullable=False)


class DoctorPatient(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    doctor_id = db.Column(db.Integer,
                          db.ForeignKey("doctor.id"), nullable=False)
    patient_id = db.Column(db.Integer,
                           db.ForeignKey("patient.id"), nullable=False)
    status = db.Column(db.String(20), default="active", nullable=False)

    doctor = db.relationship("Doctor")
    patient = db.relationship("Patient")


class ChangeRequest(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    patient_id = db.Column(db.Integer,
                            db.ForeignKey("patient.id"), nullable=False)
    requested_by_type = db.Column(db.String(20), nullable=False)
    requested_by_id = db.Column(db.Integer, nullable=False)
    field_name = db.Column(db.String(80), nullable=False)
    old_value = db.Column(db.Text, nullable=True)
    new_value = db.Column(db.Text, nullable=True)
    reason = db.Column(db.Text, nullable=True)
    status = db.Column(db.String(20), default="pending", nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    reviewed_at = db.Column(db.DateTime, nullable=True)

    patient = db.relationship("Patient")


class AuditLog(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    patient_id = db.Column(db.Integer,
                           db.ForeignKey("patient.id"), nullable=False)
    actor_type = db.Column(db.String(20), nullable=False)
    actor_id = db.Column(db.Integer, nullable=True)
    action = db.Column(db.String(120), nullable=False)
    details = db.Column(db.Text, nullable=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    patient = db.relationship("Patient")


class MedicalRecord(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    patient_id = db.Column(db.Integer,
                           db.ForeignKey("patient.id"), nullable=False)
    record_type = db.Column(db.String(50), nullable=False)
    title = db.Column(db.String(200), nullable=False)
    record_date = db.Column(db.String(30), nullable=True)
    description = db.Column(db.Text, nullable=True)

    # Uploaded document fields
    original_filename = db.Column(db.String(255), nullable=True)
    mime_type = db.Column(db.String(100), nullable=True)
    file_size = db.Column(db.Integer, nullable=True)
    file_data = db.Column(db.LargeBinary, nullable=True)

    patient = db.relationship("Patient")


# ============================================================
# DATABASE UPGRADE
# Adds file columns to an existing medical_record table.
# Does not delete existing patients, doctors, or records.
# ============================================================

def ensure_medical_record_columns():
    inspector = inspect(db.engine)

    if "medical_record" not in inspector.get_table_names():
        return

    existing_columns = {
        column["name"]
        for column in inspector.get_columns("medical_record")
    }

    dialect = db.engine.dialect.name
    binary_type = "BYTEA" if dialect == "postgresql" else "BLOB"

    additions = {
        "original_filename": "VARCHAR(255)",
        "mime_type": "VARCHAR(100)",
        "file_size": "INTEGER",
        "file_data": binary_type,
    }

    with db.engine.begin() as connection:
        for column_name, column_type in additions.items():
            if column_name not in existing_columns:
                connection.execute(text(
                    f"ALTER TABLE medical_record "
                    f"ADD COLUMN {column_name} {column_type}"
                ))


# ============================================================
# HELPER FUNCTIONS
# ============================================================

def current_patient():
    if session.get("role") != "patient":
        return None
    return db.session.get(Patient, session.get("user_id"))


def current_doctor():
    if session.get("role") != "doctor":
        return None
    return db.session.get(Doctor, session.get("user_id"))


def login_required(role=None):
    def decorator(fn):
        @wraps(fn)
        def wrapper(*args, **kwargs):
            if not session.get("user_id"):
                return redirect(url_for(
                    "login", role=role or "patient"
                ))

            if role and session.get("role") != role:
                abort(403)

            return fn(*args, **kwargs)
        return wrapper
    return decorator


def is_linked(doctor, patient):
    return DoctorPatient.query.filter_by(
        doctor_id=doctor.id,
        patient_id=patient.id,
        status="active"
    ).first() is not None


def add_audit(patient, actor_type, actor_id, action, details=""):
    db.session.add(AuditLog(
        patient_id=patient.id,
        actor_type=actor_type,
        actor_id=actor_id,
        action=action,
        details=details
    ))


def generate_patient_id():
    patients = Patient.query.all()
    highest = 1000

    for patient in patients:
        if patient.patient_id.startswith("P"):
            try:
                highest = max(
                    highest, int(patient.patient_id[1:])
                )
            except ValueError:
                pass

    return f"P{highest + 1}"


def generate_doctor_id():
    doctors = Doctor.query.all()
    highest = 1000

    for doctor in doctors:
        if doctor.doctor_id.startswith("D"):
            try:
                highest = max(
                    highest, int(doctor.doctor_id[1:])
                )
            except ValueError:
                pass

    return f"D{highest + 1}"


def records_patient_for_token(token):
    patient = Patient.query.filter_by(qr_token=token).first_or_404()

    if session.get("records_patient_id") != patient.id:
        abort(403)

    return patient


def allowed_file(filename):
    return (
        "." in filename
        and filename.rsplit(".", 1)[1].lower() in ALLOWED_EXTENSIONS
    )


# ============================================================
# GLOBAL TEMPLATE VARIABLES
# ============================================================

@app.context_processor
def inject_globals():
    return {
        "session_role": session.get("role"),
        "session_name": session.get("name")
    }


# ============================================================
# HOME AND EMERGENCY QR
# ============================================================

@app.route("/")
def index():
    return render_template("index.html")


@app.route("/emergency/<token>")
def emergency(token):
    patient = Patient.query.filter_by(qr_token=token).first_or_404()

    add_audit(patient, "public", None,
              "Emergency profile viewed", "QR profile")
    db.session.commit()

    return render_template("emergency.html", patient=patient)


@app.route("/qr/<token>.png")
def qr_png(token):
    patient = Patient.query.filter_by(qr_token=token).first_or_404()

    target = url_for(
        "emergency", token=patient.qr_token, _external=True
    )

    image = qrcode.make(target)
    buffer = BytesIO()
    image.save(buffer, format="PNG")
    buffer.seek(0)

    return send_file(buffer, mimetype="image/png")


# ============================================================
# REGISTRATION
# ============================================================

@app.route("/register/<role>", methods=["GET", "POST"])
def register(role):
    if role not in ("patient", "doctor"):
        abort(404)

    if request.method == "POST":
        name = request.form.get("name", "").strip()
        password = request.form.get("password", "")

        if not name or not password:
            flash("Name and password are required.", "error")
            return redirect(url_for("register", role=role))

        if role == "patient":
            age_value = request.form.get("age", "").strip()
            age = None

            if age_value:
                try:
                    age = int(age_value)
                    if age < 0:
                        raise ValueError
                except ValueError:
                    flash("Age must be a valid number.", "error")
                    return redirect(url_for("register", role=role))

            patient = Patient(
                patient_id=generate_patient_id(),
                name=name,
                age=age,
                weight=request.form.get("weight", "").strip(),
                blood_group=request.form.get("blood_group", "").strip(),
                allergies=request.form.get("allergies", "").strip(),
                conditions=request.form.get("conditions", "").strip(),
                medications=request.form.get("medications", "").strip(),
                emergency_contact=request.form.get(
                    "emergency_contact", ""
                ).strip(),
                emergency_phone=request.form.get(
                    "emergency_phone", ""
                ).strip(),
                private_notes=request.form.get(
                    "private_notes", ""
                ).strip(),
                password_hash=generate_password_hash(password),
                qr_token=secrets.token_urlsafe(32)
            )

            db.session.add(patient)
            db.session.commit()

            flash(
                f"Registration successful! Your Patient ID is "
                f"{patient.patient_id}",
                "success"
            )
            return redirect(url_for("login", role="patient"))

        doctor = Doctor(
            doctor_id=generate_doctor_id(),
            name=name,
            hospital=request.form.get("hospital", "").strip(),
            password_hash=generate_password_hash(password)
        )

        db.session.add(doctor)
        db.session.commit()

        flash(
            f"Registration successful! Your Doctor ID is "
            f"{doctor.doctor_id}",
            "success"
        )
        return redirect(url_for("login", role="doctor"))

    return render_template("register.html", role=role)


# ============================================================
# LOGIN AND LOGOUT
# ============================================================

@app.route("/login/<role>", methods=["GET", "POST"])
def login(role):
    if role not in ("patient", "doctor"):
        abort(404)

    if request.method == "POST":
        identifier = request.form.get("identifier", "").strip()
        password = request.form.get("password", "")

        if role == "patient":
            user = Patient.query.filter_by(
                patient_id=identifier
            ).first()
        else:
            user = Doctor.query.filter_by(
                doctor_id=identifier
            ).first()

        if user and check_password_hash(user.password_hash, password):
            session.clear()
            session["user_id"] = user.id
            session["role"] = role
            session["name"] = user.name

            if role == "patient":
                return redirect(url_for("patient_dashboard"))
            return redirect(url_for("doctor_dashboard"))

        flash("Invalid ID or password.", "error")

    return render_template("login.html", role=role)


@app.post("/logout")
def logout():
    session.clear()
    return redirect(url_for("index"))


# ============================================================
# PATIENT DASHBOARD
# ============================================================

@app.route("/patient/dashboard")
@login_required("patient")
def patient_dashboard():
    patient = current_patient()

    incoming = ChangeRequest.query.filter_by(
        patient_id=patient.id,
        status="pending"
    ).order_by(ChangeRequest.created_at.desc()).all()

    outgoing = ChangeRequest.query.filter_by(
        patient_id=patient.id,
        requested_by_type="patient"
    ).order_by(ChangeRequest.created_at.desc()).limit(10).all()

    links = DoctorPatient.query.filter_by(
        patient_id=patient.id,
        status="active"
    ).all()

    pending_doctor_links = DoctorPatient.query.filter_by(
        patient_id=patient.id,
        status="pending"
    ).all()

    return render_template(
        "patient_dashboard.html",
        patient=patient,
        incoming=incoming,
        outgoing=outgoing,
        links=links,
        pending_doctor_links=pending_doctor_links
    )


# ============================================================
# DOCTOR DASHBOARD
# ============================================================

@app.route("/doctor/dashboard")
@login_required("doctor")
def doctor_dashboard():
    doctor = current_doctor()

    links = DoctorPatient.query.filter_by(
        doctor_id=doctor.id,
        status="active"
    ).all()

    pending_links = DoctorPatient.query.filter_by(
        doctor_id=doctor.id,
        status="pending"
    ).all()

    patient_ids = [link.patient_id for link in links]

    if patient_ids:
        pending = ChangeRequest.query.filter(
            ChangeRequest.patient_id.in_(patient_ids),
            ChangeRequest.status == "pending",
            ChangeRequest.requested_by_type == "patient"
        ).order_by(ChangeRequest.created_at.desc()).all()
    else:
        pending = []

    return render_template(
        "doctor_dashboard.html",
        doctor=doctor,
        links=links,
        pending=pending,
        pending_links=pending_links
    )


# ============================================================
# PATIENT REQUESTS DOCTOR LINK
# ============================================================

@app.post("/patient/request-doctor")
@login_required("patient")
def patient_request_doctor():
    patient = current_patient()

    doctor_id = request.form.get("doctor_id", "").strip()
    doctor = Doctor.query.filter_by(doctor_id=doctor_id).first()

    if not doctor:
        flash("Doctor ID not found.", "error")
        return redirect(url_for("patient_dashboard"))

    existing = DoctorPatient.query.filter_by(
        doctor_id=doctor.id,
        patient_id=patient.id
    ).first()

    if existing:
        if existing.status == "active":
            flash("You are already linked with this doctor.", "error")
            return redirect(url_for("patient_dashboard"))

        if existing.status == "pending":
            flash("A link request is already pending.", "error")
            return redirect(url_for("patient_dashboard"))

        existing.status = "pending"
    else:
        db.session.add(DoctorPatient(
            doctor_id=doctor.id,
            patient_id=patient.id,
            status="pending"
        ))

    add_audit(
        patient, "patient", patient.id,
        "Doctor link requested", doctor.doctor_id
    )
    db.session.commit()

    flash("Doctor link request sent.", "success")
    return redirect(url_for("patient_dashboard"))


# ============================================================
# DOCTOR ACCEPTS OR REJECTS PATIENT LINK
# ============================================================

@app.post("/doctor/link/<int:link_id>/<action>")
@login_required("doctor")
def doctor_link_action(link_id, action):
    doctor = current_doctor()
    link = db.session.get(DoctorPatient, link_id)

    if not link or link.doctor_id != doctor.id:
        abort(403)

    if link.status != "pending":
        flash("This request has already been processed.", "error")
        return redirect(url_for("doctor_dashboard"))

    if action == "accept":
        link.status = "active"
        message = "Patient link approved."
        audit_action = "Doctor-patient link approved"
    elif action == "reject":
        link.status = "rejected"
        message = "Patient link rejected."
        audit_action = "Doctor-patient link rejected"
    else:
        abort(400)

    add_audit(
        link.patient, "doctor", doctor.id,
        audit_action, doctor.doctor_id
    )
    db.session.commit()

    flash(message, "success")
    return redirect(url_for("doctor_dashboard"))


# ============================================================
# REQUEST MEDICAL DATA CHANGES
# ============================================================

@app.post("/patient/request-change")
@login_required("patient")
def patient_request_change():
    patient = current_patient()
    field = request.form.get("field_name")
    new_value = request.form.get("new_value", "").strip()
    reason = request.form.get("reason", "").strip()

    if field not in EDITABLE_FIELDS:
        abort(400)

    old_value = getattr(patient, field)

    db.session.add(ChangeRequest(
        patient_id=patient.id,
        requested_by_type="patient",
        requested_by_id=patient.id,
        field_name=field,
        old_value=str(old_value or ""),
        new_value=new_value,
        reason=reason
    ))

    add_audit(
        patient, "patient", patient.id,
        "Change requested", field
    )
    db.session.commit()

    flash("Change request submitted for doctor approval.", "success")
    return redirect(url_for("patient_dashboard"))


@app.post("/doctor/request-change")
@login_required("doctor")
def doctor_request_change():
    doctor = current_doctor()

    try:
        patient_pk = int(request.form.get("patient_pk", 0))
    except ValueError:
        abort(400)

    patient = db.session.get(Patient, patient_pk)
    field = request.form.get("field_name")
    new_value = request.form.get("new_value", "").strip()
    reason = request.form.get("reason", "").strip()

    if not patient or field not in EDITABLE_FIELDS:
        abort(400)

    if not is_linked(doctor, patient):
        abort(403)

    old_value = getattr(patient, field)

    db.session.add(ChangeRequest(
        patient_id=patient.id,
        requested_by_type="doctor",
        requested_by_id=doctor.id,
        field_name=field,
        old_value=str(old_value or ""),
        new_value=new_value,
        reason=reason
    ))

    add_audit(
        patient, "doctor", doctor.id,
        "Change requested", field
    )
    db.session.commit()

    flash("Change request submitted for patient approval.", "success")
    return redirect(url_for("doctor_dashboard"))


# ============================================================
# APPROVE OR REJECT CHANGE REQUEST
# ============================================================

def authorize_change_review(change_request):
    actor_type = session.get("role")
    actor_id = session.get("user_id")

    if actor_type == change_request.requested_by_type:
        abort(403)

    if actor_type == "patient":
        if actor_id != change_request.patient_id:
            abort(403)

    elif actor_type == "doctor":
        doctor = db.session.get(Doctor, actor_id)

        if not doctor or not is_linked(
            doctor, change_request.patient
        ):
            abort(403)
    else:
        abort(403)

    return actor_type, actor_id


@app.post("/change/<int:request_id>/approve")
@login_required()
def approve_change(request_id):
    change_request = db.session.get(ChangeRequest, request_id)

    if not change_request or change_request.status != "pending":
        abort(404)

    actor_type, actor_id = authorize_change_review(change_request)

    if change_request.field_name == "age":
        try:
            change_request.patient.age = int(change_request.new_value)
        except (ValueError, TypeError):
            abort(400)
    else:
        setattr(
            change_request.patient,
            change_request.field_name,
            change_request.new_value
        )

    change_request.status = "approved"
    change_request.reviewed_at = datetime.utcnow()

    add_audit(
        change_request.patient, actor_type, actor_id,
        "Change approved", change_request.field_name
    )
    db.session.commit()

    flash("Change approved and applied.", "success")
    return redirect(request.referrer or url_for("index"))


@app.post("/change/<int:request_id>/reject")
@login_required()
def reject_change(request_id):
    change_request = db.session.get(ChangeRequest, request_id)

    if not change_request or change_request.status != "pending":
        abort(404)

    actor_type, actor_id = authorize_change_review(change_request)

    change_request.status = "rejected"
    change_request.reviewed_at = datetime.utcnow()

    add_audit(
        change_request.patient, actor_type, actor_id,
        "Change rejected", change_request.field_name
    )
    db.session.commit()

    flash("Change rejected.", "success")
    return redirect(request.referrer or url_for("index"))


# ============================================================
# DOCTOR VIEW OF LINKED PATIENT
# ============================================================

@app.route("/doctor/patient/<int:patient_pk>")
@login_required("doctor")
def doctor_patient(patient_pk):
    doctor = current_doctor()
    patient = db.session.get(Patient, patient_pk)

    if not patient or not is_linked(doctor, patient):
        abort(403)

    changes = ChangeRequest.query.filter_by(
        patient_id=patient.id
    ).order_by(ChangeRequest.created_at.desc()).all()

    logs = AuditLog.query.filter_by(
        patient_id=patient.id
    ).order_by(AuditLog.created_at.desc()).limit(30).all()

    return render_template(
        "doctor_patient.html",
        patient=patient,
        changes=changes,
        logs=logs
    )


@app.route("/patient/qr")
@login_required("patient")
def patient_qr():
    return render_template(
        "patient_qr.html",
        patient=current_patient()
    )


# ============================================================
# MEDICAL RECORD LOGIN
# ============================================================

@app.route("/medical-records/<token>", methods=["GET", "POST"])
def medical_records_login(token):
    patient = Patient.query.filter_by(qr_token=token).first_or_404()

    if request.method == "POST":
        identifier = request.form.get("identifier", "").strip()
        password = request.form.get("password", "")

        patient_user = Patient.query.filter_by(
            patient_id=identifier
        ).first()

        if patient_user and check_password_hash(
            patient_user.password_hash, password
        ):
            if patient_user.id != patient.id:
                flash(
                    "You can only access your own medical records.",
                    "error"
                )
                return redirect(url_for(
                    "medical_records_login", token=token
                ))

            session["records_patient_id"] = patient.id
            session["records_access"] = "patient"
            session.pop("records_doctor_id", None)

            add_audit(
                patient, "patient", patient_user.id,
                "Medical records accessed", "Patient authentication"
            )
            db.session.commit()

            return redirect(url_for("medical_records", token=token))

        doctor = Doctor.query.filter_by(
            doctor_id=identifier
        ).first()

        if doctor and check_password_hash(
            doctor.password_hash, password
        ):
            # This preserves the original emergency-access behavior:
            # any authenticated doctor may access this token's records.
            session["records_patient_id"] = patient.id
            session["records_access"] = "doctor"
            session["records_doctor_id"] = doctor.id

            add_audit(
                patient, "doctor", doctor.id,
                "Medical records accessed", "Doctor emergency access"
            )
            db.session.commit()

            return redirect(url_for("medical_records", token=token))

        flash("Invalid ID or password.", "error")

    return render_template("records_login.html", patient=patient)


# ============================================================
# MEDICAL RECORDS PAGE
# ============================================================

@app.route("/medical-records/<token>/view")
def medical_records(token):
    patient = records_patient_for_token(token)

    records = MedicalRecord.query.filter_by(
        patient_id=patient.id
    ).order_by(MedicalRecord.id.desc()).all()

    return render_template(
        "medical_records.html",
        patient=patient,
        records=records,
        record_types=RECORD_TYPES,
        access_type=session.get("records_access")
    )


# ============================================================
# UPLOAD MEDICAL RECORD
# Form fields: record_type, title, record_date, description, file
# ============================================================

@app.post("/medical-records/<token>/upload")
def upload_medical_record(token):
    patient = records_patient_for_token(token)

    uploaded_file = request.files.get("file")

    if not uploaded_file or not uploaded_file.filename:
        flash("Please choose a file to upload.", "error")
        return redirect(url_for("medical_records", token=token))

    safe_filename = secure_filename(uploaded_file.filename)

    if not safe_filename or not allowed_file(safe_filename):
        flash(
            "Only PDF, JPG, JPEG, and PNG files are allowed.",
            "error"
        )
        return redirect(url_for("medical_records", token=token))

    file_data = uploaded_file.read(10 * 1024 * 1024 + 1)

    if not file_data:
        flash("The selected file is empty.", "error")
        return redirect(url_for("medical_records", token=token))

    if len(file_data) > 10 * 1024 * 1024:
        flash("The file exceeds the 10 MB limit.", "error")
        return redirect(url_for("medical_records", token=token))

    record_type = request.form.get("record_type", "other").strip()
    if record_type not in RECORD_TYPES:
        record_type = "other"

    title = request.form.get("title", "").strip()
    if not title:
        title = Path(safe_filename).stem[:200] or "Medical document"

    record_date = request.form.get("record_date", "").strip()
    description = request.form.get("description", "").strip()

    # Do not trust the browser's supplied MIME type alone.
    extension = safe_filename.rsplit(".", 1)[1].lower()
    mime_types = {
        "pdf": "application/pdf",
        "jpg": "image/jpeg",
        "jpeg": "image/jpeg",
        "png": "image/png",
    }
    mime_type = mime_types[extension]

    # Basic file-signature checks to reject obvious extension mismatches.
    if extension == "pdf" and not file_data.startswith(b"%PDF-"):
        flash("The selected file does not appear to be a valid PDF.", "error")
        return redirect(url_for("medical_records", token=token))

    if extension in ("jpg", "jpeg") and not file_data.startswith(b"\xff\xd8\xff"):
        flash("The selected file does not appear to be a valid JPEG image.", "error")
        return redirect(url_for("medical_records", token=token))

    if extension == "png" and not file_data.startswith(b"\x89PNG\r\n\x1a\n"):
        flash("The selected file does not appear to be a valid PNG image.", "error")
        return redirect(url_for("medical_records", token=token))

    record = MedicalRecord(
        patient_id=patient.id,
        record_type=record_type,
        title=title,
        record_date=record_date or None,
        description=description or None,
        original_filename=safe_filename,
        mime_type=mime_type,
        file_size=len(file_data),
        file_data=file_data
    )

    db.session.add(record)

    actor_type = session.get("records_access", "patient")
    if actor_type == "doctor":
        actor_id = session.get("records_doctor_id")
    else:
        actor_id = patient.id

    add_audit(
        patient, actor_type, actor_id,
        "Medical document uploaded",
        safe_filename
    )

    db.session.commit()

    flash("Medical document uploaded successfully.", "success")
    return redirect(url_for("medical_records", token=token))


# ============================================================
# DOWNLOAD MEDICAL RECORD
# ============================================================

@app.route("/medical-records/<token>/download/<int:record_id>")
def download_medical_record(token, record_id):
    patient = records_patient_for_token(token)

    record = db.session.get(MedicalRecord, record_id)

    if not record or record.patient_id != patient.id:
        abort(404)

    if not record.file_data or not record.original_filename:
        flash("This record does not have an uploaded file.", "error")
        return redirect(url_for("medical_records", token=token))

    actor_type = session.get("records_access", "patient")
    actor_id = (
        session.get("records_doctor_id")
        if actor_type == "doctor"
        else patient.id
    )

    add_audit(
        patient, actor_type, actor_id,
        "Medical document downloaded",
        record.original_filename
    )
    db.session.commit()

    return send_file(
        BytesIO(record.file_data),
        mimetype=record.mime_type or "application/octet-stream",
        as_attachment=True,
        download_name=record.original_filename
    )


# ============================================================
# MEDICAL RECORD LOGOUT
# ============================================================

@app.post("/medical-records/<token>/logout")
def medical_records_logout(token):
    patient = Patient.query.filter_by(qr_token=token).first_or_404()

    if session.get("records_patient_id") == patient.id:
        session.pop("records_patient_id", None)
        session.pop("records_access", None)
        session.pop("records_doctor_id", None)

    return redirect(url_for("emergency", token=token))


# ============================================================
# DEMO DATA
# ============================================================

def seed_demo():
    if Patient.query.count() == 0:
        patient = Patient(
            patient_id="P1001",
            name="Demo Patient",
            age=24,
            weight="68 kg",
            blood_group="O+",
            allergies="Penicillin",
            conditions="Asthma",
            medications="Inhaler (as prescribed)",
            emergency_contact="Demo Emergency Contact",
            emergency_phone="0000000000",
            private_notes="DEMO DATA ONLY",
            password_hash=generate_password_hash("Patient@123"),
            qr_token=secrets.token_urlsafe(32)
        )

        doctor = Doctor(
            doctor_id="D1001",
            name="Dr. Demo",
            hospital="Demo Hospital",
            password_hash=generate_password_hash("Doctor@123")
        )

        db.session.add_all([patient, doctor])
        db.session.flush()

        db.session.add(DoctorPatient(
            doctor_id=doctor.id,
            patient_id=patient.id,
            status="active"
        ))

        db.session.commit()


# ============================================================
# DATABASE INITIALIZATION
# ============================================================

with app.app_context():
    db.create_all()
    ensure_medical_record_columns()
    seed_demo()


# ============================================================
# LOCAL DEVELOPMENT
# ============================================================

if __name__ == "__main__":
    app.run(
        host="0.0.0.0",
        port=int(os.environ.get("PORT", 5000)),
        debug=False
    )
