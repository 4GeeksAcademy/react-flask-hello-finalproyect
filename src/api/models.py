from flask_sqlalchemy import SQLAlchemy
from datetime import datetime, timezone

db = SQLAlchemy()

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    firstname = db.Column(db.String(80), nullable=False)
    lastname = db.Column(db.String(80), nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password = db.Column(db.String(180), unique=False, nullable=False)
    salt = db.Column(db.String(180), nullable=False)
    avatar = db.Column(db.String(100), nullable=False, default="https://i.pravatar.cc/300")
    public_id_avatar = db.Column(db.String(100), nullable=True)
    is_admin = db.Column(db.Boolean, default=False)
    created_at = db.Column(db.DateTime, nullable=False, default=datetime.now(timezone.utc))
    update_at = db.Column(db.DateTime, nullable=False, default=datetime.now(timezone.utc), onupdate=datetime.now(timezone.utc))
    
    # Relaciones
    forms_filled = db.relationship('FormResponse', back_populates='user')

    def __repr__(self):
        return f'<User {self.email}>'

    def serialize(self):
        return {
            "id": self.id,
            "email": self.email,
            "firstname": self.firstname,
            "lastname": self.lastname,
            "is_admin": self.is_admin
        }

class Space(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    description = db.Column(db.Text, nullable=True)
    created_at = db.Column(db.DateTime, nullable=False, default=datetime.now(timezone.utc))
    update_at = db.Column(db.DateTime, nullable=False, default=datetime.now(timezone.utc), onupdate=datetime.now(timezone.utc))

    # Relaciones
    form_responses = db.relationship('FormResponse', back_populates='space')

    def __repr__(self):
        return f'<Space {self.name}>'

    def serialize(self):
        return {
            "id": self.id,
            "name": self.name,
            "description": self.description
        }

class Form(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(100), nullable=False)
    description = db.Column(db.Text, nullable=True)
    structure = db.Column(db.JSON, nullable=False)  # Almacena la estructura del formulario
    created_at = db.Column(db.DateTime, nullable=False, default=datetime.now(timezone.utc))
    update_at = db.Column(db.DateTime, nullable=False, default=datetime.now(timezone.utc), onupdate=datetime.now(timezone.utc))

    # Relaciones
    responses = db.relationship('FormResponse', back_populates='form')

    def __repr__(self):
        return f'<Form {self.title}>'

    def serialize(self):
        return {
            "id": self.id,
            "title": self.title,
            "description": self.description,
            "structure": self.structure
        }

class FormResponse(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    form_id = db.Column(db.Integer, db.ForeignKey('form.id'), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    space_id = db.Column(db.Integer, db.ForeignKey('space.id'), nullable=False)
    response_data = db.Column(db.JSON, nullable=False)
    created_at = db.Column(db.DateTime, nullable=False, default=datetime.now(timezone.utc))

    # Relaciones
    form = db.relationship('Form', back_populates='responses')
    user = db.relationship('User', back_populates='forms_filled')
    space = db.relationship('Space', back_populates='form_responses')

    def __repr__(self):
        return f'<FormResponse {self.id}>'

    def serialize(self):
        return {
            "id": self.id,
            "form_id": self.form_id,
            "user_id": self.user_id,
            "space_id": self.space_id,
            "response_data": self.response_data,
            "created_at": self.created_at
        }