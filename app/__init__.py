from flask import Flask
from config import Config
from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate
from flask_login import LoginManager
from flask_cors import CORS
from celery import Celery

db = SQLAlchemy()
migrate = Migrate()
login = LoginManager()
cors = CORS()

celery = Celery(__name__, broker=Config.CELERY_BROKER_URL)

def create_app(config_class=Config):
    app = Flask(__name__)
    app.config.from_object(config_class)

    db.init_app(app)
    migrate.init_app(app, db)
    login.init_app(app)
    cors.init_app(app)

    celery.conf.update(app.config)

    from app.routes import bp as main_bp
    app.register_blueprint(main_bp, url_prefix='/api')

    return app