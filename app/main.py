from flasgger import Swagger
from dotenv import load_dotenv
from pathlib import Path

from flask import Flask, jsonify, render_template
from flask_cors import CORS

from app.core.config import settings
from app.db.mongodb import close_mongo, connect_to_mongo
from app.routers.auth import auth_bp
from app.routers.otp import otp_bp
from app.routers.virustotal import virustotal_bp, service

load_dotenv()
def create_app() -> Flask:
    
    app = Flask(__name__, template_folder=str(Path(__file__).parent / "templates"))
    swagger = Swagger(app)
    app.config["SECRET_KEY"] = settings.jwt_secret_key.get_secret_value()
    app.config["SESSION_COOKIE_HTTPONLY"] = True
    app.config["SESSION_COOKIE_SECURE"] = settings.cookie_secure or settings.environment == "production"
    app.config["SESSION_COOKIE_SAMESITE"] = settings.cookie_samesite
    app.config["PERMANENT_SESSION_LIFETIME"] = 1800
    CORS(app, origins=settings.cors_origins, supports_credentials=True)

    app.register_blueprint(auth_bp)
    app.register_blueprint(otp_bp)
    app.register_blueprint(virustotal_bp)

    @app.get("/")
    def root():
        '''root endpoint
        ---
            responses:
            200:
            description: returns hello world message
            ''' 
        return jsonify(message="Hello World")

    @app.get("/login")
    def login_page():
        return render_template("login.html", app_name=settings.app_name)

    @app.get("/health")
    def health_check():
        return jsonify(status="ok")

    @app.errorhandler(400)
    @app.errorhandler(401)
    @app.errorhandler(403)
    @app.errorhandler(404)
    @app.errorhandler(405)
    @app.errorhandler(409)
    @app.errorhandler(413)
    @app.errorhandler(422)
    @app.errorhandler(502)
    @app.errorhandler(503)
    def json_error(error):
        return jsonify(detail=getattr(error, "description", str(error))), error.code

    return app


app = create_app()


def initialize_app() -> None:
    connect_to_mongo()


def shutdown_app() -> None:
    service.close()
    close_mongo()
