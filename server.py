import hashlib
import tornado.ioloop
import tornado.web
import pymysql.cursors
import logging
import json
import os
from requests_oauthlib import OAuth2Session
from tornado.httpclient import AsyncHTTPClient, HTTPRequest
from datetime import datetime, timedelta, timezone
from dotenv import load_dotenv
import smtplib
import secrets
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart

# Load environment variables from .env file
load_dotenv()

# Configure logging
logging.basicConfig(level=logging.INFO)

# Get database credentials from environment variables
db_user = os.getenv('DATABASE_USER')
db_password = os.getenv('DATABASE_PASSWORD')
db_host = os.getenv('DATABASE_HOST')
db_name = os.getenv('DATABASE_NAME')

# Database connection
try:
    connection = pymysql.connect(
        host=db_host,
        user=db_user,
        password=db_password,
        database=db_name,
        cursorclass=pymysql.cursors.DictCursor
    )
    logging.info("Database connection established")
except pymysql.MySQLError as e:
    logging.error(f"Database connection error: {e}")

# Set environment variable for local development
os.environ['OAUTHLIB_INSECURE_TRANSPORT'] = '1'

# OAuth configuration from environment variables
client_id = os.getenv('CLIENT_ID')
client_secret = os.getenv('CLIENT_SECRET')
redirect_uri = 'http://localhost:8888/auth/google/callback'
authorization_base_url = 'https://accounts.google.com/o/oauth2/auth'
token_url = 'https://oauth2.googleapis.com/token'
user_info_url = 'https://openidconnect.googleapis.com/v1/userinfo'

# Email sending function 
def send_reset_email(email, token):
    reset_link = f"http://localhost:8888/reset-password?token={token}"
    subject = "Password Reset Request"
    body = f"Please click the link to reset your password: {reset_link}"

    # Create email message
    msg = MIMEMultipart()
    msg['From'] = os.getenv('SMTP_EMAIL')
    msg['To'] = email
    msg['Subject'] = subject
    msg.attach(MIMEText(body, 'plain'))

    # Using smtplib to send email
    try:
        with smtplib.SMTP(os.getenv('SMTP_SERVER'), os.getenv('SMTP_PORT')) as server:
            server.starttls()
            server.login(os.getenv('SMTP_EMAIL'), os.getenv('SMTP_PASSWORD'))
            server.sendmail(os.getenv('SMTP_EMAIL'), email, msg.as_string())
        logging.info(f"Reset email sent to {email}")
    except smtplib.SMTPException as e:
        logging.error(f"Error sending email: {e}")

class MainHandler(tornado.web.RequestHandler):
    def get(self):
        logging.info("MainHandler: GET request received")
        self.render("dist/index.html")

class SigninHandler(tornado.web.RequestHandler):
    def get(self):
        logging.info("SigninHandler: GET request received")
        self.render("dist/signin.html")

    def post(self):
        logging.info("SigninHandler: POST request received")
        email = self.get_argument('email')
        password = self.get_argument('password')
        hashed_password = hashlib.sha256(password.encode()).hexdigest()
        logging.info(f"SigninHandler: Email={email}, Password={hashed_password}")

        with connection.cursor() as cursor:
            sql = "SELECT * FROM users WHERE email=%s AND password=%s"
            cursor.execute(sql, (email, hashed_password))
            result = cursor.fetchone()
            if result:
                self.write("<script>alert('Signin successful'); window.location.href='/landing';</script>")
                logging.info("Signin successful")
            else:
                self.write("<script>alert('Invalid email or password'); window.location.href='/signin';</script>")
                logging.info("Invalid email or password")

class SignupHandler(tornado.web.RequestHandler):
    def get(self):
        logging.info("SignupHandler: GET request received")
        self.render("dist/signup.html")

    def post(self):
        logging.info("SignupHandler: POST request received")
        fullname = self.get_argument('fullname')
        email = self.get_argument('email')
        password = self.get_argument('password')
        confirm_password = self.get_argument('confirm_password')

        if password != confirm_password:
            self.write("<script>alert('Passwords do not match'); window.location.href='/signup';</script>")
            logging.info("Passwords do not match")
            return

        hashed_password = hashlib.sha256(password.encode()).hexdigest()
        signup_type = 'manual'
        logging.info(f"SignupHandler: Fullname={fullname}, Email={email}, Password={hashed_password}, SignupType={signup_type}")

        with connection.cursor() as cursor:
            sql = "SELECT * FROM users WHERE email=%s"
            cursor.execute(sql, (email,))
            if cursor.fetchone():
                self.write("<script>alert('Email already exists'); window.location.href='/signup';</script>")
                logging.info("Email already exists")
                return

            sql = "INSERT INTO users (fullname, email, password, signup_type) VALUES (%s, %s, %s, %s)"
            try:
                cursor.execute(sql, (fullname, email, hashed_password, signup_type))
                connection.commit()
                self.write("<script>alert('Signup successful'); window.location.href='/landing';</script>")
                logging.info("Signup successful")
            except pymysql.MySQLError as e:
                self.write(f"<script>alert('Database error: {e}'); window.location.href='/signup';</script>")
                logging.error(f"SignupHandler: Database error: {e}")
                
class AuthLoginHandler(tornado.web.RequestHandler):
    def get(self):
        google = OAuth2Session(client_id, redirect_uri=redirect_uri, scope=['openid', 'email', 'profile'])
        authorization_url, state = google.authorization_url(authorization_base_url, access_type='offline', prompt='select_account')
        self.set_secure_cookie('oauth_state', state)
        self.redirect(authorization_url)

class AuthCallbackHandler(tornado.web.RequestHandler):
    async def get(self):
        try:
            state = self.get_secure_cookie('oauth_state').decode('utf-8')
            google = OAuth2Session(client_id, redirect_uri=redirect_uri, state=state)
            token = google.fetch_token(token_url, client_secret=client_secret, authorization_response=self.request.uri)
            logging.info(f"AuthCallbackHandler: Token received: {token}")

            async_client = AsyncHTTPClient()
            request = HTTPRequest(user_info_url, headers={'Authorization': f'Bearer {token["access_token"]}'})
            response = await async_client.fetch(request)
            user_info = json.loads(response.body)
            logging.info(f"AuthCallbackHandler: User info received: {user_info}")

            email = user_info['email']

            with connection.cursor() as cursor:
                sql = "SELECT * FROM users WHERE email=%s"
                cursor.execute(sql, (email,))
                user = cursor.fetchone()

                if user:
                    self.write("<script>alert('Signin successful'); window.location.href='/landing';</script>")
                else:
                    fullname = user_info['name']
                    hashed_password = ''  # Set an empty password or generate a random one
                    signup_type = 'google'
                    sql = "INSERT INTO users (fullname, email, password, signup_type) VALUES (%s, %s, %s, %s)"
                    try:
                        cursor.execute(sql, (fullname, email, hashed_password, signup_type))
                        connection.commit()
                        self.write("<script>alert('Signup successful'); window.location.href='/landing';</script>")
                    except pymysql.MySQLError as e:
                        self.write(f"<script>alert('Database error: {e}'); window.location.href='/signup';</script>")
                        logging.error(f"AuthCallbackHandler: Database error: {e}")
        except Exception as e:
            logging.error(f"AuthCallbackHandler: Error during callback: {e}")
            self.write(f"<script>alert('Error during callback: {e}'); window.location.href='/signin';</script>")


class ForgotPasswordHandler(tornado.web.RequestHandler):
    def get(self):
        logging.info("ForgotPasswordHandler: GET request received")
        self.render("dist/forgot-password.html")

    def post(self):
        email = self.get_argument('email')
        logging.info(f"ForgotPasswordHandler: Received forgot password request for {email}")

        try:
            with connection.cursor() as cursor:
                sql = "SELECT * FROM users WHERE email=%s"
                cursor.execute(sql, (email,))
                user = cursor.fetchone()
                logging.info(f"ForgotPasswordHandler: User lookup result: {user}")

                if user:
                    # Generate a secure token
                    reset_token = secrets.token_urlsafe(20)
                    reset_token_expiry = datetime.now() + timedelta(hours=1)
                    logging.info(f"ForgotPasswordHandler: Generated reset token: {reset_token} with expiry: {reset_token_expiry}")

                    # Update the user record with the reset token and expiry
                    sql = "UPDATE users SET reset_token=%s, reset_token_expiry=%s WHERE email=%s"
                    cursor.execute(sql, (reset_token, reset_token_expiry, email))
                    connection.commit()
                    logging.info(f"ForgotPasswordHandler: Reset token saved to database for email: {email}")

                    # Send reset email
                    send_reset_email(email, reset_token)
                    logging.info(f"ForgotPasswordHandler: Password reset email sent to {email}")
                    self.write("<script>alert('Password reset email sent'); window.location.href='/signin';</script>")
                else:
                    logging.warning(f"ForgotPasswordHandler: Email not found: {email}")
                    self.write("<script>alert('Email not found'); window.location.href='/forgot-password';</script>")

        except pymysql.MySQLError as e:
            logging.error(f"Database error: {e}")
            self.write("<script>alert('Database error. Please try again later.'); window.location.href='/forgot-password';</script>")
        except Exception as e:
            logging.error(f"An unexpected error occurred: {e}")
            self.write("<script>alert('An unexpected error occurred. Please try again later.'); window.location.href='/forgot-password';</script>")

class ResetPasswordHandler(tornado.web.RequestHandler):
    def get(self):
        token = self.get_argument('token', None)
        if not token:
            self.write("<script>alert('Invalid request'); window.location.href='/';</script>")
            return

        try:
            with connection.cursor() as cursor:
                sql = "SELECT * FROM users WHERE reset_token=%s AND reset_token_expiry>%s"
                cursor.execute(sql, (token, datetime.now(timezone.utc)))
                user = cursor.fetchone()

                if user:
                    self.render("dist/reset-password.html", token=token)
                else:
                    self.write("<script>alert('Invalid or expired token'); window.location.href='/forgot-password';</script>")
        except Exception as e:
            logging.error(f"Error in ResetPasswordHandler GET: {e}")
            self.write("<script>alert('An error occurred'); window.location.href='/';</script>")

    def post(self):
        token = self.get_argument('token')
        password = self.get_argument('password')
        confirm_password = self.get_argument('confirm_password')

        if password != confirm_password:
            self.write("<script>alert('Passwords do not match'); window.location.href='/reset-password?token=' + token;</script>")
            return

        hashed_password = hashlib.sha256(password.encode()).hexdigest()
        try:
            with connection.cursor() as cursor:
                sql = "UPDATE users SET password=%s, reset_token=NULL, reset_token_expiry=NULL WHERE reset_token=%s"
                cursor.execute(sql, (hashed_password, token))
                connection.commit()

                if cursor.rowcount == 0:
                    self.write("<script>alert('Invalid or expired token'); window.location.href='/forgot-password';</script>")
                    return

            self.write("<script>alert('Password reset successfully'); window.location.href='/signin';</script>")
        except Exception as e:
            logging.error(f"Error in ResetPasswordHandler POST: {e}")
            self.write("<script>alert('An error occurred while resetting your password'); window.location.href='/reset-password?token=' + token;</script>")

class LandingHandler(tornado.web.RequestHandler):
    def get(self):
        logging.info("LandingHandler: GET request received")
        self.render("dist/landing.html")

def make_app():
    return tornado.web.Application([
        (r"/", MainHandler),
        (r"/signin", SigninHandler),
        (r"/signup", SignupHandler),
        (r"/auth/google", AuthLoginHandler),
        (r"/auth/google/callback", AuthCallbackHandler),
        (r"/forgot-password", ForgotPasswordHandler),
        (r"/reset-password", ResetPasswordHandler),
        (r"/landing", LandingHandler),  # Adding handler for landing page
        (r"/assets/(.*)", tornado.web.StaticFileHandler, {"path": "dist/assets"}),  # Updated path
        (r"/(.*)", tornado.web.StaticFileHandler, {"path": "dist", "default_filename": "index.html"})
    ], cookie_secret=os.getenv('COOKIE_SECRET'))

if __name__ == "__main__":
    app = make_app()
    app.listen(8888)
    logging.info("Tornado server is running on http://localhost:8888")
    tornado.ioloop.IOLoop.current().start()