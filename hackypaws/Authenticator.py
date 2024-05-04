import datetime, hashlib, hmac
import sqlite3 as sql

class Authenticator:

    def generate_session(username):
        '''
        Generates user sessions
            sessions will be invalidated every 24h for security
        '''
        auth_secret = str(datetime.date.today()).encode('utf-8')
        hmac_value = hmac.new(auth_secret, username.encode('utf-8'), hashlib.sha256).hexdigest()
        return hmac_value

    def validate_session(token, username):
        '''
        Validates if user token was generated from our site
        '''
        auth_secret = str(datetime.date.today()).encode('utf-8')
        username_bytes = username.encode('utf-8')
        hmac_digest = hmac.new(auth_secret, username_bytes, hashlib.sha256).hexdigest()
        if hmac.compare_digest(token, hmac_digest):
            return username
        else:
            return False
    
    def login(username, password):
        '''
        Accepts a username and password, hashes the password, then checks if a valid login
        '''
        if not username or not password:
            return False
        
        salt = "Sa1tyd0g".encode('utf-8')
        submitted_hash = hmac.new(salt, password.encode('utf-8'), hashlib.sha512).hexdigest()

        con = sql.connect("hackypaws.db")
        cur = con.cursor()
        login_sql = "SELECT * FROM users WHERE username == ? AND password == ?"
        cur.execute(login_sql, (username, submitted_hash))
        login_result = cur.fetchone()
        con.close()
        if login_result is not None:
            return True
        else:
            return False

        