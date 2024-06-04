from app import app

if __name__ == '__main__':
    app.run(ssl_context=(r'C:\Users\Usuario\MonDojo\localhost+2.pem', r'C:\Users\Usuario\MonDojo\localhost+2-key.pem'))
