from waitress import serve
from app import app

if __name__ == '__main__':
    serve(app, 
          host='0.0.0.0',  # Listen on all available network interfaces
          port=8000,       # Port number
          threads=4,       # Number of worker threads
          url_scheme='http') 