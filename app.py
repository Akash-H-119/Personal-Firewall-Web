from flask import Flask, render_template
from flask_socketio import SocketIO, emit
from sniffer import start_sniffer

app = Flask(__name__)
app.config['SECRET_KEY'] = 'firewall_secret_key'
socketio = SocketIO(app)

@app.route('/')
def index():
    return render_template('index.html')

# Start packet sniffing in background
start_sniffer(socketio)

if __name__ == '__main__':
    socketio.run(app, debug=True)
