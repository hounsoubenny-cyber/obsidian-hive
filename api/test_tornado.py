import tornado.ioloop
import tornado.web
import tornado.websocket

class WebSocketHandler(tornado.websocket.WebSocketHandler):
    # Stocker tous les clients connectés
    clients = set()
    
    def open(self):
        self.clients.add(self)
        print(f"🔗 Nouveau client connecté ({len(self.clients)} clients)")
        self.write_message("Bienvenue sur le chat !")
    
    def on_message(self, message):
        print(f"📩 Message reçu : {message}")
        # Diffuser le message à tous les clients
        for client in self.clients:
            if client != self:
                client.write_message(f"👤 {message}")
    
    def on_close(self):
        self.clients.remove(self)
        print(f"🔌 Client déconnecté ({len(self.clients)} clients)")

class MainHandler(tornado.web.RequestHandler):
    def get(self):
        self.write("""
        <html>
        <body>
            <h1>💬 Chat WebSocket</h1>
            <input id="msg" placeholder="Message">
            <button onclick="send()">Envoyer</button>
            <div id="log"></div>
            
            <script>
                var ws = new WebSocket("ws://localhost:8888/ws");
                ws.onmessage = function(e) {
                    var log = document.getElementById("log");
                    log.innerHTML += "<p>" + e.data + "</p>";
                };
                function send() {
                    var msg = document.getElementById("msg").value;
                    ws.send(msg);
                    document.getElementById("msg").value = "";
                }
            </script>
        </body>
        </html>
        """)

def make_app():
    return tornado.web.Application([
        (r"/", MainHandler),
        (r"/ws", WebSocketHandler),
    ])

if __name__ == "__main__":
    app = make_app()
    app.listen(8888)
    print("🚀 Chat sur http://localhost:8888")
    tornado.ioloop.IOLoop.current().start()