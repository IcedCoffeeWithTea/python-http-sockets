import socket
import threading
import os
import sys
import mimetypes
import logging
import ssl
import re

class HTTPException(Exception):
    def __init__(self, f, *args):
        super().__init__(args)
        self.status = f

    def __str__(self):
        return f"HTTP {self.status}"


class Server:
    def __init__(self, port: int):
        self.ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        self.ctx.load_cert_chain("keys/cert.pem", "keys/key.pem", "1234")
        self.sock = self.ctx.wrap_socket(socket.socket(socket.AF_INET, socket.SOCK_STREAM))
        self.port = port
        self.buff = 1028 ** 2
        self.headers = {"accept-ranges": "bytes",
                        "Content-Type": "text/raw",
                        "server": "python",
                        }
        with open(sys.argv[0]) as f:
            self.origFile = f.read()

        self.OK = b"HTTP/2 200 OK\r\n"
        self.NF = b"HTTP/2 404 not found\r\n"
        self.pages = {}
        self.staticPages = {}
        self.errHandlers = {}
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.logger = logging.getLogger(__name__)
        self.sock.bind(("127.0.0.1", self.port))
        self.up = True

    def addPage(self, path, func, method=None):
        if method == None:
            method = ["GET"]
        self.pages[path] = func, method
        if not path.endswith("/"):
            path += "/"
            self.pages[path] = func, method

    def onConnect(self, client: socket.socket, addr: tuple):
        req = client.recv(self.buff)
        prot, headers = self.parseHeaders(req)
        self.logger.warning(f"{prot[0]} {prot[1]} - {addr[0]}")
        try:
            if prot[1] in self.pages:
                if self.pages[prot[1]][1] and prot[0] in self.pages[prot[1]][1]:
                    self.pages[prot[1]][0](self, client, headers, prot[0])
            elif prot[1] in self.staticPages:
                self.sendResp(client, self.OK, (self.staticPages[prot[1]], mimetypes.guess_type(prot[1])[0]))
            else:
                try:
                    for thing, handle in self.errHandlers.items():
                        if re.search(thing, "404"):
                            raise HTTPException(404)
                except HTTPException as e:
                    handle(self, client, e.status)
                else:
                    self.sendResp(client, self.NF, self.loadDocument("404.html"), raiseException=False)
        except HTTPException as e:
            for st, handle in self.errHandlers.items():
                if re.search(str(st), str(e.status)):
                    handle(self, client, e.status)

        client.close()

    def sendResp(self, client, status, data, headers=None, raiseException=False):
        if not headers:
            headers = self.headers

        headers["Content-Type"] = "text/html" if isinstance(data, bytes) or not data[1] else data[1]
        headers["Content-Length"] = str(len(data if isinstance(data, bytes) else data[0]))
        statusNumber = int(status[7:][:3])
        if statusNumber > 299 and raiseException:
            raise HTTPException(statusNumber)

        headers = self.headers2Req(headers)
        client.sendall(status + headers + (data if isinstance(data, bytes) else data[0]))

    def loadFavicon(self):
        with open("favicon.png", "rb") as icon:
            self.staticPages["/favicon.ico"] = icon.read()

    def loadDocument(self, name):
        try:
            with open(name, "r") as f:
                return f.read().encode("utf-8"), mimetypes.guess_type(name)[0]
        except FileNotFoundError:
            return b"Not found", None

    def errorHandler(self, status, func):
        self.errHandlers[status] = func

    def parseHeaders(self, data):
        d = data.split(b"\r\n")
        protocol = d.pop(0).decode("utf-8")
        headers = {}
        for header in d:
            h = header.find(b": ")
            name = header[:h].decode("utf-8")
            info = header[h + 2:].decode("utf-8")
            headers[name] = info
        headers.pop("")
        return protocol.split(" "), headers

    def headers2Req(self, headers: dict):
        final = b""
        for name, val in headers.items():
            final += name.encode("utf-8") + b": " + val.encode("utf-8") + b"\r\n"
        return final + b"\r\n"

    def static(self, path, prefix="/static"):
        dirs = os.scandir(path)
        if prefix.endswith("/"):
            prefix = prefix[:-1]
        for file in dirs:
            if file.is_dir():
                self.static(file.path, prefix)
            else:
                page = file.path[2:]
                page = page[page.find("/"):]
                self.staticPages[prefix + page] = self.loadDocument(file.path)[0]

    def start(self):
        self.sock.listen()
        self.logger.warning(f"Running on https://localhost:{self.port}")
        self.loadFavicon()
        while 1:
            try:
                if not self.up:
                    break
                client, addr = self.sock.accept()
                threading.Thread(target=self.onConnect, args=[client, addr]).start()
            except Exception as _:
                pass

