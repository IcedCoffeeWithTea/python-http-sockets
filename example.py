from server import Server


def home(self: Server, client, headers, method):
    dock = self.loadDocument("index.html")
    status = self.OK
    if method != "GET":
        dock = b"we don't serve your kind.", "text/raw"
        status = b"HTTP/2 500 Internal Server Error\r\n"

    self.sendResp(client, status, dock)


def secret(self: Server, client, status, method):
    self.sendResp(client, self.NF, (b"it's a 404...", "text/html"))


def main():
    server = Server(1234)
    server.static("./static", prefix="")
    server.addPage("/", home)
    server.addPage("/secret", secret)
    server.start()


if __name__ == "__main__":
    main()
