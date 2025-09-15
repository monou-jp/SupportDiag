#!/usr/bin/env python
# -*- coding: utf-8 -*-
from __future__ import print_function

"""
サポート用：環境診断＋公開鍵暗号化（CLI/CGI両対応、依存ゼロ）
- 基本情報：掲示板にコピペしやすいテキストを表示
- 詳細情報：JSON を生成し、openssl があれば 自動でハイブリッド暗号化
  (AES-256-CBC + RSA-OAEP) → data.enc と key.enc を用意（ダウンロード可）
- 公開鍵の受け取り：
  1) 環境変数 SUPPORT_PUBKEY_PEM に PEM 文字列（-----BEGIN PUBLIC KEY----- …）
  2) スクリプトと同じディレクトリの support_pubkey.pem
  3) このファイル末尾の PLACEHOLDER_PUBLIC_KEY に直接貼り付け（推奨）
- 古いPython（2.7/3.5〜）配慮、標準ライブラリのみ使用
"""

import os, sys, platform, time, json, traceback, tempfile, subprocess, uuid

# Built-in HTTP server imports (Python 2/3 compatibility)
try:
    # Python 3
    from http.server import HTTPServer, BaseHTTPRequestHandler
    from urllib.parse import parse_qs, urlparse
except ImportError:
    # Python 2
    from BaseHTTPServer import HTTPServer, BaseHTTPRequestHandler
    from urlparse import parse_qs, urlparse

# ======== ここに公開鍵（PEM）を貼り付け可能 ===================================
PLACEHOLDER_PUBLIC_KEY = u"""\
# ここに '-----BEGIN PUBLIC KEY-----' から '-----END PUBLIC KEY-----' までを貼り付け
# 例:
# -----BEGIN PUBLIC KEY-----
# MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8A...
# -----END PUBLIC KEY-----
"""
# ============================================================================

def _u(x):
    try:
        if isinstance(x, unicode):  # py2
            return x
    except NameError:
        pass
    try:
        return str(x)
    except Exception:
        return repr(x)

def html_escape(s):
    s = _u(s)
    return (s.replace(u"&", u"&amp;")
             .replace(u"<", u"&lt;")
             .replace(u">", u"&gt;")
             .replace(u'"', u"&quot;")
             .replace(u"'", u"&#39;"))

def has_openssl():
    path = os.environ.get('PATH','')
    exes = ['openssl']
    if os.name == 'nt':
        exes += ['openssl.exe']
    for d in path.split(os.pathsep):
        for e in exes:
            p = os.path.join(d, e)
            if os.path.isfile(p) and os.access(p, os.X_OK):
                return p
    return None

def load_pubkey_pem():
    # 1) ENV
    pem = os.environ.get('SUPPORT_PUBKEY_PEM', '').strip()
    if pem.startswith('-----BEGIN '):
        return pem
    # 2) sidecar file
    here = os.path.dirname(os.path.abspath(sys.argv[0] or __file__))
    fpath = os.path.join(here, 'support_pubkey.pem')
    if os.path.isfile(fpath):
        try:
            with open(fpath, 'r') as f:
                return f.read().strip()
        except Exception:
            pass
    # 3) in-file placeholder
    if 'BEGIN PUBLIC KEY' in PLACEHOLDER_PUBLIC_KEY:
        # コメント行を取り除く
        lines = []
        for ln in PLACEHOLDER_PUBLIC_KEY.splitlines():
            ln = ln.strip()
            if ln.startswith('#') or not ln:
                continue
            lines.append(ln)
        pem = "\n".join(lines).strip()
        if pem.startswith('-----BEGIN '):
            return pem
    return ''

def collect_basic():
    return {
        'python': sys.version.replace('\n',' '),
        'impl': platform.python_implementation(),
        'exe': sys.executable,
        'platform': platform.platform(),
        'arch': platform.architecture(),
        'cwd': os.getcwd(),
    }

def collect_detail():
    info = {}
    info['basic'] = collect_basic()
    info['time'] = time.strftime('%Y-%m-%d %H:%M:%S', time.gmtime())
    info['env'] = {k: os.environ.get(k,'') for k in [
        'GATEWAY_INTERFACE','SERVER_SOFTWARE','SERVER_NAME','SERVER_ADDR','SERVER_PORT',
        'REQUEST_METHOD','REQUEST_URI','SCRIPT_NAME','PATH_INFO','QUERY_STRING',
        'REMOTE_ADDR','REMOTE_PORT','HTTP_HOST','HTTP_USER_AGENT','HTTPS','DOCUMENT_ROOT','PATH'
    ] if k in os.environ}
    info['sys_path'] = list(sys.path)
    # key libs
    def try_import(name, attr='__version__'):
        d = {'installed': False, 'version': 'N/A', 'path': 'N/A', 'error': ''}
        try:
            m = __import__(name)
            for part in name.split('.')[1:]:
                m = getattr(m, part)
            d['installed'] = True
            d['path'] = getattr(m,'__file__','N/A')
            v = getattr(m, attr, None)
            if v is None and name=='sqlite3':
                import sqlite3
                v = sqlite3.sqlite_version
            d['version'] = _u(v or 'unknown')
        except Exception as e:
            d['error'] = _u(e)
        return d
    libs = {}
    for n in ['sqlite3','bottle','peewee','jinja2','itsdangerous','ssl','cgi','wsgiref','json','re','subprocess']:
        libs[n] = try_import(n)
    info['modules'] = libs
    # write test
    tmp_candidates = [os.environ.get('TMPDIR'), os.environ.get('TEMP'), os.environ.get('TMP'), '/tmp', os.getcwd()]
    write_ok, write_where, write_err = False, '', ''
    for d in tmp_candidates:
        if not d: continue
        try:
            fn = os.path.join(d, 'support_diag_write_test_%d.tmp' % int(time.time()))
            with open(fn,'wb') as f: f.write(b'test')
            write_ok, write_where = True, d
            try: os.remove(fn)
            except Exception: pass
            break
        except Exception as e:
            write_err = _u(e)
    info['write_test'] = {'ok': write_ok, 'dir': write_where or '|'.join([x for x in tmp_candidates if x]), 'error': write_err}
    # packages (best-effort)
    pkgs = []
    method = 'none'
    try:
        import pkg_resources
        for d in pkg_resources.working_set:
            pkgs.append({'name': _u(d.project_name), 'version': _u(d.version), 'location': _u(getattr(d,'location',''))})
        method = 'pkg_resources'
    except Exception:
        try:
            import pkgutil
            for m in pkgutil.iter_modules():
                pkgs.append({'name': _u(m[1]), 'version': '', 'location': _u(getattr(m[0],'path',''))})
            method = 'pkgutil'
        except Exception:
            pass
    info['packages_method'] = method
    info['packages'] = pkgs
    return info

def is_cgi():
    return ('GATEWAY_INTERFACE' in os.environ) or ('REQUEST_METHOD' in os.environ)

def respond_headers(content_type, content_disposition=None):
    if is_cgi():
        sys.stdout.write("Content-Type: %s; charset=utf-8\r\n" % content_type)
        if content_disposition:
            sys.stdout.write("Content-Disposition: %s\r\n" % content_disposition)
        sys.stdout.write("\r\n")

def render_basic_text(b):
    lines = []
    lines.append("=== サポート用 基本情報（コピペ推奨） ===")
    lines.append("Python : %s" % b['python'])
    lines.append("Impl   : %s" % b['impl'])
    lines.append("Exec   : %s" % b['exe'])
    lines.append("OS     : %s" % b['platform'])
    lines.append("Arch   : %s" % _u(b['arch']))
    lines.append("CWD    : %s" % b['cwd'])
    lines.append("")
    lines.append("※この下は掲示板に貼らなくてOK。詳細は暗号化ファイルを添付してください。")
    return "\n".join(lines)

def render_html(basic_text, encrypt_result):
    esc = html_escape
    html = []
    html.append(u"<!doctype html><meta charset='utf-8'>")
    html.append(u"<title>Support Diag & Secure Upload</title>")
    html.append(u"<style>body{font-family:system-ui,Segoe UI,Roboto,sans-serif;line-height:1.5;background:#fafafa;padding:16px}pre{white-space:pre-wrap;background:#fff;border:1px solid #ddd;border-radius:8px;padding:12px}section{background:#fff;border:1px solid #ddd;border-radius:8px;padding:12px;margin:12px 0}</style>")
    html.append(u"<h1>サポート用：環境診断 + 暗号化</h1>")
    html.append(u"<section><h2>1) 基本情報（掲示板にコピペ）</h2><pre>%s</pre></section>" % esc(basic_text))
    html.append(u"<section><h2>2) 詳細情報（自動暗号化ファイルを添付）</h2>")
    if encrypt_result['ok']:
        html.append(u"<p>以下の2ファイルをサポート掲示板に<strong>添付</strong>してください：</p><ul>")
        html.append(u"<li><a href='?download=%s'>%s</a>（暗号化データ本体）</li>" % (esc(encrypt_result['enc_name']), esc(encrypt_result['enc_name'])))
        html.append(u"<li><a href='?download=%s'>%s</a>（暗号化キー）</li>" % (esc(encrypt_result['key_name']), esc(encrypt_result['key_name'])))
        html.append(u"</ul>")
        html.append(u"<p style='color:#555'>※ 御社側：秘密鍵で <code>%s</code> を復号 → 平文キーを使って <code>%s</code> を復号（AES-256-CBC, PBKDF2）。</p>" % (esc(encrypt_result['key_name']), esc(encrypt_result['enc_name'])))
    else:
        html.append(u"<p style='color:#b00'><strong>自動暗号化は未実施</strong>：%s</p>" % esc(encrypt_result['reason']))
        html.append(u"<p>対処案：<br>1) サーバに <code>openssl</code> を導入<br>2) 公開鍵(PEM)を本スクリプトの <code>PLACEHOLDER_PUBLIC_KEY</code> または <code>SUPPORT_PUBKEY_PEM</code> に設定<br>3) 再実行してください。</p>")
    html.append(u"</section>")
    html.append(u"<section><h2>安全の注意</h2><ul><li>このページは機密になり得る情報を扱います。外部に公開しないでください。</li><li>確認が終わったらスクリプトを削除してください。</li></ul></section>")
    return u"".join(html)

def do_encrypt(detail_json, pubkey_pem, openssl_path):
    """
    ハイブリッド方式：
      - data.json を AES-256-CBC + PBKDF2 で暗号化 → data.enc
      - パスフレーズ（key.txt）を RSA-OAEP(SHA-256) で暗号化 → key.enc
      - 2ファイルをダウンロードしてもらう
    """
    result = {'ok': False, 'enc_name': '', 'key_name': '', 'reason': ''}
    try:
        tmpdir = tempfile.gettempdir() or os.getcwd()
        token = uuid.uuid4().hex
        base = 'supportdiag_%s' % token
        json_path = os.path.join(tmpdir, base + '_data.json')
        key_path  = os.path.join(tmpdir, base + '_key.txt')
        pem_path  = os.path.join(tmpdir, base + '_pub.pem')
        enc_path  = os.path.join(tmpdir, base + '.enc')
        rkey_path = os.path.join(tmpdir, base + '.key.enc')

        # 書き出し
        with open(json_path, 'wb') as f:
            if isinstance(detail_json, bytes):
                f.write(detail_json)
            else:
                f.write(detail_json.encode('utf-8'))
        with open(pem_path, 'wb') as f:
            f.write(pubkey_pem.encode('utf-8'))

        # ランダムなパスフレーズを生成（32バイト）
        rnd = os.urandom(32)
        with open(key_path, 'wb') as f:
            f.write(rnd)

        # 1) データ暗号化（AES-256-CBC + PBKDF2, salt有）
        cmd1 = [openssl_path, 'enc', '-aes-256-cbc', '-salt', '-pbkdf2',
                '-in', json_path, '-out', enc_path, '-pass', 'file:%s' % key_path]
        p1 = subprocess.Popen(cmd1, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
        out1 = p1.communicate()[0]
        if p1.returncode != 0:
            raise RuntimeError("openssl enc failed: %s" % (out1.decode('utf-8','replace') if out1 else ''))

        # 2) キー暗号化（RSA-OAEP SHA-256）
        cmd2 = [openssl_path, 'pkeyutl', '-encrypt', '-pubin', '-inkey', pem_path,
                '-pkeyopt', 'rsa_padding_mode:oaep', '-pkeyopt', 'rsa_oaep_md:sha256',
                '-in', key_path, '-out', rkey_path]
        p2 = subprocess.Popen(cmd2, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
        out2 = p2.communicate()[0]
        if p2.returncode != 0:
            raise RuntimeError("openssl pkeyutl failed: %s" % (out2.decode('utf-8','replace') if out2 else ''))

        # 後片付け（平文ファイルは消す）
        try: os.remove(json_path)
        except Exception: pass
        try: os.remove(key_path)
        except Exception: pass
        try: os.remove(pem_path)
        except Exception: pass

        # 成果物
        result['ok'] = True
        result['enc_name'] = os.path.basename(enc_path)
        result['key_name'] = os.path.basename(rkey_path)
        result['token'] = token  # ダウンロード検証用
        return result
    except Exception as e:
        result['reason'] = _u(e)
        return result

def handle_download():
    # ?download=<filename> を TMPDIR から読み出して送信（当日生成の supportdiag_* のみ）
    q = os.environ.get('QUERY_STRING','')
    target = ''
    for part in q.split('&'):
        if part.startswith('download='):
            target = part.split('=',1)[1]
            break
    if not target:
        return False
    # 非常に簡易な検査：ファイル名のみ、supportdiag_ で始まり .enc / .key.enc のみ許可
    name = target.strip().split('/')[-1]
    if not (name.startswith('supportdiag_') and (name.endswith('.enc') or name.endswith('.key.enc'))):
        respond_headers('text/plain')
        sys.stdout.write('Invalid download request.')
        return True
    path = os.path.join(tempfile.gettempdir() or os.getcwd(), name)
    if not os.path.isfile(path):
        respond_headers('text/plain')
        sys.stdout.write('File not found (expired or cleaned).')
        return True
    # 送信
    respond_headers('application/octet-stream', 'attachment; filename=%s' % name)
    with open(path, 'rb') as f:
        data = f.read()
        if sys.version_info[0] < 3:
            sys.stdout.write(data)
        else:
            # Python 3: バイナリデータを直接stdout.bufferに書き込み
            if hasattr(sys.stdout, 'buffer'):
                sys.stdout.buffer.write(data)
            else:
                # CGI環境での代替処理
                sys.stdout.write(data.decode('latin1'))
    return True

class SupportDiagHandler(BaseHTTPRequestHandler):
    """Simple HTTP request handler that simulates CGI environment"""
    
    def do_GET(self):
        try:
            # Parse URL
            parsed = urlparse(self.path)
            
            # Set up CGI environment variables
            os.environ['GATEWAY_INTERFACE'] = 'CGI/1.1'
            os.environ['REQUEST_METHOD'] = 'GET'
            os.environ['REQUEST_URI'] = self.path
            os.environ['SCRIPT_NAME'] = '/sds.py'
            os.environ['PATH_INFO'] = parsed.path
            os.environ['QUERY_STRING'] = parsed.query or ''
            os.environ['SERVER_SOFTWARE'] = 'SDS-TestServer/1.0'
            os.environ['SERVER_NAME'] = self.server.server_name
            os.environ['SERVER_PORT'] = str(self.server.server_port)
            os.environ['REMOTE_ADDR'] = self.client_address[0]
            os.environ['HTTP_HOST'] = self.headers.get('Host', '')
            os.environ['HTTP_USER_AGENT'] = self.headers.get('User-Agent', '')
            
            # Capture stdout to send as HTTP response
            import io
            if sys.version_info[0] >= 3:
                old_stdout = sys.stdout
                sys.stdout = io.StringIO()
            else:
                old_stdout = sys.stdout
                sys.stdout = io.BytesIO()
            
            try:
                # Call main function which will detect CGI mode and output accordingly
                main()
                output = sys.stdout.getvalue()
            finally:
                sys.stdout = old_stdout
            
            # Send HTTP response
            if 'download=' in parsed.query:
                # File download - need to handle binary data properly
                if sys.version_info[0] >= 3:
                    # Python 3: output may contain binary data, handle carefully
                    if isinstance(output, str):
                        # Check if this is likely binary data that was decoded as latin1
                        try:
                            self.wfile.write(output.encode('latin1'))
                        except UnicodeEncodeError:
                            self.wfile.write(output.encode('utf-8'))
                    else:
                        self.wfile.write(output)
                else:
                    # Python 2: output is already bytes
                    self.wfile.write(output)
            else:
                # Regular HTML response
                self.send_response(200)
                self.send_header('Content-Type', 'text/html; charset=utf-8')
                self.end_headers()
                self.wfile.write(output.encode('utf-8') if sys.version_info[0] >= 3 else output)
                
        except Exception as e:
            self.send_response(500)
            self.send_header('Content-Type', 'text/plain')
            self.end_headers()
            error_msg = "Internal Server Error: %s" % str(e)
            self.wfile.write(error_msg.encode('utf-8') if sys.version_info[0] >= 3 else error_msg)
    
    def log_message(self, format, *args):
        """Override to provide simple logging"""
        print("[%s] %s" % (time.strftime('%Y-%m-%d %H:%M:%S'), format % args))

def run_server(host='127.0.0.1', port=8000):
    """Start the built-in HTTP server for testing"""
    server = HTTPServer((host, port), SupportDiagHandler)
    print("SDS Test Server started at http://%s:%d/" % (host, port))
    print("Press Ctrl+C to stop the server")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nServer stopped.")
        server.server_close()

def main():
    # ダウンロード要求なら先に処理
    if is_cgi() and 'download=' in os.environ.get('QUERY_STRING',''):
        try:
            if handle_download():
                return
        except Exception:
            respond_headers('text/plain'); sys.stdout.write('ERROR'); return

    try:
        basic = collect_basic()
        detail = collect_detail()
        basic_text = render_basic_text(basic)

        # 暗号化の可否
        openssl_path = has_openssl()
        pubkey_pem = load_pubkey_pem()
        enc_res = {'ok': False, 'reason': 'openssl or public key not available'}
        if openssl_path and pubkey_pem.startswith('-----BEGIN PUBLIC KEY-----'):
            enc_res = do_encrypt(json.dumps(detail, indent=2, ensure_ascii=False), pubkey_pem, openssl_path)

        if is_cgi():
            respond_headers('text/html')
            sys.stdout.write(render_html(basic_text, enc_res))
        else:
            # CLI: テキストで出力、暗号化結果も表示
            out = []
            out.append(basic_text)
            if enc_res['ok']:
                out.append("\n[暗号化ファイル準備OK]")
                out.append("  - %s (暗号化データ)" % enc_res['enc_name'])
                out.append("  - %s (暗号化キー)" % enc_res['key_name'])
                out.append("これらをサポートに添付してください。")
            else:
                out.append("\n[暗号化は未実施] 理由: %s" % enc_res.get('reason',''))
                out.append("openssl と 公開鍵(PEM) を用意して再実行してください。")
            sys.stdout.write("\n".join(out) if sys.version_info[0] >= 3 else ("\n".join(out)).encode('utf-8'))
    except Exception:
        if is_cgi():
            respond_headers('text/plain')
        sys.stdout.write("ERROR\n" + traceback.format_exc())

if __name__ == '__main__':
    # Check for server mode
    if len(sys.argv) > 1 and sys.argv[1] == '--server':
        # Parse optional host and port
        host = '127.0.0.1'
        port = 8000
        if len(sys.argv) > 2:
            try:
                port = int(sys.argv[2])
            except ValueError:
                print("Invalid port number. Using default port 8000.")
        if len(sys.argv) > 3:
            host = sys.argv[3]
        run_server(host, port)
    elif len(sys.argv) > 1 and sys.argv[1] in ['--help', '-h']:
        print("Usage:")
        print("  python sds.py                    # CLI mode")
        print("  python sds.py --server [port] [host]  # Test server mode")
        print("  python sds.py --help             # Show this help")
        print("")
        print("Examples:")
        print("  python sds.py --server           # Start server on 127.0.0.1:8000")
        print("  python sds.py --server 8080      # Start server on 127.0.0.1:8080")
        print("  python sds.py --server 8080 0.0.0.0  # Start server on 0.0.0.0:8080")
    else:
        main()
