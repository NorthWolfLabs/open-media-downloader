"""Local-only TLS and HTTP fixture for impersonation checks (omd-ytdlp-source-fixture-v1).

`pki` creates a throwaway CA and leaf certificates with the OS `openssl` in a new private
directory: a `localhost` leaf (SAN DNS:localhost) and a leaf for another name, for the
hostname-mismatch check. `Server` listens on the loopback interface only. For each
connection it peeks the complete TLS ClientHello before the handshake, then completes
TLS with ALPN `h2` or `http/1.1` and answers every request with one fixed HTML page whose
body uses a chosen content encoding. It records the parsed ClientHello, the negotiated
ALPN and, for HTTP/2, the client's SETTINGS, WINDOW_UPDATE, PRIORITY and HEADERS frames
(the raw HPACK block is kept; values are not decoded).

The client trusts the CA only through a per-run verify file. Certificate and hostname
validation stay enabled; nothing here disables verification, contacts a public host or
changes system trust. Only the Python standard library is used.
"""
import hashlib
import json
import os
import socket
import ssl
import struct
import subprocess
import threading
import zlib
from pathlib import Path

SCHEMA = 'omd-ytdlp-source-fixture-v1'
OPENSSL = '/usr/bin/openssl'
H2_PREFACE = b'PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n'
MAX_HELLO = 64 * 1024
MAX_FRAME = 1 << 20
PAGE = (b'<!DOCTYPE html>\n<html><head><meta charset="utf-8"><title>omd impersonation fixture</title></head>\n'
        b'<body><p>' + b'Local fixture page. ' * 64 + b'</p>\n<video src="/clip.mp4" controls></video>\n</body></html>\n')
# Sandbox for client runs: the loopback interface and the local resolver socket only.
SANDBOX = ('(version 1)(allow default)(deny network*)(allow network-outbound (remote ip "localhost:*"))'
           '(allow network-outbound (remote unix-socket (path-literal "/private/var/run/mDNSResponder")))')
EXTENSION_NAMES = {0: 'server_name', 5: 'status_request', 10: 'supported_groups', 11: 'ec_point_formats', 13: 'signature_algorithms',
                   16: 'alpn', 18: 'signed_certificate_timestamp', 21: 'padding', 23: 'extended_master_secret', 27: 'compress_certificate',
                   28: 'record_size_limit', 34: 'delegated_credentials', 35: 'session_ticket', 41: 'pre_shared_key', 43: 'supported_versions',
                   45: 'psk_key_exchange_modes', 49: 'post_handshake_auth', 51: 'key_share', 17513: 'application_settings_old',
                   17613: 'application_settings', 65037: 'encrypted_client_hello', 65281: 'renegotiation_info'}
# Extension bodies that carry per-connection randomness or depend on its length. The
# normalized fingerprint keeps everything else: versions, cipher suites, the extension set,
# fixed extension bodies, ALPN, key-share groups and key sizes, and GREASE positions.
VARIABLE_BODIES = {21, 41, 51, 65037}


def need(ok, why):
    if not ok:
        raise ValueError(why)


def grease(value):
    return value & 0x0f0f == 0x0a0a and value >> 8 == value & 0xff


def label(value):
    return 'GREASE' if grease(value) else value


# ---------------------------------------------------------------- certificates

def pki(folder):
    """Throwaway CA, a localhost leaf and a wrong-name leaf: named-curve P-256 keys, SHA-256
    signatures, two-day validity."""
    folder = Path(folder)
    folder.mkdir(mode=0o700)
    env = {'PATH': '/usr/bin:/bin', 'HOME': str(folder), 'RANDFILE': str(folder / '.rnd')}

    def run(*argv):
        subprocess.run([OPENSSL, *argv], cwd=folder, env=env, check=True, capture_output=True, timeout=60)

    run('req', '-x509', '-sha256', '-newkey', 'ec', '-pkeyopt', 'ec_paramgen_curve:prime256v1', '-pkeyopt', 'ec_param_enc:named_curve', '-nodes', '-keyout', 'ca.key', '-out', 'ca.pem',
        '-days', '2', '-subj', '/CN=omd throwaway fixture CA', '-addext', 'basicConstraints=critical,CA:TRUE',
        '-addext', 'keyUsage=critical,keyCertSign,cRLSign', '-addext', 'subjectKeyIdentifier=hash')
    for name, host in (('leaf', 'localhost'), ('wrong', 'wrong-name.invalid')):
        (folder / f'{name}.cnf').write_text(f'subjectAltName=DNS:{host}\nbasicConstraints=critical,CA:FALSE\n'
                                            'keyUsage=critical,digitalSignature\nextendedKeyUsage=serverAuth\n'
                                            'subjectKeyIdentifier=hash\nauthorityKeyIdentifier=keyid\n')
        run('req', '-newkey', 'ec', '-pkeyopt', 'ec_paramgen_curve:prime256v1', '-pkeyopt', 'ec_param_enc:named_curve', '-nodes', '-keyout', f'{name}.key', '-out', f'{name}.csr',
            '-subj', f'/CN={host}')
        run('x509', '-req', '-sha256', '-in', f'{name}.csr', '-CA', 'ca.pem', '-CAkey', 'ca.key', '-set_serial', '1' if name == 'leaf' else '2',
            '-out', f'{name}.pem', '-days', '2', '-extfile', f'{name}.cnf')
    (folder / 'ca.key').unlink()
    return {'ca': folder / 'ca.pem', 'leaf': (folder / 'leaf.pem', folder / 'leaf.key'), 'wrong': (folder / 'wrong.pem', folder / 'wrong.key')}


# ---------------------------------------------------------------- ClientHello

def u16_list(data, width=2):
    return [int.from_bytes(data[i:i + width], 'big') for i in range(0, len(data), width)]


def vector(data, at, width):
    length = int.from_bytes(data[at:at + width], 'big')
    end = at + width + length
    need(end <= len(data), 'Truncated ClientHello vector')
    return data[at + width:end], end


def parse_client_hello(record):
    """Fields of one TLS ClientHello (from its records); GREASE values are labelled."""
    handshake, at = b'', 0
    while at < len(record):
        need(record[at] == 22 and at + 5 <= len(record), 'Not a TLS handshake record')
        length = int.from_bytes(record[at + 3:at + 5], 'big')
        handshake += record[at + 5:at + 5 + length]
        at += 5 + length
    need(handshake[:1] == b'\x01', 'Not a ClientHello')
    body = handshake[4:4 + int.from_bytes(handshake[1:4], 'big')]
    version = int.from_bytes(body[:2], 'big')
    _, at = vector(body, 34, 1)  # session id
    ciphers, at = vector(body, at, 2)
    compression, at = vector(body, at, 1)
    extensions_raw, _ = vector(body, at, 2)
    extensions, at = [], 0
    while at < len(extensions_raw):
        kind = int.from_bytes(extensions_raw[at:at + 2], 'big')
        data, at = vector(extensions_raw, at + 2, 2)
        extensions.append((kind, data))
    found = {'record_version': int.from_bytes(record[1:3], 'big'), 'legacy_version': version,
             'cipher_suites': [label(v) for v in u16_list(ciphers)], 'compression_methods': list(compression),
             'extensions': [label(k) if grease(k) else EXTENSION_NAMES.get(k, k) for k, _ in extensions], 'bodies': {}}
    for kind, data in extensions:
        name = EXTENSION_NAMES.get(kind, str(kind))
        if grease(kind):
            continue
        if kind == 0:
            names, _ = vector(data, 0, 2)
            found['sni'] = names[3:].decode('ascii', 'replace')
        elif kind == 10:
            found['bodies'][name] = [label(v) for v in u16_list(vector(data, 0, 2)[0])]
        elif kind == 13:
            found['bodies'][name] = u16_list(vector(data, 0, 2)[0])
        elif kind == 16:
            protocols, raw, i = [], vector(data, 0, 2)[0], 0
            while i < len(raw):
                item, i = vector(raw, i, 1)
                protocols.append(item.decode('ascii', 'replace'))
            found['alpn'] = protocols
        elif kind == 43:
            found['bodies'][name] = [label(v) for v in u16_list(vector(data, 0, 1)[0])]
        elif kind == 51:
            shares, raw, i = [], vector(data, 0, 2)[0], 0
            while i < len(raw):
                group = int.from_bytes(raw[i:i + 2], 'big')
                key, i = vector(raw, i + 2, 2)
                shares.append([label(group), len(key)])
            found['key_shares'] = shares
        elif kind == 27:
            found['bodies'][name] = u16_list(vector(data, 0, 1)[0])
        elif kind in (17513, 17613):
            protocols, raw, i = [], vector(data, 0, 2)[0], 0
            while i < len(raw):
                item, i = vector(raw, i, 1)
                protocols.append(item.decode('ascii', 'replace'))
            found['bodies'][name] = protocols
        elif kind not in VARIABLE_BODIES:
            found['bodies'][name] = data.hex()
    found['ech_grease'] = 65037 in [k for k, _ in extensions]
    # BoringSSL adds the padding extension only when the unpadded ClientHello length falls in
    # a window, and the length varies with randomized fields (GREASE ECH payload size), so
    # padding is recorded but kept out of the normalized fingerprint.
    found['padding'] = 21 in [k for k, _ in extensions]
    found['length'] = len(handshake)
    stable = {k: v for k, v in found.items() if k not in ('extensions', 'padding', 'length')}
    stable['extension_set'] = sorted(str(e) for e in found['extensions'] if e != 'padding')
    found['fingerprint_sha256'] = hashlib.sha256(json.dumps(stable, sort_keys=True).encode()).hexdigest()
    found['order_sha256'] = hashlib.sha256(json.dumps(found['extensions']).encode()).hexdigest()
    return found


def peek_client_hello(sock, timeout=20):
    """The complete ClientHello records, read with MSG_PEEK so the handshake still sees them."""
    sock.settimeout(timeout)
    want, data = 5, b''
    while True:
        data = sock.recv(MAX_HELLO, socket.MSG_PEEK)
        need(data, 'Connection closed before a ClientHello')
        need(data[0] == 22, 'First record is not a TLS handshake')
        if len(data) >= 9:
            hello_length = int.from_bytes(data[6:9], 'big') + 4
            records, at, total = 0, 0, 0
            while at + 5 <= len(data) and total < hello_length:
                length = int.from_bytes(data[at + 3:at + 5], 'big')
                if at + 5 + length > len(data):
                    break
                total += length
                at += 5 + length
                records += 1
            if total >= hello_length:
                return data[:at]
        need(len(data) < MAX_HELLO, 'ClientHello too large')
        threading.Event().wait(0.01)


# ---------------------------------------------------------------- HTTP/2 and HTTP/1.1

def read_exact(stream, size):
    data = b''
    while len(data) < size:
        chunk = stream.recv(size - len(data))
        if not chunk:
            raise EOFError('peer closed')
        data += chunk
    return data


def h2_frame(kind, flags, stream, payload=b''):
    return struct.pack('>I', len(payload))[1:] + bytes([kind, flags]) + struct.pack('>I', stream) + payload


def hpack_int(value, prefix, first):
    limit = (1 << prefix) - 1
    if value < limit:
        return bytes([first | value])
    out, value = bytearray([first | limit]), value - limit
    while value >= 128:
        out.append(value % 128 | 128)
        value //= 128
    out.append(value)
    return bytes(out)


def hpack_literal(index, value):
    """Literal header field without indexing, indexed name, plain (non-Huffman) value."""
    return hpack_int(index, 4, 0) + hpack_int(len(value), 7, 0) + value


def response_headers(encoding, length):
    block = b'\x88' + hpack_literal(31, b'text/html; charset=utf-8') + hpack_literal(28, str(length).encode())
    if encoding != 'identity':
        block += hpack_literal(26, encoding.encode())
    return block


def encode(body, encoding):
    if encoding == 'gzip':
        compressor = zlib.compressobj(9, zlib.DEFLATED, 31)
        return compressor.compress(body) + compressor.flush()
    if encoding == 'deflate':
        return zlib.compress(body, 9)
    if encoding == 'zstd':
        # One zstd frame (RFC 8878): single segment, 2-byte content size, one raw last block.
        need(256 <= len(body) < 65536 + 256, 'zstd fixture body size out of range')
        return (b'\x28\xb5\x2f\xfd' + bytes([0x60]) + struct.pack('<H', len(body) - 256)
                + struct.pack('<I', 1 | (len(body) << 3))[:3] + body)
    if encoding == 'br':
        # Brotli (RFC 7932) with uncompressed meta-blocks: WBITS=16, ISLAST=0, MNIBBLES=4,
        # MLEN-1, ISUNCOMPRESSED=1, byte-aligned data, then an empty last meta-block.
        out, bits, nbits = bytearray(), 0, 0

        def put(value, count):
            nonlocal bits, nbits
            bits |= value << nbits
            nbits += count
            while nbits >= 8:
                out.append(bits & 255)
                bits >>= 8
                nbits -= 8

        put(0, 1)  # WBITS = 16
        for start in range(0, len(body), 65536):
            chunk = body[start:start + 65536]
            put(0, 1)
            put(0, 2)
            put(len(chunk) - 1, 16)
            put(1, 1)
            if nbits:
                put(0, 8 - nbits)
            out += chunk
        put(1, 1)
        put(1, 1)
        if nbits:
            put(0, 8 - nbits)
        return bytes(out)
    need(encoding == 'identity', f'Unknown fixture encoding: {encoding}')
    return body


def serve_h2(conn, row, encoding):
    preface = read_exact(conn, len(H2_PREFACE))
    need(preface == H2_PREFACE, 'Missing HTTP/2 client preface')
    conn.sendall(h2_frame(4, 0, 0, struct.pack('>HI', 3, 100)))
    frames, headers, answered = [], {}, set()
    body = encode(PAGE, encoding)
    while True:
        header = read_exact(conn, 9)
        length, kind, flags, stream = int.from_bytes(header[:3], 'big'), header[3], header[4], struct.unpack('>I', header[5:])[0] & 0x7fffffff
        need(length <= MAX_FRAME, 'HTTP/2 frame too large')
        payload = read_exact(conn, length)
        if kind == 4 and not flags & 1:
            frames.append({'type': 'SETTINGS', 'settings': [list(struct.unpack('>HI', payload[i:i + 6])) for i in range(0, len(payload), 6)]})
            conn.sendall(h2_frame(4, 1, 0))
        elif kind == 4:
            frames.append({'type': 'SETTINGS_ACK'})
        elif kind == 8:
            frames.append({'type': 'WINDOW_UPDATE', 'stream': stream, 'increment': struct.unpack('>I', payload)[0] & 0x7fffffff})
        elif kind == 2:
            dependency, weight = struct.unpack('>IB', payload[:5])
            frames.append({'type': 'PRIORITY', 'stream': stream, 'exclusive': bool(dependency >> 31), 'depends_on': dependency & 0x7fffffff, 'weight': weight + 1})
        elif kind in (1, 9):
            fragment = payload
            if kind == 1:
                pad = payload[0] if flags & 8 else 0
                fragment = payload[1:] if flags & 8 else payload
                priority = None
                if flags & 0x20:
                    dependency, weight = struct.unpack('>IB', fragment[:5])
                    priority = {'exclusive': bool(dependency >> 31), 'depends_on': dependency & 0x7fffffff, 'weight': weight + 1}
                    fragment = fragment[5:]
                fragment = fragment[:len(fragment) - pad] if pad else fragment
                headers[stream] = {'flags': flags, 'priority': priority, 'block': fragment}
                frames.append({'type': 'HEADERS', 'stream': stream, 'flags': flags, 'priority': priority})
            else:
                headers[stream]['block'] += fragment
                frames.append({'type': 'CONTINUATION', 'stream': stream})
            if flags & 4 and stream not in answered:
                answered.add(stream)
                block = response_headers(encoding, len(body))
                conn.sendall(h2_frame(1, 4, stream, block) + h2_frame(0, 1, stream, body))
        elif kind == 7:
            frames.append({'type': 'GOAWAY'})
            break
        elif kind == 3:
            frames.append({'type': 'RST_STREAM', 'stream': stream})
        elif kind == 6 and not flags & 1:
            conn.sendall(h2_frame(6, 1, 0, payload))
        else:
            frames.append({'type': f'type-{kind}', 'stream': stream, 'flags': flags})
    row['h2'] = {'frames': frames, 'requests': [{'stream': s, 'flags': h['flags'], 'priority': h['priority'], 'hpack_sha256': hashlib.sha256(h['block']).hexdigest(),
                                                'hpack_hex': h['block'].hex()} for s, h in sorted(headers.items())]}


def serve_http1(conn, row, encoding):
    data = b''
    while b'\r\n\r\n' not in data:
        chunk = conn.recv(65536)
        if not chunk:
            break
        data += chunk
        need(len(data) < 1 << 20, 'HTTP/1.1 request too large')
    head = data.split(b'\r\n\r\n', 1)[0].decode('latin-1').split('\r\n')
    row['http1'] = {'request_line': head[0], 'header_names': [line.split(':', 1)[0] for line in head[1:]],
                    'headers': {line.split(':', 1)[0].lower(): line.split(':', 1)[1].strip() for line in head[1:] if ':' in line}}
    body = encode(PAGE, encoding)
    extra = f'Content-Encoding: {encoding}\r\n' if encoding != 'identity' else ''
    conn.sendall(f'HTTP/1.1 200 OK\r\nContent-Type: text/html; charset=utf-8\r\nContent-Length: {len(body)}\r\n{extra}Connection: close\r\n\r\n'.encode() + body)


class Server:
    """A loopback TLS server that records each connection; one fixed page per request."""

    def __init__(self, cert, key, encoding='identity', alpn=('h2', 'http/1.1')):
        self.context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        self.context.load_cert_chain(cert, key)
        self.context.set_alpn_protocols(list(alpn))
        self.encoding, self.connections, self.lock = encoding, [], threading.Lock()
        self.listener = socket.create_server(('127.0.0.1', 0))
        self.port = self.listener.getsockname()[1]
        self.thread = threading.Thread(target=self.accept, daemon=True)
        self.thread.start()

    def accept(self):
        while True:
            try:
                conn, _ = self.listener.accept()
            except OSError:
                return
            threading.Thread(target=self.handle, args=(conn,), daemon=True).start()

    def handle(self, raw):
        row = {}
        with self.lock:
            self.connections.append(row)
        try:
            row['client_hello'] = parse_client_hello(peek_client_hello(raw))
            raw.settimeout(30)
            with self.context.wrap_socket(raw, server_side=True) as conn:
                row['tls_version'], row['cipher'], row['alpn'] = conn.version(), conn.cipher()[0], conn.selected_alpn_protocol()
                (serve_h2 if row['alpn'] == 'h2' else serve_http1)(conn, row, self.encoding)
        except (OSError, EOFError, ValueError, ssl.SSLError) as error:
            row.setdefault('end', f'{type(error).__name__}: {error}'[:300])
        finally:
            raw.close()

    def close(self):
        self.listener.close()

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        self.close()


def run_client(argv, home, env_extra=None, timeout=180):
    """Run one client command in the loopback-only sandbox with a private home."""
    home = Path(home)
    (home / 'tmp').mkdir(parents=True, exist_ok=True)
    env = {'PATH': '/usr/bin:/bin', 'HOME': str(home), 'TMPDIR': str(home / 'tmp'), 'LANG': 'en_US.UTF-8', 'LC_ALL': 'en_US.UTF-8',
           'XDG_CONFIG_HOME': str(home / 'config'), 'XDG_CACHE_HOME': str(home / 'cache'), **(env_extra or {})}
    result = subprocess.run(['/usr/bin/sandbox-exec', '-p', SANDBOX, *map(str, argv)], cwd=home, env=env, capture_output=True, text=True,
                            timeout=timeout, stdin=subprocess.DEVNULL)
    return result.returncode, result.stdout, result.stderr


def extractor_case(exe, target, encoding, pki_files, home, verify=True, wrong=False, timeout=180):
    """yt-dlp --impersonate TARGET -J against the fixture page. Returns the client result and
    what the server observed. With verify, the client trusts the throwaway CA through
    SSL_CERT_FILE (curl_cffi's documented CA override); validation stays on."""
    cert, key = pki_files['wrong' if wrong else 'leaf']
    with Server(cert, key, encoding) as server:
        url = f'https://localhost:{server.port}/watch'
        argv = [exe, '--ignore-config', '--no-plugin-dirs', '--no-cache-dir', '--impersonate', target, '-J', url]
        code, out, err = run_client(argv, home, {'SSL_CERT_FILE': str(pki_files['ca'])} if verify else {}, timeout)
        threading.Event().wait(0.2)
        with server.lock:
            seen = json.loads(json.dumps(server.connections))
    info = None
    if code == 0:
        try:
            info = json.loads(out)
        except ValueError:
            info = None
    formats = [f.get('url') for f in (info or {}).get('formats', [])] if info else []
    return {'target': target, 'encoding': encoding, 'verify_file': verify, 'wrong_name': wrong, 'exit': code, 'port': server.port,
            'found_video': f'https://localhost:{server.port}/clip.mp4' in formats + [(info or {}).get('url')],
            'stderr_tail': err.strip().splitlines()[-3:], 'connections': seen}
