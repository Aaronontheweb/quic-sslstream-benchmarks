#!/usr/bin/env python3
"""Create an untrusted localhost identity and pin libraries loaded by a real QUIC listener."""
import hashlib
import json
import os
import subprocess
import time
from pathlib import Path

from run_spike import BINARY, IDENTITY, LAUNCHER, NATIVE_PINS, ROOT, digest, records, stop


def main():
    if not BINARY.is_file():
        raise SystemExit('Build the Release application before running prepare.py')
    if NATIVE_PINS.exists() or IDENTITY.exists():
        raise SystemExit('Local setup already exists; reuse it or explicitly remove .local/ to prepare again')
    os.umask(0o077)
    IDENTITY.mkdir(parents=True)
    cert = IDENTITY / 'localhost.pem'
    key = IDENTITY / 'localhost.key'
    subprocess.run(['openssl', 'req', '-x509', '-newkey', 'rsa:2048', '-sha256', '-days', '30',
                    '-nodes', '-subj', '/CN=localhost', '-addext', 'subjectAltName=DNS:localhost,IP:127.0.0.1',
                    '-keyout', str(key), '-out', str(cert)], check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    subprocess.run(['openssl', 'pkcs12', '-export', '-inkey', str(key), '-in', str(cert),
                    '-out', str(IDENTITY / 'loopback.pfx'), '-passout', 'pass:'], check=True)
    der = subprocess.check_output(['openssl', 'x509', '-in', str(cert), '-outform', 'DER'])
    pin = hashlib.sha1(der).hexdigest().upper()
    (IDENTITY / 'thumbprint.txt').write_text(pin + '\n')
    log = ROOT / '.local/setup.log'
    with log.open('w') as output:
        process = subprocess.Popen([str(LAUNCHER), str(BINARY), 'server', '--transport', 'quic',
                                    '--cert', str(IDENTITY / 'loopback.pfx'), '--pin', pin],
                                   cwd=ROOT, stdout=output, stderr=subprocess.STDOUT, start_new_session=True)
        try:
            deadline = time.monotonic() + 15
            while time.monotonic() < deadline and process.poll() is None:
                if records(log, 'READY'):
                    break
                time.sleep(.02)
            else:
                raise RuntimeError('QUIC setup probe failed; inspect ignored .local/setup.log')
            native = {}
            prefixes = ('libmsquic', 'libcoreclr', 'libssl', 'libcrypto')
            for line in Path(f'/proc/{process.pid}/maps').read_text().splitlines():
                file = Path(line.split()[-1])
                if file.is_absolute() and file.name.startswith(prefixes):
                    value = digest(file)
                    if file.name in native and native[file.name] != value:
                        raise RuntimeError('Multiple different native libraries share a basename')
                    native[file.name] = value
            if any(not any(name.startswith(prefix) for name in native) for prefix in prefixes):
                raise RuntimeError('QUIC probe did not load every required native library family')
            NATIVE_PINS.write_text(json.dumps(native, indent=2) + '\n')
        finally:
            stop(process)
    print('Prepared ignored local identity and native library pins. No trust-store changes.')


if __name__ == '__main__':
    main()
