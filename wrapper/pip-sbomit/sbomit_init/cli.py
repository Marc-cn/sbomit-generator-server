import os, sys, stat, tempfile, subprocess, urllib.request

INSTALLER_URL = "https://raw.githubusercontent.com/sbomit/sbomit/main/install.sh"

def main():
    args = sys.argv[1:]
    if '--version' in args or '-v' in args:
        from sbomit_init import __version__
        print('sbomit-init ' + __version__); sys.exit(0)
    print('==> Downloading sbomit-init...')
    with tempfile.NamedTemporaryFile(suffix='.sh', delete=False) as f:
        urllib.request.urlretrieve(INSTALLER_URL, f.name)
        os.chmod(f.name, os.stat(f.name).st_mode | stat.S_IEXEC)
        script = f.name
    try:
        sys.exit(subprocess.run(['bash', script] + args).returncode)
    finally:
        os.unlink(script)

if __name__ == '__main__':
    main()
