#!/usr/bin/env python3
"""MIME type detection by extension and magic bytes."""
import sys

EXT_MAP={'.html':'text/html','.htm':'text/html','.css':'text/css','.js':'application/javascript',
    '.json':'application/json','.xml':'text/xml','.txt':'text/plain','.csv':'text/csv',
    '.png':'image/png','.jpg':'image/jpeg','.jpeg':'image/jpeg','.gif':'image/gif',
    '.svg':'image/svg+xml','.webp':'image/webp','.ico':'image/x-icon',
    '.pdf':'application/pdf','.zip':'application/zip','.gz':'application/gzip',
    '.tar':'application/x-tar','.mp3':'audio/mpeg','.wav':'audio/wav','.ogg':'audio/ogg',
    '.mp4':'video/mp4','.webm':'video/webm','.avi':'video/x-msvideo',
    '.py':'text/x-python','.rs':'text/x-rust','.go':'text/x-go','.c':'text/x-c',
    '.md':'text/markdown','.yaml':'text/yaml','.yml':'text/yaml','.toml':'application/toml',
    '.wasm':'application/wasm','.ttf':'font/ttf','.woff':'font/woff','.woff2':'font/woff2'}

MAGIC={b'\x89PNG':' image/png',b'\xff\xd8\xff':'image/jpeg',b'GIF8':'image/gif',
    b'%PDF':'application/pdf',b'PK\x03\x04':'application/zip',b'\x1f\x8b':'application/gzip',
    b'RIFF':'audio/wav',b'\xff\xfb':'audio/mpeg',b'\x00\x00\x00\x1cftyp':'video/mp4'}

def guess_by_ext(filename):
    for ext in sorted(EXT_MAP.keys(),key=len,reverse=True):
        if filename.lower().endswith(ext):return EXT_MAP[ext]
    return'application/octet-stream'

def guess_by_magic(data):
    for sig,mime in MAGIC.items():
        if data[:len(sig)]==sig:return mime.strip()
    return None

def guess(filename=None,data=None):
    if data:
        m=guess_by_magic(data)
        if m:return m
    if filename:return guess_by_ext(filename)
    return'application/octet-stream'

def main():
    if len(sys.argv)>1 and sys.argv[1]=="--test":
        assert guess_by_ext("style.css")=="text/css"
        assert guess_by_ext("photo.PNG")=="image/png"
        assert guess_by_ext("data.unknown")=="application/octet-stream"
        assert guess_by_magic(b'\x89PNG\r\n\x1a\n')=="image/png"
        assert guess_by_magic(b'\xff\xd8\xff\xe0')=="image/jpeg"
        assert guess_by_magic(b'random')==None
        assert guess("app.js")=="application/javascript"
        assert guess(data=b'%PDF-1.4')=="application/pdf"
        print("All tests passed!")
    else:
        f=sys.argv[1] if len(sys.argv)>1 else "document.pdf"
        print(f"{f}: {guess(f)}")
if __name__=="__main__":main()
