#!/usr/bin/env python3
"""Fetch and verify the WASI SDK used to build Gecko's sandboxed libraries."""
import hashlib,json,os,platform,shutil,subprocess,sys,tarfile,tempfile,urllib.request
from pathlib import Path
ROOT=Path(__file__).resolve().parents[2]

def sha(path):
    with path.open('rb') as source:return hashlib.file_digest(source,'sha256').hexdigest()

def host_key():
    system={'Darwin':'macos','Linux':'linux'}.get(platform.system())
    machine={'arm64':'arm64','aarch64':'arm64','x86_64':'x86_64','AMD64':'x86_64'}.get(platform.machine())
    if not system or not machine:raise RuntimeError('unsupported WASI SDK host')
    return machine+'-'+system

def selected_sdk():
    specification=json.loads((ROOT/'ports/zen/host-tools.json').read_text())['wasi_sdk']
    selected=specification['hosts'][host_key()]
    return specification,selected,ROOT/'ports/zen/upstream/tools'/selected['directory']

def verify(directory,specification,selected):
    receipt=directory/'alix-sdk-receipt.json'
    if not receipt.is_file():raise RuntimeError('existing WASI SDK has no verified receipt; left untouched')
    saved=json.loads(receipt.read_text())
    if saved['archive_sha256']!=selected['sha256']:raise RuntimeError('WASI SDK archive identity changed')
    for name,value in saved['files'].items():
        path=directory/name
        if path.is_symlink():
            actual='symlink:'+os.readlink(path)
        elif path.is_file():
            actual=sha(path)
        else:raise RuntimeError('missing WASI SDK file: '+name)
        if actual!=value:raise RuntimeError('modified WASI SDK input: '+name)
    compiler=directory/'bin/clang'
    version=subprocess.check_output([str(compiler),'--version'],text=True).splitlines()[0]
    if not (directory/'share/wasi-sysroot/include/wasm32-wasip1/string.h').is_file():
        raise RuntimeError('WASI SDK lacks actual wasip1 headers')
    if not (directory/'share/wasi-sysroot/lib/wasm32-wasip1/libc.a').is_file():
        raise RuntimeError('WASI SDK lacks actual wasip1 libc')
    print('Verified WASI SDK '+specification['version']+': '+version)
    return directory

def main():
    specification,selected,destination=selected_sdk()
    if destination.exists():verify(destination,specification,selected);return 0
    tools=destination.parent;tools.mkdir(parents=True,exist_ok=True)
    archive=tools/selected['archive']
    if archive.exists():
        if sha(archive)!=selected['sha256']:raise RuntimeError('existing WASI SDK archive hash mismatch; left untouched')
    else:
        with tempfile.NamedTemporaryFile(prefix='.wasi-sdk-download-',dir=tools,delete=False) as output:
            temporary=Path(output.name)
            try:
                print('Fetching pinned WASI SDK: '+selected['url'],flush=True)
                with urllib.request.urlopen(selected['url'],timeout=60) as response:
                    shutil.copyfileobj(response,output,1024*1024)
                output.flush()
                if sha(temporary)!=selected['sha256']:raise RuntimeError('downloaded WASI SDK hash mismatch')
                temporary.replace(archive)
            finally:
                if temporary.exists():temporary.unlink()
    with tempfile.TemporaryDirectory(prefix='.wasi-sdk-extract-',dir=tools) as staging:
        with tarfile.open(archive) as source:source.extractall(staging,filter='data')
        extracted=Path(staging)/selected['directory']
        if not extracted.is_dir():raise RuntimeError('unexpected WASI SDK archive root')
        files={}
        for path in sorted(extracted.rglob('*')):
            if path.is_symlink():files[str(path.relative_to(extracted))]='symlink:'+os.readlink(path)
            elif path.is_file():files[str(path.relative_to(extracted))]=sha(path)
        (extracted/'alix-sdk-receipt.json').write_text(json.dumps({
            'version':specification['version'],'url':selected['url'],'archive_sha256':selected['sha256'],'files':files},indent=2)+'\n')
        extracted.replace(destination)
    verify(destination,specification,selected)
    return 0

if __name__=='__main__':sys.exit(main())
