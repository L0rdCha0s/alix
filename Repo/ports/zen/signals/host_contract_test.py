#!/usr/bin/env python3
"""Run the production signal module with modeled kernel boundaries on the host.
Only privileged FXSAVE is substituted; policy/frame/state functions are copied
verbatim. Native compilation and guest tests separately exercise the machine ABI.
"""
from pathlib import Path
import argparse,subprocess,sys
HERE=Path(__file__).resolve().parent;ROOT=HERE.parents[2]
sys.path.insert(0,str(ROOT/'tests'))
from audio_stream_contract_test import function_definition
parser=argparse.ArgumentParser();parser.add_argument('--active',action='store_true');args=parser.parse_args()
tree=ROOT if args.active else HERE/'pending'
source=(tree/'src/kernel/process/process_signal.c').read_text()
source='\n'.join(line for line in source.splitlines() if not line.startswith('#include'))
body=function_definition(source,'static void signal_fxsave(')
source=source.replace(body,'static void signal_fxsave(uint8_t *image) { memcpy(image,model_fp,512); }',1)
out=HERE/'out';out.mkdir(exist_ok=True)
path=out/'host_contract_test.c'
path.write_text((HERE/'host_model.h').read_text()+'\n'+source+'\n'+(HERE/'host_contract_cases.c').read_text())
for sanitize in [False,True]:
    exe=out/('host_contract_san' if sanitize else 'host_contract')
    flags=['-fsanitize=address,undefined','-fno-omit-frame-pointer'] if sanitize else []
    subprocess.run(['cc','-std=c11','-O1','-g','-Wall','-Wextra','-Werror','-DTTF_HOST_BUILD','-iquote',str(tree/'include'),'-iquote',str(ROOT/'include'),*flags,str(path),'-o',str(exe)],check=True)
    subprocess.run([str(exe)],check=True)
