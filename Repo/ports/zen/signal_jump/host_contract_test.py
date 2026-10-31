#!/usr/bin/env python3
from pathlib import Path
import argparse,subprocess,sys
HERE=Path(__file__).resolve().parent;ROOT=HERE.parents[2]
parser=argparse.ArgumentParser();parser.add_argument('--active',action='store_true');args=parser.parse_args()
tree=ROOT if args.active else HERE/'pending';sys.dont_write_bytecode=True;sys.path.insert(0,str(ROOT/'tests'))
from audio_stream_contract_test import function_definition
source=(tree/'src/kernel/process/process_signal.c').read_text();source='\n'.join(line for line in source.splitlines() if not line.startswith('#include'))
old=function_definition(source,'static void signal_fxsave(');source=source.replace(old,'static void signal_fxsave(uint8_t *image){memcpy(image,model_fp,512);}')
model=(tree/'ports/zen/signals/host_model.h').read_text()
cases=(ROOT/'ports/zen/signals/host_contract_cases.c').read_text()
cases=cases.replace('int main(void)',(HERE/'host_cases.c').read_text()+'\nint main(void)')
cases=cases.replace('Native signal production host contracts:', 'Native signal checkpoint + existing signal contracts:')
cases=cases.replace('    frame_contract();','    jump_contracts();\n    frame_contract();')
out=HERE/'out';out.mkdir(exist_ok=True);path=out/'host_test.c';path.write_text(model+'\n'+source+'\n'+cases)
for sanitize in [False,True]:
 exe=out/('host_san' if sanitize else 'host');flags=['-fsanitize=address,undefined','-fno-omit-frame-pointer'] if sanitize else []
 subprocess.run(['cc','-std=c11','-O1','-g','-Wall','-Wextra','-Werror','-DTTF_HOST_BUILD','-iquote',str(tree/'include'),'-iquote',str(ROOT/'include'),*flags,str(path),'-o',str(exe)],check=True)
 subprocess.run([str(exe)],check=True)
