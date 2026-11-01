#!/usr/bin/env python3
"""Build actual upstream cubeb/Speex plus the Alix backend as a native ELF."""
from pathlib import Path
import argparse,hashlib,json,os,shlex,shutil,subprocess,sys
ROOT=Path(__file__).resolve().parents[3]
sys.path.insert(0,str(ROOT/'ports/zen'))
from patch_engine import apply_patches

def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--profiler-provider', action='store_true')
    args=parser.parse_args()
    engine=ROOT/'ports/zen/upstream/firefox-159.0'
    apply_patches(engine)
    objects=shlex.split(os.environ.get('ALIX_RUNTIME_OBJECTS',''))
    if not objects:raise RuntimeError('use make zen-cubeb-test to supply current native runtime objects')
    manifest=ROOT/'ports/zen/upstream/alix-toolchain/runtime-objects.json'
    temporary=manifest.with_name('.cubeb-runtime-'+str(os.getpid())+'.json')
    temporary.write_text(json.dumps([str((ROOT/item).resolve()) for item in objects],indent=2)+'\n')
    temporary.replace(manifest)
    build=ROOT/'ports/zen/upstream'/('cubeb-alix-profiler-test' if args.profiler_provider else 'cubeb-alix-test')
    (build/'include/speex').mkdir(parents=True,exist_ok=True)
    (build/'include/mozilla').mkdir(parents=True,exist_ok=True)
    shutil.copyfile(engine/'media/libspeex_resampler/src/speex_resampler.h',build/'include/speex/speex_resampler.h')
    shutil.copyfile(engine/'mozglue/build/arm.h',build/'include/mozilla/arm.h')
    includes=[engine/'media/libcubeb/include',engine/'media/libcubeb/src',engine/'tools/profiler/public',
              engine/'media/libspeex_resampler/src',ROOT/'ports/zen/upstream/obj-js-alix/dist/include',build/'include']
    sources=['media/libcubeb/src/cubeb.c','media/libcubeb/src/cubeb_alix.cpp',
             'media/libcubeb/src/cubeb_log.cpp','media/libcubeb/src/cubeb_mixer.cpp',
             'media/libcubeb/src/cubeb_resampler.cpp','media/libcubeb/src/cubeb_strings.c',
             'media/libcubeb/src/cubeb_utils.cpp','media/libspeex_resampler/src/resample.c',
             'media/libspeex_resampler/src/resample_sse.c','media/libspeex_resampler/src/simd_detect.cpp',
             'mfbt/Assertions.cpp','mozglue/misc/Printf.cpp']
    sources += [str(path.relative_to(engine)) for path in
                sorted((engine/'mfbt/double-conversion/double-conversion').glob('*.cc'))]
    if args.profiler_provider:sources += [str(ROOT/'tests/static_profiler_provider.cpp')]
    compiled=[];provenance={}
    env=os.environ.copy();env['ALIX_RUNTIME_MANIFEST']=str(manifest)
    for path in sources+[str(ROOT/'tests/cubeb_alix_test.cpp')]:
        source=Path(path) if Path(path).is_absolute() else engine/path
        name=str(path).replace('/','_')+'.o';output=build/name
        c=source.suffix=='.c'
        compiler=ROOT/'ports/zen/toolchain'/('alix-clang' if c else 'alix-clang++')
        command=[str(compiler),'-std=gnu11' if c else '-std=c++20','-O2','-DUSE_ALIX=1','-DXP_UNIX=1','-DMOZ_UPROFILER_STATIC=1',
                 '-DCUBEB_GECKO_BUILD=1','-DOUTSIDE_SPEEX=1','-DFLOATING_POINT=1',
                 '-DEXPORT=','-DUSE_SSE=1','-DUSE_SSE2=1','-msse2']
        command += ['-I'+str(directory) for directory in includes]
        if args.profiler_provider:command += ['-DALIX_TEST_LINKED_PROFILER=1']
        subprocess.run(command+['-c',str(source),'-o',str(output)],cwd=ROOT,env=env,check=True)
        compiled.append(output)
        provenance[str(source.relative_to(ROOT))]=hashlib.sha256(source.read_bytes()).hexdigest()
    binary=ROOT/'build/user'/('cubeb_alix_profiler_test.elf' if args.profiler_provider else 'cubeb_alix_test.elf')
    subprocess.run([str(ROOT/'ports/zen/toolchain/alix-clang++'),*map(str,compiled),'-o',str(binary)],
                   cwd=ROOT,env=env,check=True)
    if subprocess.check_output(['x86_64-elf-nm','--undefined-only',str(binary)],text=True).strip():
        raise RuntimeError('unresolved symbols in native cubeb acceptance ELF')
    metadata={'sources':provenance,'linked_profiler':args.profiler_provider,
              'elf':str(binary.relative_to(ROOT)),
              'elf_sha256':hashlib.sha256(binary.read_bytes()).hexdigest(),
              'runtime_objects':{str(Path(path).relative_to(ROOT)):hashlib.sha256(Path(path).read_bytes()).hexdigest()
                                 for path in json.loads(manifest.read_text())},
              'patch_series_sha256':hashlib.sha256((ROOT/'ports/zen/patches/series.json').read_bytes()).hexdigest()}
    (ROOT/'build/ports/zen'/(binary.stem+'-build.json')).write_text(json.dumps(metadata,indent=2)+'\n')
    print('Actual upstream cubeb/Speex Alix acceptance ELF linked:',binary)
    return 0

if __name__=='__main__':sys.exit(main())
