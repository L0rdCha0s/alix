#!/usr/bin/env python3
"""Reject corrupt ELF version metadata in both runtime and build-time parsers."""
import ast,contextlib,io,os,struct,tempfile
from pathlib import Path
from audio_stream_contract_test import ROOT,compile_and_run,function_definition

source=(ROOT/'ports/zen/upstream/firefox-159.0/python/mozbuild/mozbuild/action/check_binary.py').read_text()
node=next(n for n in ast.parse(source).body if isinstance(n,ast.FunctionDef) and n.name=='check_alix_static_elf')
namespace={'os':os,'struct':struct};exec(compile(ast.Module(body=[node],type_ignores=[]),'<active-version-validator>','exec'),namespace)
validate=namespace['check_alix_static_elf']

class Image:
    def __init__(self,path):
        self.data=path.read_bytes();h=struct.unpack_from('<16sHHIQQQIHHHHHH',self.data)
        self.loads=[struct.unpack_from('<IIQQQQQQ',self.data,h[5]+i*56)for i in range(h[10])]
        dynamic=next(p for p in self.loads if p[0]==2);self.tags={};self.tag_offsets={}
        for at in range(dynamic[2],dynamic[2]+dynamic[5],16):
            tag,value=struct.unpack_from('<qQ',self.data,at)
            if not tag:break
            self.tags[tag]=value;self.tag_offsets[tag]=at
    def offset(self,address):
        for tag,flags,off,virtual,physical,filesz,memsz,align in self.loads:
            if tag==1 and virtual<=address<virtual+filesz:return off+address-virtual
        raise RuntimeError('fixture virtual address not in load')
    def field(self,offset,fmt,value):
        data=bytearray(self.data);struct.pack_into(fmt,data,offset,value);return data

directory=ROOT/'build/ports/zen/version-loader';provider=Image(directory/'libversion_provider.so');consumer=Image(directory/'libversion_consumer.so')
cases=[]
def mutation(image,label,offset,fmt,value):cases.append((label,image.field(offset,fmt,value)))
for label,image in (('provider',provider),('consumer',consumer)):
    validate(directory/('libversion_'+label+'.so'))
    mutation(image,label+' unaligned versym',image.tag_offsets[0x6ffffff0]+8,'<Q',image.tags[0x6ffffff0]+1)
    mutation(image,label+' outside versym',image.tag_offsets[0x6ffffff0]+8,'<Q',1<<63)
    mutation(image,label+' hidden reserved symbol',image.offset(image.tags[0x6ffffff0]),'<H',0x8000)
    mutation(image,label+' hash budget',image.offset(image.tags[4]),'<I',2000001)

definition=provider.offset(provider.tags[0x6ffffffc]);record=struct.unpack_from('<HHHHIII',provider.data,definition);aux=definition+record[5]
for label,offset,fmt,value in (
    ('definition version',definition,'<H',2),('definition flags',definition+2,'<H',8),
    ('definition index',definition+4,'<H',0),('definition count',definition+6,'<H',0),
    ('definition aux',definition+12,'<I',0),('definition hash',definition+8,'<I',record[4]^1),
    ('definition name',aux,'<I',0xffffffff),('definition aux tail',aux+4,'<I',8),
    ('definition chain overlap',definition+16,'<I',20),('definition early tail',definition+16,'<I',0),
    ('definition count pair',provider.tag_offsets[0x6ffffffd]+8,'<Q',0),
    ('definition resource count',provider.tag_offsets[0x6ffffffd]+8,'<Q',32768),
):mutation(provider,label,offset,fmt,value)
mutation(provider,'duplicate definition index',definition+record[6]+4,'<H',1)
data=bytearray(provider.data);at=provider.tag_offsets[14];struct.pack_into('<qQ',data,at,0x6ffffffc,provider.tags[0x6ffffffc]);cases.append(('duplicate version tag',data))
requirement=consumer.offset(consumer.tags[0x6ffffffe]);header=struct.unpack_from('<HHIII',consumer.data,requirement);aux=requirement+header[3]
for label,offset,fmt,value in (
    ('requirement version',requirement,'<H',2),('requirement count',requirement+2,'<H',0),
    ('requirement file',requirement+4,'<I',0),('requirement aux',requirement+8,'<I',0),
    ('requirement tail',requirement+12,'<I',16),('requirement flags',aux+4,'<H',1),
    ('requirement index',aux+6,'<H',1),('requirement hash',aux,'<I',struct.unpack_from('<I',consumer.data,aux)[0]^1),
    ('requirement name',aux+8,'<I',0xffffffff),('requirement early aux tail',aux+12,'<I',0),
    ('requirement count pair',consumer.tag_offsets[0x6fffffff]+8,'<Q',0),
):mutation(consumer,label,offset,fmt,value)
symbols=provider.offset(provider.tags[6]);strings=provider.offset(provider.tags[5]);count=struct.unpack_from('<II',provider.data,provider.offset(provider.tags[4]))[1]
for i in range(1,count):
    name=struct.unpack_from('<I',provider.data,symbols+i*24)[0];start=strings+name;end=provider.data.index(0,start)
    if provider.data[start:end]==b'versioned_value':
        mutation(provider,'unknown symbol version',provider.offset(provider.tags[0x6ffffff0])+i*2,'<H',1234);break
else:raise RuntimeError('missing versioned fixture symbol')

# Reuse the real runtime's existing host VM/allocator model; all parser and
# resolution code comes from the active dlfcn.c, not a metadata reimplementation.
with contextlib.redirect_stdout(io.StringIO()):
    import dynamic_loader_contract_test as base
program=base.code[:base.code.index('int main(void){initialize_model();')]
program='#include <pthread.h>\n'+program
for signature in ('static unsigned open_and_close(', 'static void metadata_mutations('):
    program=program.replace(function_definition(program,signature),'',1)
program=program.replace('"malloc","free","strcpy","strcmp",','"version_events","version_constructor_calls","malloc","free","strcpy","strcmp",')
program+=r'''
typedef struct{void*handle;unsigned failed;}version_job_t;
static void*version_worker(void*context){
    version_job_t*j=context;
    for(unsigned n=0;n<64;++n){
        int*old=model_dlvsym(j->handle,"versioned_tls","ALIX_1");
        int*current=model_dlvsym(j->handle,"versioned_tls","ALIX_2");
        if(!old||!current||*old!=101+(int)n||*current!=202+(int)n){j->failed=1;break;}
        ++*old;++*current;
    }
    __alix_dl_thread_cleanup();return NULL;
}
static bool inspect_versions(const char *path,unsigned failure){
    initialize_model();calls=0;injected=false;fail_at=failure;dl_pending=false;
    dl_module*m=owned_calloc(1,sizeof(*m));bool ok=false;
    if(m){m->path=owned_strdup(path);if(m->path)ok=dl_map_file(m);}
    if(failure)CHECK(injected&&!ok);
    if(m){if(m->reservation)CHECK(!model_munmap((void*)m->reservation,m->reservation_bytes));
        owned_free(m->segments);owned_free(m->versions);owned_free(m->path);owned_free(m);}
    CHECK(!allocations&&!live_files&&!live_maps);return ok;
}
int main(void){
'''
with tempfile.TemporaryDirectory(prefix='alix-version-metadata-') as temporary:
    temporary=Path(temporary)
    for i,(label,data) in enumerate(cases):
        path=temporary/f'bad-{i}.elf';path.write_bytes(data)
        try:validate(path)
        except RuntimeError:pass
        else:raise RuntimeError('build validator accepted '+label)
        program+=f'CHECK(!inspect_versions("{path}",0));\n'
    for path in (directory/'libversion_provider.so',directory/'libversion_consumer.so',directory/'libversion_bad.so'):
        validate(path);program+=f'CHECK(inspect_versions("{path}",0));\n'
    program+=f'CHECK(inspect_versions("{directory / "libversion_provider.so"}",0));unsigned points=calls;\n'
    program+=f'for(unsigned i=1;i<=points;++i)CHECK(!inspect_versions("{directory / "libversion_provider.so"}",i));\n'
    program+='initialize_model();fail_at=0;dl_pending=false;\n'
    program+=f'void*handle=model_dlopen("{directory / "libversion_provider.so"}",RTLD_NOW|RTLD_GLOBAL);CHECK(handle);\n'
    program+='CHECK(model_dlsym(handle,"versioned_value")==model_dlvsym(handle,"versioned_value","ALIX_2"));\n'
    program+='CHECK(model_dlvsym(handle,"versioned_value","ALIX_1")!=model_dlvsym(handle,"versioned_value","ALIX_2"));\n'
    program+='CHECK(*(int*)model_dlvsym(handle,"versioned_data","ALIX_1")==3&&*(int*)model_dlsym(handle,"versioned_data")==7);\n'
    program+='version_job_t*jobs=owned_calloc(8,sizeof(*jobs));pthread_t*threads=owned_calloc(8,sizeof(*threads));CHECK(jobs&&threads);\n'
    program+='for(unsigned i=0;i<8;++i){jobs[i].handle=handle;CHECK(!pthread_create(&threads[i],NULL,version_worker,&jobs[i]));}\n'
    program+='for(unsigned i=0;i<8;++i)CHECK(!pthread_join(threads[i],NULL)&&!jobs[i].failed);owned_free(jobs);owned_free(threads);\n'
    program+='CHECK(!model_dlclose(handle)&&!allocations&&!live_maps);\n'
    program+='puts("ELF_VERSION_METADATA: PASS runtime_and_validator=1 allocation_faults=1 no_leaks=1");return 0;}\n'
    compile_and_run('elf-version-metadata',program)
print(f'ELF version metadata: PASS {len(cases)} corruptions rejected by runtime/build validator, real aliases/requirements accepted')
