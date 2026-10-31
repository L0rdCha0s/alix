#!/usr/bin/env python3
"""Check production buffered I/O, errors, registry ownership and close races."""
import os, shlex, sys
sys.dont_write_bytecode=True
from audio_stream_contract_test import compile_and_run
from stdio_stream_contract_test import build_program

code=build_program().replace('int main(void) {','static int __attribute__((unused)) unbuffered_main(void) {',1)
code+=r'''
static void output_modes(void) {
    native_FILE *s=open_stream("w+","",true);model_file_t *f=model_file(s->fd);
    char *caller=malloc(8);CHECK(caller);
    CHECK(native_setvbuf(s,caller,_IOFBF,8)==0);memset(caller,0xff,8);free(caller);
    CHECK(native_fwrite("abc",1,3,s)==3 && !f->write_calls && native_ftell(s)==3);
    CHECK(native_fwrite("defgh",1,5,s)==5 && f->size==8 && !memcmp(f->data,"abcdefgh",8));
    CHECK(native_fwrite("ij",1,2,s)==2 && native_ftell(s)==10 && f->size==8);
    CHECK(native_fflush(NULL)==0 && f->size==10 && !memcmp(f->data,"abcdefghij",10));
    CHECK(native_fwrite("K",1,1,s)==1 && native_fseek(s,0,SEEK_SET)==0 && f->size==11);
    char data[16]={0};CHECK(native_fread(data,1,11,s)==11 && !strcmp(data,"abcdefghijK"));
    CHECK(native_fclose(s)==0);

    s=open_stream("w","",true);f=model_file(s->fd);CHECK(native_setvbuf(s,NULL,_IOLBF,8)==0);
    CHECK(native_fwrite("abc",1,3,s)==3&&!f->write_calls);
    CHECK(native_fwrite("def\nx",1,5,s)==5&&f->size==7&&!memcmp(f->data,"abcdef\n",7)&&s->write_length==1);
    CHECK(native_fflush(NULL)==0&&f->size==8&&f->data[7]=='x');
    CHECK(native_fwrite("123456789",1,9,s)==9&&f->size==16&&s->write_length==1);
    unsigned char *buffer=s->buffer;CHECK(native_setvbuf(s,NULL,_IONBF,0)==-1&&test_errno==EBUSY&&s->buffer==buffer);
    CHECK(native_fclose(s)==0&&f->size==17&&f->data[16]=='9');

    s=open_stream("w","",true);f=model_file(s->fd);CHECK(native_setvbuf(s,NULL,_IOFBF,0)==0&&s->buffer_capacity==BUFSIZ);
    buffer=s->buffer;fail_file_allocation=true;
    CHECK(native_setvbuf(s,NULL,_IOLBF,32)==-1&&test_errno==ENOMEM&&s->buffer==buffer&&s->buffering==_IOFBF);
    CHECK(native_setvbuf(s,(char*)1,_IOLBF,0)==-1&&test_errno==EINVAL&&s->buffer==buffer);
    CHECK(native_setvbuf(s,NULL,99,8)==-1&&test_errno==EINVAL&&s->buffer==buffer);
    CHECK(native_setvbuf(s,NULL,_IONBF,SIZE_MAX)==0&&!s->buffer);
    CHECK(native_fwrite("x",1,1,s)==1&&f->size==1);CHECK(native_fclose(s)==0);
    s=open_stream("w","",true);f=model_file(s->fd);native_setbuf(s,(char*)1);
    CHECK(native_fwrite("held",1,4,s)==4&&!f->size&&native_fclose(s)==0&&f->size==4);
}
static void input_and_positions(void) {
    native_FILE *s=open_stream("r+","abcdef\nXYZ",true);model_file_t *f=model_file(s->fd);
    CHECK(native_setvbuf(s,NULL,_IOFBF,4)==0&&native_fgetc(s)=='a'&&f->position==4&&native_ftell(s)==1);
    CHECK(native_ungetc('Q',s)=='Q'&&native_ftell(s)==0);
    CHECK(native_fflush(NULL)==0&&f->position==4&&s->pushback_pending);
    CHECK(native_fflush(s)==0&&f->position==0&&!s->pushback_pending&&!s->read_end);
    CHECK(native_fgetc(s)=='a'&&native_fwrite("Q",1,1,s)==1&&native_ftell(s)==2&&f->position==1);
    CHECK(native_fflush(s)==0&&f->position==2&&!memcmp(f->data,"aQcdef",6));
    CHECK(native_fseek(s,0,SEEK_SET)==0&&native_fgetc(s)=='a'&&native_fseek(s,1,SEEK_CUR)==0&&native_fgetc(s)=='c');
    native_fpos_t saved;CHECK(native_fgetpos(s,&saved)==0&&saved==3);
    CHECK(native_fgetc(s)=='d'&&native_fsetpos(s,&saved)==0&&native_fgetc(s)=='d');
    native_rewind(s);CHECK(native_fgetc(s)=='a');CHECK(native_fclose(s)==0);

    s=open_stream("r","abcdef",false);f=model_file(s->fd);CHECK(native_setvbuf(s,NULL,_IOFBF,4)==0);
    CHECK(native_fgetc(s)=='a'&&f->position==4);
    CHECK(native_fflush(s)==EOF&&test_errno==ESPIPE&&s->read_end-s->read_position==3);
    native_clearerr(s);CHECK(native_fgetc(s)=='b');CHECK(native_fseek(s,0,SEEK_CUR)==-1&&test_errno==ESPIPE);
    CHECK(native_fgetc(s)=='c'&&native_fgetc(s)=='d'&&native_fgetc(s)=='e'&&native_fgetc(s)=='f');
    CHECK(native_fgetc(s)==EOF&&native_feof(s));CHECK(native_fclose(s)==0);

    native_FILE *out=open_stream("w","",true);model_file_t *output=model_file(out->fd);
    CHECK(native_setvbuf(out,NULL,_IOLBF,16)==0&&native_fwrite("prompt",1,6,out)==6&&!output->size);
    s=open_stream("r","a\nbc",true);f=model_file(s->fd);CHECK(native_setvbuf(s,NULL,_IOFBF,4)==0);
    CHECK(native_fgetc(s)=='a'&&!output->size);CHECK(native_fclose(s)==0);
    s=open_stream("r","a\nbc",true);f=model_file(s->fd);CHECK(native_setvbuf(s,NULL,_IOLBF,4)==0);
    CHECK(native_fgetc(s)=='a'&&output->size==6&&f->position==2&&native_fgetc(s)=='\n');
    CHECK(native_fclose(s)==0&&native_fclose(out)==0);

    s=open_stream("a+","abc",true);f=model_file(s->fd);CHECK(native_setvbuf(s,NULL,_IOFBF,8)==0);
    CHECK(native_fseek(s,0,SEEK_SET)==0&&native_fputc('X',s)=='X'&&native_ftell(s)==4);
    f->data[f->size++]='Y';CHECK(native_ftell(s)==5&&native_fflush(s)==0&&f->size==5&&!memcmp(f->data,"abcYX",5));
    CHECK(native_fclose(s)==0);
}
static void output_failures(void) {
    native_FILE *s=open_stream("w","",true);model_file_t *f=model_file(s->fd);CHECK(native_setvbuf(s,NULL,_IOFBF,8)==0);
    CHECK(native_fwrite("old",1,3,s)==3);f->write_chunk=2;f->write_fail_after=1;f->write_error=ENOSPC;
    CHECK(native_fwrite("NEWxx",1,5,s)==0&&native_ferror(s)&&test_errno==ENOSPC&&f->size==2&&s->write_length==1);
    native_clearerr(s);f->write_fail_after=UINT_MAX;CHECK(native_fflush(s)==0&&f->size==3&&!memcmp(f->data,"old",3));
    CHECK(native_fwrite("NEWxx",1,5,s)==5&&native_fflush(s)==0&&f->size==8&&!memcmp(f->data,"oldNEWxx",8));
    CHECK(native_fclose(s)==0);
    s=open_stream("w","",true);f=model_file(s->fd);CHECK(native_setvbuf(s,NULL,_IOFBF,8)==0);
    CHECK(native_fwrite("old",1,3,s)==3);f->write_chunk=5;f->write_fail_after=1;f->write_error=ENOSPC;
    CHECK(native_fwrite("NEWxx",1,5,s)==2&&f->size==5&&!s->write_length&&!memcmp(f->data,"oldNE",5));
    native_clearerr(s);f->write_fail_after=UINT_MAX;
    CHECK(native_fwrite("Wxx",1,3,s)==3&&native_fflush(s)==0&&!memcmp(f->data,"oldNEWxx",8));CHECK(native_fclose(s)==0);
    s=open_stream("w","",true);f=model_file(s->fd);CHECK(native_setvbuf(s,NULL,_IOFBF,8)==0);
    CHECK(native_fwrite("abcde",1,5,s)==5);f->write_chunk=2;f->write_fail_after=1;f->write_error=ENOSPC;
    CHECK(native_fflush(NULL)==EOF&&test_errno==ENOSPC&&s->write_length==3&&f->size==2);
    native_clearerr(s);f->write_fail_after=UINT_MAX;CHECK(native_fflush(s)==0&&f->size==5&&!memcmp(f->data,"abcde",5));
    CHECK(native_fwrite("lost",1,4,s)==4);f->write_fail_after=f->write_calls;f->close_error=EIO;
    CHECK(native_fclose(s)==EOF&&test_errno==ENOSPC&&!f->opened);
}
typedef struct { native_FILE *stream; unsigned started,done; int result; } close_state_t;
static void *global_flush(void *argument) { int *result=argument;*result=native_fflush(NULL);return NULL; }
static void *close_stream(void *argument) {
    close_state_t *state=argument;__atomic_store_n(&state->started,1,__ATOMIC_RELEASE);
    state->result=native_fclose(state->stream);__atomic_store_n(&state->done,1,__ATOMIC_RELEASE);return NULL;
}
static void close_during_flush(void) {
    native_FILE *s=open_stream("w","",true);model_file_t *f=model_file(s->fd);
    CHECK(native_setvbuf(s,NULL,_IOFBF,16)==0&&native_fwrite("held data",1,9,s)==9);
    f->block_write=true;pthread_t flusher,closer;int flush_result=-9;
    close_state_t *state=calloc(1,sizeof(*state));CHECK(state);state->stream=s;
    CHECK(!pthread_create(&flusher,NULL,global_flush,&flush_result));
    while(!__atomic_load_n(&f->write_entered,__ATOMIC_ACQUIRE))sched_yield();
    CHECK(!pthread_create(&closer,NULL,close_stream,state));
    while(!__atomic_load_n(&state->started,__ATOMIC_ACQUIRE))sched_yield();
    /* A blocking callback must not monopolize the registry. */
    native_FILE *other=open_stream("w","",true);CHECK(native_fwrite("ok",1,2,other)==2&&native_fclose(other)==0);
    CHECK(!__atomic_load_n(&state->done,__ATOMIC_ACQUIRE));
    __atomic_store_n(&f->release_write,1,__ATOMIC_RELEASE);
    CHECK(!pthread_join(flusher,NULL)&&!pthread_join(closer,NULL)&&flush_result==0&&state->result==0);
    CHECK(f->size==9&&!memcmp(f->data,"held data",9)&&f->close_calls==1);free(state);
}
int main(void) {
    output_modes();input_and_positions();output_failures();close_during_flush();
    CHECK(!model_file_allocations&&!held_stream);
    CHECK(g_file_registry==&g_stdout_obj&&g_stdout_obj.registry_next==&g_stderr_obj&&g_stderr_obj.registry_next==&g_stdin_obj);
    for(unsigned i=0;i<64;++i)if(files[i]) { CHECK(!files[i]->opened);free(files[i]->data);free(files[i]); }
    puts("BUFFERED_STDIO: PASS modes=3 positions=1 partial_errors=1 no_stack_borrow=1 global_flush_close=1");return 0;
}
'''
previous=os.environ.get('HOST_CC')
try:
    os.environ['HOST_CC']=shlex.join(shlex.split(previous or 'cc')+['-pthread'])
    compile_and_run('stdio-buffer',code)
finally:
    if previous is None:os.environ.pop('HOST_CC',None)
    else:os.environ['HOST_CC']=previous
print('native buffered stdio contracts passed')
