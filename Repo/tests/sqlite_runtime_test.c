#include "sqlite3.h"
#include "pthread.h"
#include "usyscall.h"
#include "unistd.h"
#include "spawn.h"
#include "sys/wait.h"
#include "stdlib.h"
#include "stdio.h"
#include "string.h"
#include "serial.h"
#include "errno.h"
#include "dlfcn.h"
#define APIS(X) \
 X(init,sqlite3_initialize) X(shutdown,sqlite3_shutdown) X(threadsafe,sqlite3_threadsafe) \
 X(version_number,sqlite3_libversion_number) X(version,sqlite3_libversion) X(vfs,sqlite3_vfs_find) \
 X(open,sqlite3_open_v2) X(close,sqlite3_close) X(exec,sqlite3_exec) X(error,sqlite3_errmsg) \
 X(prepare,sqlite3_prepare_v2) X(step,sqlite3_step) X(integer,sqlite3_column_int) X(text,sqlite3_column_text) \
 X(finalize,sqlite3_finalize) X(timeout,sqlite3_busy_timeout) \
 X(extension,sqlite3_auto_extension)
typedef struct sqlite3_api_routines sqlite3_api_routines;
typedef struct {
#define FIELD(field,name) __typeof__(&name) field;
    APIS(FIELD)
#undef FIELD
    int(*fts5)(sqlite3*,char**,const sqlite3_api_routines*);
    int(*vec)(sqlite3*,char**,const sqlite3_api_routines*);
    void*library;
} sqlite_api_t;
static sqlite_api_t api;
static int load_library(void)
{
    uintptr_t*guard=dlsym(RTLD_DEFAULT,"__stack_chk_guard");
    if(!guard||!*guard){serial_printf("SQLITE_RUNTIME_SUPPORT: missing initialized stack guard\n");return 1;}
    api.library=dlopen("/tmp/libmozsqlite3.so",RTLD_NOW|RTLD_GLOBAL|RTLD_NODELETE);
    if(!api.library){serial_printf("SQLITE_LIBRARY_ERROR: %s\n",dlerror());return 1;}
#define LOAD(field,name) api.field=(__typeof__(api.field))dlsym(api.library,#name);if(!api.field){serial_printf("SQLITE_IMPORT_ERROR: %s %s\n",#name,dlerror());return 1;}
    APIS(LOAD)
#undef LOAD
    api.fts5=dlsym(api.library,"sqlite3_fts5_init");api.vec=dlsym(api.library,"sqlite3_vec_init");
    if(!api.fts5||!api.vec||api.init()||api.extension((void(*)(void))api.fts5)||api.extension((void(*)(void))api.vec))return 1;
    return 0;
}
#define sqlite3_initialize api.init
#define sqlite3_shutdown api.shutdown
#define sqlite3_threadsafe api.threadsafe
#define sqlite3_libversion_number api.version_number
#define sqlite3_libversion api.version
#define sqlite3_vfs_find api.vfs
#define sqlite3_open_v2 api.open
#define sqlite3_close api.close
#define sqlite3_exec api.exec
#define sqlite3_errmsg api.error
#define sqlite3_prepare_v2 api.prepare
#define sqlite3_step api.step
#define sqlite3_column_int api.integer
#define sqlite3_column_text api.text
#define sqlite3_finalize api.finalize
#define sqlite3_busy_timeout api.timeout
#define DB_PATH "/tmp/sqlite-disk/browser.sqlite"
#define CHECK(c) do{if(!(c)){serial_printf("SQLITE_RUNTIME_TEST: FAIL line=%u errno=%d\n",__LINE__,errno);return 1;}}while(0)
typedef struct {pthread_t thread;unsigned cpu,failed;sqlite3*db;char sql[256];} writer_t;
typedef struct {sqlite3*db,*reader;sqlite3_stmt*statement;writer_t writers[8];char*arguments[4];pid_t child;int status;} fixture_t;
static int execute(sqlite3*db,const char*sql)
{
    int rc=sqlite3_exec(db,sql,NULL,NULL,NULL);
    if(rc)serial_printf("SQLITE_ERROR: rc=%d detail=%s sql=%s\n",rc,sqlite3_errmsg(db),sql);
    return rc;
}
static int scalar(sqlite3*db,const char*sql,int expected)
{
    sqlite3_stmt*statement=NULL;int rc=sqlite3_prepare_v2(db,sql,-1,&statement,NULL);
    bool ok=!rc&&sqlite3_step(statement)==SQLITE_ROW&&sqlite3_column_int(statement,0)==expected;
    int done=sqlite3_finalize(statement);return !ok||done;
}
static int text_value(sqlite3*db,const char*sql,const char*expected)
{
    sqlite3_stmt*statement=NULL;int rc=sqlite3_prepare_v2(db,sql,-1,&statement,NULL);
    bool ok=!rc&&sqlite3_step(statement)==SQLITE_ROW&&sqlite3_column_text(statement,0)&&
        !strcmp((const char*)sqlite3_column_text(statement,0),expected);
    int done=sqlite3_finalize(statement);return !ok||done;
}
static int child_main(const char*mode,const char*path)
{
    fixture_t*f=calloc(1,sizeof(*f));CHECK(f);
    CHECK(sqlite3_open_v2(path,&f->db,SQLITE_OPEN_READWRITE|SQLITE_OPEN_FULLMUTEX,NULL)==SQLITE_OK);
    if(!strcmp(mode,"busy"))CHECK(sqlite3_exec(f->db,"BEGIN IMMEDIATE",NULL,NULL,NULL)==SQLITE_BUSY);
    else CHECK(!execute(f->db,"INSERT INTO records VALUES(2000, 'child')"));
    CHECK(sqlite3_close(f->db)==SQLITE_OK);free(f);return 0;
}
static int spawn_child(fixture_t*f,const char*mode)
{
    f->arguments[0]="/tmp/test.elf";f->arguments[1]=(char*)mode;f->arguments[2]=DB_PATH;
    CHECK(!posix_spawn(&f->child,f->arguments[0],NULL,NULL,f->arguments,NULL));
    CHECK(waitpid(f->child,&f->status,0)==f->child&&WIFEXITED(f->status)&&WEXITSTATUS(f->status)==0);
    return 0;
}
static void *writer(void*argument)
{
    writer_t*w=argument;
    if(sys_thread_set_affinity(w->cpu)||sys_thread_cpu()!=w->cpu){w->failed=1;return NULL;}
    if(sqlite3_open_v2(DB_PATH,&w->db,SQLITE_OPEN_READWRITE|SQLITE_OPEN_FULLMUTEX,NULL)){w->failed=2;return NULL;}
    sqlite3_busy_timeout(w->db,10000);
    if(execute(w->db,"BEGIN IMMEDIATE")){w->failed=3;goto finished;}
    for(unsigned n=0;n<12;++n){snprintf(w->sql,sizeof(w->sql),"INSERT INTO records VALUES(%u, 'worker-%u')",10000+w->cpu*100+n,w->cpu);
        if(execute(w->db,w->sql)){w->failed=4;goto finished;}}
    if(execute(w->db,"COMMIT"))w->failed=5;
finished:
    if(sqlite3_close(w->db))w->failed=6;
    w->db=NULL;return NULL;
}
int main(int argc,char**argv)
{
    CHECK(!load_library());
    if(argc==3)return child_main(argv[1],argv[2]);
    fixture_t*f=calloc(1,sizeof(*f));CHECK(f&&sqlite3_threadsafe()&&sqlite3_initialize()==SQLITE_OK);
    CHECK(sqlite3_libversion_number()==SQLITE_VERSION_NUMBER);
    serial_printf("SQLITE_NATIVE: version=%s vfs=%s threadsafe=%d\n",sqlite3_libversion(),sqlite3_vfs_find(NULL)->zName,sqlite3_threadsafe());
    if(argc==2&&!strcmp(argv[1],"read"))
    {
        CHECK(sqlite3_open_v2("/root/browser.sqlite",&f->db,SQLITE_OPEN_READONLY|SQLITE_OPEN_FULLMUTEX,NULL)==SQLITE_OK);
        CHECK(!scalar(f->db,"SELECT count(*) FROM records",198)&&!text_value(f->db,"PRAGMA integrity_check","ok"));
        CHECK(!scalar(f->db,"SELECT count(*) FROM search WHERE search MATCH 'native'",1)&&
              !scalar(f->db,"SELECT vec_length(embedding) FROM vectors",4));
        CHECK(!sqlite3_close(f->db)&&!sqlite3_shutdown());free(f);
        serial_printf("SQLITE_REMOUNT_TEST: PASS rows=198 integrity=1 readonly=1 full_library=1 fts5=1 vectors=1\n");return 0;
    }
    CHECK(sqlite3_open_v2(DB_PATH,&f->db,SQLITE_OPEN_READWRITE|SQLITE_OPEN_CREATE|SQLITE_OPEN_FULLMUTEX,NULL)==SQLITE_OK);
    CHECK(!execute(f->db,"PRAGMA synchronous=FULL; PRAGMA journal_mode=DELETE; CREATE TABLE records(id INTEGER PRIMARY KEY, value TEXT); BEGIN IMMEDIATE;"));
    CHECK(!execute(f->db,"WITH RECURSIVE n(x) AS (VALUES(0) UNION ALL SELECT x+1 FROM n WHERE x<99) INSERT INTO records SELECT x, 'initial' FROM n; COMMIT;"));
    CHECK(!execute(f->db,"BEGIN; INSERT INTO records VALUES(999,'rollback'); ROLLBACK;")&&!scalar(f->db,"SELECT count(*) FROM records",100));
    CHECK(!scalar(f->db,"SELECT sqrt(81)",9));
    CHECK(!execute(f->db,"CREATE VIRTUAL TABLE search USING fts5(content); INSERT INTO search VALUES('native browser storage');"));
    CHECK(!scalar(f->db,"SELECT count(*) FROM search WHERE search MATCH 'native'",1));
    CHECK(!execute(f->db,"CREATE VIRTUAL TABLE vectors USING vec0(embedding float[4]); INSERT INTO vectors(rowid,embedding) VALUES(1,vec_f32('[1.0,2.0,3.0,4.0]'));"));
    CHECK(!scalar(f->db,"SELECT vec_length(embedding) FROM vectors",4));
    CHECK(!text_value(f->db,"PRAGMA journal_mode=WAL","wal"));
    CHECK(!sqlite3_open_v2(DB_PATH,&f->reader,SQLITE_OPEN_READONLY|SQLITE_OPEN_FULLMUTEX,NULL));
    CHECK(!execute(f->reader,"BEGIN")&&!scalar(f->reader,"SELECT count(*) FROM records",100));
    CHECK(!execute(f->db,"BEGIN IMMEDIATE; INSERT INTO records VALUES(1000,'snapshot'); COMMIT;"));
    CHECK(!scalar(f->reader,"SELECT count(*) FROM records",100)&&!execute(f->reader,"ROLLBACK")&&
        !scalar(f->reader,"SELECT count(*) FROM records",101)&&!sqlite3_close(f->reader));f->reader=NULL;
    CHECK(!execute(f->db,"BEGIN IMMEDIATE")&&!spawn_child(f,"busy")&&!execute(f->db,"ROLLBACK"));
    CHECK(!spawn_child(f,"write")&&!scalar(f->db,"SELECT count(*) FROM records",102));
    for(unsigned cpu=0;cpu<8;++cpu){f->writers[cpu].cpu=cpu;CHECK(!pthread_create(&f->writers[cpu].thread,NULL,writer,&f->writers[cpu]));}
    for(unsigned cpu=0;cpu<8;++cpu){CHECK(!pthread_join(f->writers[cpu].thread,NULL));
        if(f->writers[cpu].failed)serial_printf("SQLITE_WRITER: cpu=%u stage=%u\n",cpu,f->writers[cpu].failed);
        CHECK(!f->writers[cpu].failed);}
    CHECK(!scalar(f->db,"SELECT count(*) FROM records",198)&&!text_value(f->db,"PRAGMA integrity_check","ok"));
    CHECK(!scalar(f->db,"PRAGMA wal_checkpoint(TRUNCATE)",0));
    CHECK(!sqlite3_close(f->db)&&!sqlite3_shutdown());free(f);
    serial_printf("SQLITE_RUNTIME_TEST: PASS cpus=8 rows=198 rollback=1 wal=1 snapshot=1 cross_process=1 busy=1 integrity=1 commit=1 full_library=1 fts5=1 vectors=1\n");return 0;
}
