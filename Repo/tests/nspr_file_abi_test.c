#define CHECK(c,label) do { if(!(c)){serial_printf("NSPR_FILE_ABI_TEST: FAIL %s line=%u errno=%d\n",label,__LINE__,errno);return 1;} }while(0)
typedef struct {
    struct stat metadata;
    PRFileInfo narrow;
    PRFileInfo64 wide;
    PRFileMap mapping;
    PRFileDesc descriptor;
    PRFilePrivate secret;
} file_abi_fixture_t;
int main(void)
{
    file_abi_fixture_t *test=calloc(1,sizeof(*test));CHECK(test,"heap fixture");
    _MD_Open64 native_open=open;
    int fd=native_open("/tmp/nspr-file-abi",O_CREAT|O_TRUNC|O_RDWR|O_CLOEXEC|O_SYNC,0600);
    CHECK(fd>=0 && write(fd,"native",6)==6 && !fstat(fd,&test->metadata),"actual 64-bit open flags and stat");
    CHECK(PR_GetSysfdTableMax()==256 && PR_SetSysfdTableSize(3)==3 &&
        native_open("/tmp/nspr-file-abi",O_RDWR)==-1 && errno==EMFILE &&
        PR_GetSysfdTableMax()==256 && PR_SetSysfdTableSize(1024)==256,"whole NSPR pthread I/O object enforces native limits");
    pt_MakeFdNonblock(fd);
    CHECK((fcntl(fd,F_GETFL)&(O_SYNC|O_NONBLOCK))==(O_SYNC|O_NONBLOCK),"actual NSPR nonblocking helper preserves synchronous status");
    CHECK(!_MD_convert_stat_to_fileinfo(&test->metadata,&test->narrow) &&
        !_MD_convert_stat64_to_fileinfo64(&test->metadata,&test->wide),"real metadata conversion");
    CHECK(test->narrow.type==PR_FILE_FILE && test->wide.type==PR_FILE_FILE && test->narrow.size==6 && test->wide.size==6,"file type and size");
    CHECK(test->wide.modifyTime==(PRInt64)test->metadata.st_mtime*PR_USEC_PER_SEC &&
        test->narrow.modifyTime==test->wide.modifyTime,"native second timestamps");
    CHECK(native_open("/tmp/nspr-file-abi",O_RDWR|((uint64_t)1<<40))==-1 && errno==EINVAL,"high flag bits are not truncated");
    test->metadata.st_size=((uint64_t)1<<33)+17;
    CHECK(!_MD_convert_stat64_to_fileinfo64(&test->metadata,&test->wide) && test->wide.size==((PRInt64)1<<33)+17,"64-bit size preserved");
    CHECK(_MD_convert_stat_to_fileinfo(&test->metadata,&test->narrow)==-1 && captured_error==PR_FILE_TOO_BIG_ERROR,"32-bit size overflow");
    test->metadata.st_size=1;test->metadata.st_mtime=(PRUint64)(PR_INT64_MAX/PR_USEC_PER_SEC);test->metadata.st_ctime=0;
    CHECK(!_MD_convert_stat64_to_fileinfo64(&test->metadata,&test->wide),"maximum timestamp");
    ++test->metadata.st_mtime;
    CHECK(_MD_convert_stat64_to_fileinfo64(&test->metadata,&test->wide)==-1 && captured_error==PR_RANGE_ERROR && captured_os_error==EOVERFLOW,"timestamp overflow 64");
    CHECK(_MD_convert_stat_to_fileinfo(&test->metadata,&test->narrow)==-1 && captured_error==PR_RANGE_ERROR,"timestamp overflow 32");
    CHECK(!ftruncate(fd,8192),"mapping size");
    test->descriptor.secret=&test->secret;test->secret.md.osfd=fd;
    test->mapping.fd=&test->descriptor;test->mapping.md.prot=PROT_READ|PROT_WRITE;test->mapping.md.flags=MAP_SHARED;
    unsigned char *map=_MD_MemMap(&test->mapping,0,8192);
    unsigned char *alias=_MD_MemMap(&test->mapping,4096,4096);
    CHECK(map && alias,"actual NSPR map helpers");map[4096+7]=0x5b;
    CHECK(alias[7]==0x5b && _MD_SyncMemMap(&test->descriptor,map,8192)==PR_SUCCESS,"actual NSPR shared sync helper");
    CHECK(!_MD_MemMap(&test->mapping,1,4096) && captured_os_error==EINVAL,"actual NSPR mmap error conversion");
    CHECK(!_MD_MemMap(&test->mapping,(PRInt64)1<<32,4096) && captured_os_error==ENXIO,"NSPR preserves full native file offset");
    CHECK(!close(fd) && _MD_MemUnmap(map,8192)==PR_SUCCESS && _MD_MemUnmap(alias,4096)==PR_SUCCESS &&
        !unlink("/tmp/nspr-file-abi"),"cleanup after source close");
    serial_printf("NSPR_FILE_ABI_TEST: PASS open64=1 high_flags=1 stat=1 seconds=1 size64=1 overflow=1 nonblock=1 sync=1 fd_limits=1 mmap=1 msync=1\n");
    free(test);return 0;
}
