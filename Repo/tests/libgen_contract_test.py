#!/usr/bin/env python3
"""Path-component contracts, including root, trailing separators and UTF-8."""
from pathlib import Path
import sys
sys.dont_write_bytecode = True
from audio_stream_contract_test import compile_and_run

ROOT = Path(__file__).resolve().parents[1]


def main():
    code = r'''
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
'''
    code += "\n".join(line for line in (ROOT / "user/lib/libgen.c").read_text().splitlines()
                       if not line.startswith("#include "))
    code += r'''
int main(void) {
    const char *cases[][3]={
        {NULL,".","."},{"",".","."},{"a",".","a"},{"a/",".","a"},
        {"a/b","a","b"},{"a///b///","a","b"},{"/","/","/"},
        {"//","//","/"},{"///","/","/"},{"/a","/","a"},{"//a","//","a"},
        {"//a/b/","//a","b"},{"///a//b","///a","b"},
        {".",".","."},{"..",".",".."},{"a/../b","a/..","b"},
        {"/tmp/\xc3\xa9/file.txt/","/tmp/\xc3\xa9","file.txt"},
    };
    for(unsigned i=0;i<sizeof(cases)/sizeof(cases[0]);++i) {
        size_t n=cases[i][0]?strlen(cases[i][0])+1:1;
        char *path=malloc(n);if(!path)return 1;
        if(cases[i][0])memcpy(path,cases[i][0],n);
        if(strcmp(dirname(cases[i][0]?path:NULL),cases[i][1])) {fprintf(stderr,"dirname case %u\n",i);return 1;}
        if(cases[i][0])memcpy(path,cases[i][0],n);
        if(strcmp(basename(cases[i][0]?path:NULL),cases[i][2])) {fprintf(stderr,"basename case %u\n",i);return 1;}
        free(path);
    }
    return 0;
}
'''
    compile_and_run("libgen-contract", code)
    print("Path components PASS: 34 null/empty/root/trailing/UTF-8 cases")
    return 0


if __name__ == "__main__":
    sys.exit(main())
