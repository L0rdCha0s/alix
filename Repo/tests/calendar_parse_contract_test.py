#!/usr/bin/env python3
"""Run the production parser/calendar and timezone state under sanitizers."""
from pathlib import Path
import os
import shlex
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[1]
# Reuse the existing native timezone platform model, including tracked ownership.
source = (ROOT / "tests/timezone_contract_test.py").read_text()
prefix = source[:source.index("with tempfile.TemporaryDirectory(")]
scope = {"__file__": str(ROOT / "tests/timezone_contract_test.py")}
exec(prefix, scope)
platform, harness = scope["PLATFORM"], scope["HARNESS"]
harness = harness[:harness.index("int main(")]
harness += r'''
char *alix_strptime(const char *, const char *, struct tm *);
#define strptime alix_strptime
#include "calendar_parse_cases.h"
static void *parse_worker(void *arg) { return (void *)(uintptr_t)calendar_parse_cases((unsigned)(uintptr_t)arg); }
int main(void)
{
    setenv("TZ", "UTC0", 1); alix_tzset();
    pthread_t workers[8];
    for (unsigned i=0;i<8;++i) assert(!pthread_create(&workers[i],NULL,parse_worker,(void *)(uintptr_t)i));
    for (unsigned i=0;i<8;++i) {
        void *result; assert(!pthread_join(workers[i],&result));
        if(result) fprintf(stderr,"calendar parse failed at line %lu\n",(unsigned long)result);
        assert(!result);
    }
    setenv("TZ","AEST-10AEDT-11,M10.1.0,M4.1.0/3",1); alix_tzset();
    struct tm date={.tm_year=124,.tm_mon=0,.tm_mday=1};
    char *end=alix_strptime("AEDT!","%Z",&date);
    assert(end && !strcmp(end,"!") && date.tm_gmtoff==39600 && date.tm_isdst==1);
    end=alix_strptime("AEST","%Z",&date);
    assert(end && !*end && date.tm_gmtoff==36000 && date.tm_isdst==0);
    puts("Calendar parsing production contracts: PASS threads=8 roundtrips=49152 timezone=1");
}
'''
with tempfile.TemporaryDirectory(prefix="alix-calendar-parse-") as directory:
    folder = Path(directory)
    (folder / "platform.h").write_text(platform)
    (folder / "test.c").write_text(harness)
    symbols = ("gmtime", "gmtime_r", "timegm", "asctime", "asctime_r", "localtime", "localtime_r",
               "mktime", "ctime", "ctime_r", "strftime", "strptime", "tzset", "timezone", "daylight", "tzname")
    sanitizer = os.environ.get("SANITIZER", "address,undefined")
    flags = ["-std=c11", "-D_DARWIN_C_SOURCE", "-D_GNU_SOURCE", "-D_DEFAULT_SOURCE", "-Wall", "-Wextra",
             "-Wno-unused-function", "-g", "-pthread", "-I" + str(ROOT / "tests"), "-fsanitize=" + sanitizer]
    objects = []
    cc = shlex.split(os.environ.get("HOST_CC", "cc"))
    for module in ("calendar", "timezone", "calendar_format", "calendar_parse"):
        text = (ROOT / "user/lib" / (module + ".c")).read_text().replace('#include "timezone_platform.h"', '#include "platform.h"')
        path = folder / (module + ".c"); path.write_text(text)
        output = folder / (module + ".o"); objects.append(str(output))
        subprocess.run(cc + flags + [f"-D{x}=alix_{x}" for x in symbols + ("malloc", "calloc", "free")] +
                       ["-c", str(path), "-o", str(output)], check=True)
    binary = folder / "test"
    subprocess.run(cc + flags + [str(folder / "test.c")] + objects + ["-o", str(binary)], check=True)
    subprocess.run([str(binary)], check=True)
