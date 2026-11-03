#include "AlixFontFiles.h"
#include "hb.h"
#include "hb-ot.h"
#include <ft2build.h>
#include FT_FREETYPE_H
#include "fcntl.h"
#include "errno.h"
#include "stdlib.h"
#include "pthread.h"
#include "serial.h"
#include "sys/stat.h"
#include "unistd.h"
#include "usyscall.h"
#include <algorithm>
#include <cstdio>
#include <cstring>
#include <memory>
#include <string>
#include <vector>

#define CHECK(c, label) do { if (!(c)) { serial_printf("ALIX_FONT_FILES_TEST: FAIL %s line=%u\n", label, __LINE__); return 1; } } while (0)
struct FontResult {
  std::string family;
  uint64_t pixels;
  unsigned glyphs;
  bool operator==(const FontResult& other) const {
    return family == other.family && pixels == other.pixels && glyphs == other.glyphs;
  }
};
struct FontJob {
  pthread_t thread{};
  unsigned cpu = 0, failed = 0, invalid = 0;
  size_t candidates = 0;
  FT_Library library = nullptr;
  std::vector<FontResult> results;
};
struct FontFixture { FontJob jobs[8]; std::string deep; };
extern "C" void* moz_xmemalign(size_t alignment, size_t size);

static void InspectFont(const char* path, void* context) {
  auto* job = static_cast<FontJob*>(context);
  FT_Face face = nullptr;
  if (FT_New_Face(job->library, path, 0, &face)) { ++job->invalid; return; }
  if (FT_Set_Pixel_Sizes(face, 0, 24) || FT_Load_Char(face, 'A', FT_LOAD_RENDER) ||
      !face->glyph->bitmap.width || !face->glyph->bitmap.rows) {
    job->failed = 2; FT_Done_Face(face); return;
  }
  uint64_t hash = 1469598103934665603ULL;
  for (unsigned y = 0; y < face->glyph->bitmap.rows; ++y)
    for (unsigned x = 0; x < face->glyph->bitmap.width; ++x)
      hash = (hash ^ face->glyph->bitmap.buffer[y * face->glyph->bitmap.pitch + x]) * 1099511628211ULL;
  hb_blob_t* blob = hb_blob_create_from_file_or_fail(path);
  if (!blob) { job->failed = 3; FT_Done_Face(face); return; }
  hb_face_t* hbFace = hb_face_create(blob, 0);
  hb_font_t* font = hb_font_create(hbFace);
  hb_ot_font_set_funcs(font);
  hb_buffer_t* buffer = hb_buffer_create();
  hb_buffer_add_utf8(buffer, "office", -1, 0, -1);
  hb_buffer_set_direction(buffer, HB_DIRECTION_LTR);
  hb_buffer_set_script(buffer, HB_SCRIPT_LATIN);
  hb_buffer_set_language(buffer, hb_language_from_string("en", -1));
  hb_feature_t liga{HB_TAG('l', 'i', 'g', 'a'), 1, 0, HB_FEATURE_GLOBAL_END};
  hb_shape(font, buffer, &liga, 1);
  unsigned count = 0;
  hb_glyph_info_t* info = hb_buffer_get_glyph_infos(buffer, &count);
  if (!count || count > 6) job->failed = 4;
  for (unsigned index = 0; index < count; ++index) if (!info[index].codepoint) job->failed = 5;
  job->results.push_back({face->family_name ? face->family_name : "", hash, count});
  hb_buffer_destroy(buffer); hb_font_destroy(font); hb_face_destroy(hbFace); hb_blob_destroy(blob);
  FT_Done_Face(face);
}
static void* ScanFonts(void* context) {
  auto* job = static_cast<FontJob*>(context);
  if (sys_thread_set_affinity(job->cpu) || sys_thread_cpu() != job->cpu || FT_Init_FreeType(&job->library)) {
    job->failed = 1; return nullptr;
  }
  job->candidates = mozilla::gfx::EnumerateAlixFontFiles("/tmp/font-registry", InspectFont, job);
  std::sort(job->results.begin(), job->results.end(), [](const auto& a, const auto& b) { return a.family < b.family; });
  FT_Done_FreeType(job->library);
  return nullptr;
}
extern "C" int alix_font_files_test_main() {
  for (size_t alignment : {size_t(1), size_t(8), size_t(16), size_t(64), size_t(4096)}) {
    errno = EDOM;
    void* memory = memalign(alignment, 37);
    CHECK(memory && !(reinterpret_cast<uintptr_t>(memory) % alignment) && errno == EDOM, "native arbitrary-size aligned allocation");
    memset(memory, 0x5a, 37); free(memory);
  }
  CHECK(!memalign(3, 37) && errno == EINVAL && !memalign(4096, SIZE_MAX) && errno == ENOMEM, "aligned allocation error contract");
  void* aligned = moz_xmemalign(4096, 37);
  CHECK(aligned && !(reinterpret_cast<uintptr_t>(aligned) % 4096), "actual Mozilla aligned allocator");
  free(aligned);
  aligned = moz_xmemalign(64, 0);
  CHECK(aligned && !(reinterpret_cast<uintptr_t>(aligned) % 64), "Mozilla zero-size aligned allocation");
  free(aligned);
  auto fixture = std::make_unique<FontFixture>();
  CHECK(!mkdir("/tmp/font-registry", 0700) && !mkdir("/tmp/font-registry/sub.ttf", 0700), "font directories");
  fixture->deep = "/tmp/font-registry/sub.ttf";
  for (unsigned depth = 0; depth < 32; ++depth) { fixture->deep += "/d"; CHECK(!mkdir(fixture->deep.c_str(), 0700), "deep font tree"); }
  CHECK(!rename("/tmp/font-sans.ttf", "/tmp/font-registry/sans.TTF") &&
        !rename("/tmp/font-serif.ttf", "/tmp/font-registry/sub.ttf/serif.otf") &&
        !rename("/tmp/font-mono.ttf", (fixture->deep + "/non-utf8-\xff.ttf").c_str()), "font names and nested roots");
  int fd = open("/tmp/font-registry/bad.ttf", O_WRONLY | O_CREAT | O_EXCL, 0600);
  CHECK(fd >= 0 && write(fd, "invalid font", 12) == 12 && !close(fd), "malformed font fixture");
  fd = open("/tmp/font-registry/notes.txt", O_WRONLY | O_CREAT | O_EXCL, 0600);
  CHECK(fd >= 0 && !close(fd), "ignored file");
  for (unsigned cpu = 0; cpu < 8; ++cpu) {
    auto& job = fixture->jobs[cpu]; job.cpu = cpu;
    CHECK(!pthread_create(&job.thread, nullptr, ScanFonts, &job), "scanner thread");
  }
  for (unsigned cpu = 0; cpu < 8; ++cpu) {
    auto& job = fixture->jobs[cpu];
    CHECK(!pthread_join(job.thread, nullptr) && !job.failed && job.candidates == 4 && job.invalid == 1 &&
          job.results.size() == 3, "native candidate scan and malformed font rejection");
    CHECK(job.results[0].family == "Charis SIL Compact" && job.results[1].family == "DejaVu Sans" &&
          job.results[2].family == "Fira Code" && job.results[1].glyphs < 6, "font names and real OpenType ligature shaping");
    if (cpu) CHECK(job.results == fixture->jobs[0].results, "stable native shaping and raster pixels across CPUs");
  }
  serial_printf("ALIX_FONT_FILES_TEST: PASS cpus=8 depth=32 candidates=32 valid_faces=24 invalid=8 freetype=1 harfbuzz_ligatures=1 byte_paths=1\n");
  return 0;
}
