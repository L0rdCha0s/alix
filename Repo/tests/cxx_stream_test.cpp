#include <atomic>
#include <ctime>
#include <iomanip>
#include <iostream>
#include <limits>
#include <locale>
#include <sstream>
#include <string>
#include <system_error>
#include <thread>
#include <vector>

#include "locale.h"
#include "serial.h"
#include "stdlib.h"

struct stream_state {
    std::atomic<unsigned> failed{0};
    std::atomic<unsigned> finished{0};
};

static void stream_worker(stream_state* state, unsigned index)
{
    locale_t local = newlocale(LC_ALL_MASK, "POSIX", nullptr);
    if (!local) { ++state->failed; return; }
    locale_t previous = uselocale(local);
    if (!previous) { ++state->failed; freelocale(local); return; }
    for (unsigned round = 0; round < 32; ++round)
    {
        std::ostringstream output;
        output.imbue(std::locale::classic());
        output << "worker " << index << ' ' << round << ' ' << std::fixed << std::setprecision(2) << 1.25;
        std::istringstream input(output.str());
        std::string word;
        unsigned parsed_index = 99, parsed_round = 99;
        double value = 0;
        input >> word >> parsed_index >> parsed_round >> value;
        if (input.fail() || word != "worker" || parsed_index != index || parsed_round != round || value != 1.25 ||
            uselocale(nullptr) != local)
            ++state->failed;
    }
    if (uselocale(previous) != local) ++state->failed;
    freelocale(local);
    ++state->finished;
}

#define CHECK(condition, label) do { if (!(condition)) { \
    serial_printf("CXX_STREAM_TEST: FAIL %s\n", label); return 1; } } while (0)

int main()
{
    const std::locale classic = std::locale::classic();
    CHECK(!std::generic_category().message(std::numeric_limits<int>::max()).empty() &&
          !std::iostream_category().message(std::numeric_limits<int>::min()).empty(),
          "out-of-range native error strings");
    const auto& characters = std::use_facet<std::ctype<char>>(classic);
    const auto& collation = std::use_facet<std::collate<char>>(classic);
    CHECK(characters.is(std::ctype_base::alpha, 'A') && characters.is(std::ctype_base::space, '\t') &&
          characters.tolower('Z') == 'z' && !characters.is(std::ctype_base::alpha, static_cast<char>(0xff)),
          "C character facets");
    const std::string first = "abc", second = "abd";
    CHECK(collation.compare(first.data(), first.data() + first.size(), second.data(), second.data() + second.size()) < 0 &&
          collation.transform(first.data(), first.data() + first.size()) == first, "C collation facet");
    std::tm date{};
    date.tm_year = 124; date.tm_mon = 0; date.tm_mday = 2;
    date.tm_hour = 3; date.tm_min = 4; date.tm_sec = 5;
    std::ostringstream date_output;
    date_output << std::put_time(&date, "%Y-%m-%d %H:%M:%S");
    CHECK(date_output.str() == "2024-01-02 03:04:05", "C time facet");
    std::ostringstream output;
    output << "native " << 42 << ' ' << std::hex << 255 << ' ' << std::fixed << std::setprecision(2) << 1.25;
    CHECK(output.str() == "native 42 ff 1.25", "integer and fixed stream output");
    std::istringstream input("-42 1.25 ff");
    int signed_value = 0, hex_value = 0;
    double floating = 0;
    input >> signed_value >> floating >> std::hex >> hex_value;
    CHECK(!input.fail() && signed_value == -42 && floating == 1.25 && hex_value == 255, "numeric stream input");
    std::ostringstream scientific, general, zero, hexadecimal;
    scientific << std::scientific << std::setprecision(4) << 12.5;
    general << std::setprecision(6) << 12.5;
    zero << std::fixed << std::setprecision(1) << -0.0;
    hexadecimal << std::hexfloat << 12.5;
    CHECK(scientific.str() == "1.2500e+01" && general.str() == "12.5" && zero.str() == "-0.0",
          "scientific general and signed-zero formatting");
    std::string hex_text = hexadecimal.str();
    char* end = nullptr;
    CHECK(hex_text.find("0x") == 0 && hex_text.find('p') != std::string::npos &&
          strtod(hex_text.c_str(), &end) == 12.5 && *end == '\0', "hexadecimal floating output");
    const long double precise = 1.0L + 0x1p-60L;
    std::ostringstream extended;
    extended << std::setprecision(std::numeric_limits<long double>::max_digits10) << precise;
    long double decoded = 0;
    std::istringstream extended_input(extended.str());
    extended_input >> decoded;
    CHECK(!extended_input.fail() && decoded == precise && decoded != 1.0L, "80-bit numeric roundtrip");
    std::ostringstream large;
    large << std::scientific << std::setprecision(20) << 0x1p12000L;
    const std::string large_text = large.str();
    CHECK(strtold(large_text.c_str(), &end) == 0x1p12000L && *end == '\0', "extended exponent formatting");
    auto* state = new stream_state;
    std::vector<std::thread> workers;
    for (unsigned index = 0; index < 8; ++index) workers.emplace_back(stream_worker, state, index);
    for (auto& worker : workers) worker.join();
    CHECK(state->failed == 0 && state->finished == 8, "concurrent streams and locale restoration");
    delete state;
    std::cout << "CXX_STREAM_TEST: cout PASS" << std::endl;
    CHECK(!std::cout.fail(), "native standard output");
    serial_printf("CXX_STREAM_TEST: PASS workers=8 roundtrips=256 extended80=1\n");
    return 0;
}
