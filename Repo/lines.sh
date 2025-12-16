C=$(find . -type f \( -name '*.c' -o -name '*.h' \) -exec cat {} + | wc -l | awk '{print $1}'); \
ASM=$(find . -type f \( -name '*.s' -o -name '*.S' -o -name '*.asm' -o -name '*.inc' \) -exec cat {} + | wc -l | awk '{print $1}'); \
printf 'C: %s  ASM: %s  Total: %s\n' "$C" "$ASM" "$((C+ASM))"

