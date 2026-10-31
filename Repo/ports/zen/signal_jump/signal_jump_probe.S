.intel_syntax noprefix
.section .text
.global signal_jump_ud2
signal_jump_ud2:
    ud2
    ret
.section .note.GNU-stack,"",@progbits
