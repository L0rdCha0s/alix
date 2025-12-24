#ifndef SHELL_PROMPT_H
#define SHELL_PROMPT_H

struct process;

char *shell_prompt_build(struct process *owner);

#endif
