#include "web/css/css.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>

// Mock video_make_color since we are linking against libweb which might need it
// or we can just link against the object files.
// For now, let's assume we can link against the necessary files.

int main() {
    const char *css_text = 
        ".s-post-summary {\n"
        "  --_ps-stats-fd: column;\n"
        "  --_ps-stats-w: 108px;\n"
        "  display: flex;\n"
        "}\n"
        ".s-post-summary .s-post-summary--stats {\n"
        "  flex-direction: var(--_ps-stats-fd);\n"
        "  width: var(--_ps-stats-w);\n"
        "  display: flex;\n"
        "}\n";

    printf("Parsing CSS...\n");
    css_stylesheet_t *sheet = css_parse(css_text);
    if (!sheet) {
        fprintf(stderr, "Failed to parse CSS\n");
        return 1;
    }

    // Inspect the parsed rules to see if custom properties are stored (they won't be yet)
    // But we can check if the standard properties are set correctly on the child.
    // Since we don't have a full DOM and style application engine exposed easily,
    // we might need to rely on inspecting the rules or mocking the application.
    
    // However, the issue is about *application* and *inheritance*.
    // So we need to simulate style application.
    
    // Let's look at css_rule_t. It has 'style'.
    // If the parser resolved the vars, they would be in 'style'.
    // But they are not resolved because they are custom properties.
    
    // The child rule: .s-post-summary .s-post-summary--stats
    // Should have flex-direction and width set.
    
    css_rule_t *rule = sheet->rules;
    while (rule) {
        printf("Rule: %s\n", rule->selector);
        if (strstr(rule->selector, "stats")) {
            printf("  Checking stats rule...\n");
            if (rule->style.has_flex_direction) {
                printf("  Has flex-direction: %d\n", rule->style.flex_direction);
            } else {
                printf("  MISSING flex-direction\n");
            }
            
            if (rule->style.has_width) {
                printf("  Has width: %d unit=%d\n", rule->style.width.value_milli, rule->style.width.unit);
            } else {
                printf("  MISSING width\n");
            }
        }
        rule = rule->next;
    }

    css_stylesheet_destroy(sheet);
    return 0;
}
