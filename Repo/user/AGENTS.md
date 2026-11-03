# User Library Notes

## HTML/CSS Rendering
1. We are writing a CSS parser, HTML parser, and HTML/CSS web renderer.  
2. The HTML parser is in user/lib/web/html and the CSS parser is in user/lib/web/css.  The HTML renderer ATK component is in user/lib/atk/atk_html_view.c and user/lib/atk/html_view/*
3. Do not add new tests or test harnesses unless the user explicitly asks. Prioritize building and running the requested software; existing HTML/CSS checks are in tests/web_host_test.c.

## General
1. If we are missing a function in our libc, implement it - never create custom functions in a user app to replace functionality missing in libc - just extend libc where it makes sense.
