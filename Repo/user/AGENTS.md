# User Library Notes

## HTML/CSS Rendering
1. We are writing a CSS parser, HTML parser, and HTML/CSS web renderer.  
2. The HTML parser is in user/lib/web/html and the CSS parser is in user/lib/web/css.  The HTML renderer ATK component is in user/lib/atk/atk_html_view.c and user/lib/atk/html_view/*
3. Every time we improve the HTML or CSS parser, write a test case to cover bugs we find in parsing or layout.  These tests are in tests/web_host_test.c