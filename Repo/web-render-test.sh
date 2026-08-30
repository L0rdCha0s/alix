if [ "$#" -eq 0 ]; then
    set -- --dump-dom
fi

ALIX_HOST_FETCH=0 HTML_VIEW_HOST_TRACE=1 ALIX_HTML_TRACE=1 ALIX_HTML_TRACE_RULE_EVERY=100000 ALIX_HTML_TRACE_NODE_EVERY=100000  time ./build/host-tests/html_view_host_test "$@"
