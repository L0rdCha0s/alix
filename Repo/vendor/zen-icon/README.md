# Zen desktop icon

Unmodified `configs/branding/release/logo48.png` from Zen Browser 1.24b,
revision `f75390aa2b797ddc3524ff9ed52ceb32a839f9fa` of
https://github.com/zen-browser/desktop.

SHA-256: `83779474c1efdfcdf50c1e024d647c5df72d676fa7b52908c28c5cf2dc17d3e2`.
The upstream MPL-2.0 license is included in `LICENSE`.

The kernel build embeds these PNG bytes so the desktop launcher retains its
branding independently of the installed browser's resource files. The existing
PNG decoder supplies the button's owned 48 by 48 pixel surface.
