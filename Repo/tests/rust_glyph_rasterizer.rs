use std::{ffi::OsString, path::PathBuf, sync::Arc, thread};
use std::os::alix::ffi::OsStringExt;
use webrender_api::{ColorU, FontInstanceFlags, FontInstanceKey, FontInstancePlatformOptions,
    FontKey, FontLCDFilter, FontRenderMode, FontVariation, IdNamespace, NativeFontHandle,
    units::DevicePoint};
use wr_glyph_rasterizer::{BaseFontInstance, FontInstance, GlyphKey, SubpixelDirection,
    platform::font::FontContext};
// Keep Gecko's actual prefixed zlib implementation in the native link.
use libz_rs_sys as _;

static FONT: &[u8] = include_bytes!("../ports/zen/upstream/firefox-159.0/gfx/wr/wrench/reftests/text/FreeSans.ttf");
static VARIABLE: &[u8] = include_bytes!("../ports/zen/upstream/firefox-159.0/layout/reftests/fonts/VotoSerifGX.latin1.ttf");
type Result<T> = std::result::Result<T, Box<dyn std::error::Error + Send + Sync>>;
type Digest = (i32, i32, u64);
unsafe extern "C" {
    fn sys_thread_set_affinity(cpu: u32) -> i32;
    fn sys_thread_cpu() -> u32;
}
fn require(value: bool, message: &str) -> Result<()> {
    if value { Ok(()) } else { Err(message.into()) }
}
fn render(context: &mut FontContext, key: FontKey, case: usize) -> Result<Digest> {
    render_weight(context, key, case, None)
}
fn render_weight(context: &mut FontContext, key: FontKey, case: usize, weight_override: Option<f32>) -> Result<Digest> {
    let mode = [FontRenderMode::Mono, FontRenderMode::Alpha, FontRenderMode::Subpixel][case % 3];
    let weight = weight_override.unwrap_or_else(||
        if case >= 6 { if case == 6 { 28.0 } else { 194.0 } } else { 0.0 });
    let variations = if weight != 0.0 {
        vec![FontVariation { tag: u32::from_be_bytes(*b"wght"), value: weight }]
    } else { Vec::new() };
    let mut options = FontInstancePlatformOptions::default();
    options.lcd_filter = if case % 2 == 0 { FontLCDFilter::Default } else { FontLCDFilter::Light };
    let base = Arc::new(BaseFontInstance::new(FontInstanceKey::new(IdNamespace(71), case as u32),
        key, if case < 3 { 32.0 } else { 48.0 }, None, Some(options), variations));
    let mut font = FontInstance::new(base, ColorU::new(0, 0, 0, 255), mode,
        FontInstanceFlags::FONT_SMOOTHING);
    FontContext::prepare_font(&mut font);
    let ch = if case % 2 == 0 { 'A' } else { 'g' };
    let index = context.get_glyph_index(key, ch).ok_or("missing glyph")?;
    let glyph_key = GlyphKey::new(index, DevicePoint::zero(), SubpixelDirection::None);
    let dimensions = context.get_glyph_dimensions(&font, &glyph_key).ok_or("missing glyph metrics")?;
    require(dimensions.width > 0 && dimensions.height > 0 && dimensions.advance > 0.0,
            "native glyph metrics")?;
    FontContext::begin_rasterize(&font);
    let result = context.rasterize_glyph(&font, &glyph_key);
    FontContext::end_rasterize(&font);
    let glyph = result.map_err(|_| "native FreeType rasterization failed")?;
    require(glyph.width > 0 && glyph.height > 0 &&
            glyph.bytes.len() == glyph.width as usize * glyph.height as usize * 4,
            "WebRender BGRA glyph buffer")?;
    require(glyph.bytes.iter().any(|&b| b != 0) && glyph.bytes.iter().any(|&b| b == 0),
            "nonempty glyph coverage and background")?;
    let hash = glyph.bytes.iter().fold(14695981039346656037u64,
        |hash, &byte| (hash ^ byte as u64).wrapping_mul(1099511628211));
    Ok((glyph.width, glyph.height, hash))
}
fn run() -> Result<()> {
    let raw = Arc::new(FONT.to_vec());
    let variable = Arc::new(VARIABLE.to_vec());
    let key = FontKey::new(IdNamespace(71), 1);
    let var_key = FontKey::new(IdNamespace(71), 2);
    let file_key = FontKey::new(IdNamespace(71), 3);
    let mut context = FontContext::new();
    context.add_raw_font(&key, raw.clone(), 0);
    context.add_raw_font(&var_key, variable.clone(), 0);
    require(context.get_glyph_index(key, '\u{10ffff}').is_none(), "missing character")?;
    let expected: Vec<Digest> = (0..8).map(|case|
        render(&mut context, if case < 6 { key } else { var_key }, case)).collect::<Result<_>>()?;
    // The same variable-font character at a fixed size must change with weight.
    let variable_light = render_weight(&mut context, var_key, 6, Some(28.0))?;
    let variable_heavy = render_weight(&mut context, var_key, 6, Some(194.0))?;
    require(variable_light != variable_heavy, "actual variable-axis glyph change")?;
    let path = PathBuf::from(OsString::from_vec(b"/tmp/wr-font-\xff.ttf".to_vec()));
    std::fs::write(&path, FONT)?;
    context.add_native_font(&file_key, NativeFontHandle { path: path.clone(), index: 0 });
    for case in 0..6 {
        require(render(&mut context, file_key, case)? == expected[case], "raw and file font pixels")?;
    }
    context.delete_font(&file_key);
    std::fs::remove_file(path)?;
    let mut workers = Vec::new();
    for cpu in 0..8u32 {
        let raw = raw.clone(); let variable = variable.clone(); let expected = expected.clone();
        workers.push(thread::Builder::new().name(format!("wr-font-{cpu}")).spawn(move || -> Result<()> {
            require(unsafe { sys_thread_set_affinity(cpu) } == 0 &&
                    unsafe { sys_thread_cpu() } == cpu, "native font worker CPU")?;
            let mut context = FontContext::new();
            context.add_raw_font(&key, raw, 0);
            context.add_raw_font(&var_key, variable, 0);
            for iteration in 0..64 {
                let case = (iteration + cpu as usize) % expected.len();
                require(render(&mut context, if case < 6 { key } else { var_key }, case)? == expected[case],
                        "concurrent glyph pixels/metrics changed")?;
            }
            context.delete_font(&key); context.delete_font(&var_key);
            Ok(())
        })?);
    }
    for worker in workers { worker.join().map_err(|_| "font worker panicked")??; }
    context.delete_font(&key); context.delete_font(&var_key);
    Ok(())
}
fn main() {
    match run() {
        Ok(()) => println!("RUST_GLYPH_RASTERIZER_TEST: PASS cpus=8 glyphs=512 freetype=1 mono=1 alpha=1 subpixel=1 variable=1 file_bytes=1 shared_faces=1"),
        Err(error) => { eprintln!("RUST_GLYPH_RASTERIZER_TEST: FAIL {error}"); std::process::exit(1); }
    }
}
