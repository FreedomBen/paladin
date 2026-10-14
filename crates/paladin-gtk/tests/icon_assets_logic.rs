// SPDX-License-Identifier: AGPL-3.0-or-later

//! Hicolor app-icon install-layout contract tests for `paladin-gtk`.
//!
//! Per `docs/IMPLEMENTATION_PLAN_04_GTK.md` §"Linux desktop integration" and
//! the Milestone 7 checklist entries:
//!
//! * `data/icons/hicolor/scalable/apps/org.tamx.Paladin.Gui.svg`
//! * 16 / 24 / 32 / 48 / 64 / 128 / 256 / 512 PNG fallbacks under
//!   `data/icons/hicolor/<size>/apps/org.tamx.Paladin.Gui.png`
//! * `data/icons/hicolor/symbolic/apps/org.tamx.Paladin.Gui-symbolic.svg`
//!
//! The hicolor layout is what `gtk::IconTheme` and the freedesktop
//! `Icon=` desktop-entry key consume; the same files install verbatim
//! under `/usr/share/icons/hicolor/...` in both native (`.deb` /
//! `.rpm`) and Flatpak builds so the launcher glyph, the
//! `AdwAboutDialog` icon-name lookup, and the window-class grouping
//! all resolve identically.

use std::fs;
use std::path::{Path, PathBuf};

use paladin_gtk::APP_ID;

/// Hicolor PNG fallback sizes per §"Linux desktop integration".
///
/// 16 / 24 / 32 / 48 are the GNOME HIG fallback ladder (legacy menubar,
/// toolbar, dialog, launcher). 64 / 128 / 256 / 512 cover the sizes
/// GNOME Shell's app-drawer and search results actually request on
/// modern desktops — without them, Shell falls through to the
/// scalable SVG via `librsvg`, and a base64-PNG-in-SVG payload can
/// fail `GdkPixbuf`'s icon-theme path, leaving the launcher glyph
/// blank. Consumers that cannot render the SVG (older GTK panels,
/// certain embedded launchers) read the matching `<size>/apps/`
/// PNG directly.
const HICOLOR_PNG_SIZES: &[u32] = &[16, 24, 32, 48, 64, 128, 256, 512];

fn crate_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}

fn icons_root() -> PathBuf {
    crate_root().join("data").join("icons").join("hicolor")
}

fn scalable_svg_path() -> PathBuf {
    icons_root()
        .join("scalable")
        .join("apps")
        .join(format!("{APP_ID}.svg"))
}

fn symbolic_svg_path() -> PathBuf {
    icons_root()
        .join("symbolic")
        .join("apps")
        .join(format!("{APP_ID}-symbolic.svg"))
}

fn png_fallback_path(size: u32) -> PathBuf {
    icons_root()
        .join(format!("{size}x{size}"))
        .join("apps")
        .join(format!("{APP_ID}.png"))
}

fn read_svg(path: &PathBuf) -> String {
    fs::read_to_string(path)
        .unwrap_or_else(|err| panic!("failed to read {}: {err}", path.display()))
}

// --- Scalable SVG ------------------------------------------------------------

#[test]
fn scalable_svg_exists_at_expected_path() {
    let path = scalable_svg_path();
    assert!(
        path.is_file(),
        "expected the scalable hicolor SVG at {}",
        path.display(),
    );
}

#[test]
fn scalable_svg_basename_matches_app_id() {
    let basename = scalable_svg_path()
        .file_name()
        .and_then(|name| name.to_str())
        .map(str::to_owned)
        .expect("scalable SVG path has a basename");
    assert_eq!(basename, format!("{APP_ID}.svg"));
}

#[test]
fn scalable_svg_is_well_formed_svg_root() {
    let contents = read_svg(&scalable_svg_path());
    assert!(
        contents.trim_start().starts_with("<?xml ") || contents.trim_start().starts_with("<svg"),
        "scalable SVG must start with the XML declaration or the <svg> root",
    );
    assert!(
        contents.contains("<svg") && contents.contains("</svg>"),
        "scalable SVG must contain a well-formed <svg> root element",
    );
}

#[test]
fn scalable_svg_declares_explicit_viewbox() {
    let contents = read_svg(&scalable_svg_path());
    // freedesktop / GNOME HIG expects a viewBox-declared SVG so the
    // icon renderer can scale the artwork to any pixel size without
    // visible blur. Width/height are accepted but the viewBox is the
    // contract.
    assert!(
        contents.contains("viewBox"),
        "scalable SVG must declare an explicit viewBox so the renderer can rescale at any size",
    );
}

#[test]
fn scalable_svg_carries_spdx_header() {
    let contents = read_svg(&scalable_svg_path());
    assert!(
        contents.contains("SPDX-License-Identifier"),
        "scalable SVG must carry an SPDX-License-Identifier comment",
    );
}

// --- PNG fallbacks -----------------------------------------------------------

#[test]
fn png_fallbacks_exist_at_each_required_size() {
    for &size in HICOLOR_PNG_SIZES {
        let path = png_fallback_path(size);
        assert!(
            path.is_file(),
            "expected the {size}x{size} PNG fallback at {}",
            path.display(),
        );
    }
}

#[test]
fn png_fallbacks_use_png_magic_bytes() {
    // Hicolor-installed PNGs must be honest PNG files (the install
    // layout's contract). Read the first 8 bytes and assert against
    // the standard PNG signature: 89 50 4E 47 0D 0A 1A 0A.
    const PNG_SIGNATURE: &[u8] = &[0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A];
    for &size in HICOLOR_PNG_SIZES {
        let path = png_fallback_path(size);
        let bytes = fs::read(&path)
            .unwrap_or_else(|err| panic!("failed to read {}: {err}", path.display()));
        assert!(
            bytes.len() >= PNG_SIGNATURE.len(),
            "{} is too short to be a PNG ({} bytes)",
            path.display(),
            bytes.len(),
        );
        assert_eq!(
            &bytes[..PNG_SIGNATURE.len()],
            PNG_SIGNATURE,
            "{} must start with the PNG magic-byte signature",
            path.display(),
        );
    }
}

#[test]
fn png_fallbacks_have_matching_ihdr_dimensions() {
    // The PNG IHDR chunk's first two big-endian u32s carry width and
    // height. Pin each PNG against the size encoded in its install
    // directory so a future rerasterization can't silently land a
    // mis-sized fallback.
    const IHDR_OFFSET: usize = 16; // 8 magic + 4 chunk length + 4 chunk type = "IHDR"
    for &size in HICOLOR_PNG_SIZES {
        let path = png_fallback_path(size);
        let bytes = fs::read(&path)
            .unwrap_or_else(|err| panic!("failed to read {}: {err}", path.display()));
        assert!(
            bytes.len() >= IHDR_OFFSET + 8,
            "{} is too short to carry an IHDR chunk ({} bytes)",
            path.display(),
            bytes.len(),
        );
        let width = u32::from_be_bytes([
            bytes[IHDR_OFFSET],
            bytes[IHDR_OFFSET + 1],
            bytes[IHDR_OFFSET + 2],
            bytes[IHDR_OFFSET + 3],
        ]);
        let height = u32::from_be_bytes([
            bytes[IHDR_OFFSET + 4],
            bytes[IHDR_OFFSET + 5],
            bytes[IHDR_OFFSET + 6],
            bytes[IHDR_OFFSET + 7],
        ]);
        assert_eq!(
            width,
            size,
            "{} IHDR width must equal the hicolor directory size",
            path.display(),
        );
        assert_eq!(
            height,
            size,
            "{} IHDR height must equal the hicolor directory size",
            path.display(),
        );
    }
}

// --- Symbolic variant --------------------------------------------------------

#[test]
fn symbolic_svg_exists_at_expected_path() {
    let path = symbolic_svg_path();
    assert!(
        path.is_file(),
        "expected the symbolic hicolor SVG at {}",
        path.display(),
    );
}

#[test]
fn symbolic_svg_basename_matches_app_id_symbolic_convention() {
    // The freedesktop icon-theme convention is to suffix symbolic
    // variants with `-symbolic`. Pin the basename so a future asset
    // rename can't drop the suffix without a matching test churn.
    let basename = symbolic_svg_path()
        .file_name()
        .and_then(|name| name.to_str())
        .map(str::to_owned)
        .expect("symbolic SVG path has a basename");
    assert_eq!(basename, format!("{APP_ID}-symbolic.svg"));
}

#[test]
fn symbolic_svg_is_well_formed_svg_root() {
    let contents = read_svg(&symbolic_svg_path());
    assert!(
        contents.contains("<svg") && contents.contains("</svg>"),
        "symbolic SVG must contain a well-formed <svg> root element",
    );
}

#[test]
fn symbolic_svg_carries_spdx_header() {
    let contents = read_svg(&symbolic_svg_path());
    assert!(
        contents.contains("SPDX-License-Identifier"),
        "symbolic SVG must carry an SPDX-License-Identifier comment",
    );
}

// --- SVG content sniffability -------------------------------------------------

/// Byte window within which every shipped SVG must open its `<svg>`
/// root tag.
///
/// Two sniffers gate `GdkPixbuf`'s SVG loader before any renderer sees
/// the file, and both read only the head of the file:
///
/// * the librsvg pixbuf-loader signature anchors `<svg` /
///   `<!DOCTYPE svg` at the start of the buffer;
/// * the `g_content_type_guess()` fallback runs on data alone (no
///   filename glob), and shared-mime-info's `image/svg+xml` magic
///   matches `<svg` only within the first 256 bytes.
///
/// An SVG whose root tag sits past the window sniffs as plain
/// `application/xml`, `GdkPixbuf` refuses to load it, and GNOME Shell's
/// app grid — which requests 96 px, a size with no fixed-size hicolor
/// directory, so the icon-theme lookup always lands on the scalable
/// SVG — draws the fallback gear instead of the launcher glyph.
/// License / doc comments therefore live inside the root element,
/// never between the XML declaration and `<svg`.
const SVG_SNIFF_WINDOW_BYTES: usize = 256;

fn data_icons_root() -> PathBuf {
    crate_root().join("data").join("icons")
}

fn collect_svgs_under(dir: &Path, found: &mut Vec<PathBuf>) {
    let entries = fs::read_dir(dir)
        .unwrap_or_else(|err| panic!("failed to read dir {}: {err}", dir.display()));
    for entry in entries {
        let path = entry
            .unwrap_or_else(|err| panic!("failed to read dir entry under {}: {err}", dir.display()))
            .path();
        if path.is_dir() {
            collect_svgs_under(&path, found);
        } else if path.extension().is_some_and(|ext| ext == "svg") {
            found.push(path);
        }
    }
}

#[test]
fn shipped_svgs_keep_root_tag_within_sniff_window() {
    let mut svgs = Vec::new();
    collect_svgs_under(&data_icons_root(), &mut svgs);
    svgs.sort();
    // Guard the walker itself: the hicolor scalable + symbolic pair
    // and the gresource-bundled action placeholder must all be found.
    assert!(
        svgs.len() >= 3,
        "expected at least 3 shipped SVGs under {}, found {}",
        data_icons_root().display(),
        svgs.len(),
    );
    for path in svgs {
        let contents = read_svg(&path);
        let offset = contents
            .find("<svg")
            .unwrap_or_else(|| panic!("{} does not contain an <svg root tag", path.display()));
        assert!(
            offset < SVG_SNIFF_WINDOW_BYTES,
            "{}: <svg root tag first appears at byte {offset}, past the \
             {SVG_SNIFF_WINDOW_BYTES}-byte sniffing window shared by GdkPixbuf's loader \
             signature and shared-mime-info's image/svg+xml magic — move comments inside \
             the root element",
            path.display(),
        );
    }
}

#[test]
fn symbolic_svg_uses_currentcolor_for_recoloring() {
    // GNOME-style symbolic icons recolor on the fly. The contract is
    // that the body uses `currentColor` (or `color: currentColor`) so
    // the Adwaita palette can tint the symbolic against the active
    // foreground. A symbolic that hardcodes `fill="#xxxxxx"` shows up
    // tinted-wrong on dark themes.
    let contents = read_svg(&symbolic_svg_path());
    assert!(
        contents.contains("currentColor") || contents.contains("currentcolor"),
        "symbolic SVG must use currentColor so the Adwaita palette can recolor it",
    );
}
