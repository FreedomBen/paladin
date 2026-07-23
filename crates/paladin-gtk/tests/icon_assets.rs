//! Hicolor app-icon install-layout contract tests.
//!
//! Per `docs/IMPLEMENTATION_PLAN_04_GTK.md` §9 "App icon (shared paladin
//! logo)": the icon assets live under `data/icons/` at the workspace root
//! and install verbatim into the freedesktop hicolor theme. The hicolor
//! layout is what `gtk::IconTheme` and the desktop entry's `Icon=` key
//! consume, so these tests pin the file set, the PNG honesty (magic bytes
//! and IHDR dimensions matching the size directory), the SVG contracts
//! (`viewBox`, `currentColor`), and that the Makefile and nfpm packaging
//! reference the same set.

use std::fs;
use std::path::PathBuf;

use paladin_gtk::APP_ID;

/// Hicolor PNG fallback sizes. 16/24/32/48 are the GNOME HIG fallback
/// ladder; 64/128/256/512 are the sizes GNOME Shell's app drawer and
/// search actually request on modern desktops.
const HICOLOR_PNG_SIZES: &[u32] = &[16, 24, 32, 48, 64, 128, 256, 512];

/// Workspace root (the icon assets live in the root `data/` directory,
/// not inside the crate).
fn workspace_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join("..")
}

fn icons_root() -> PathBuf {
    workspace_root().join("data").join("icons").join("hicolor")
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

fn read_text(path: &PathBuf) -> String {
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
fn scalable_svg_is_well_formed_svg_root() {
    let contents = read_text(&scalable_svg_path());
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
    // freedesktop / GNOME HIG expects a viewBox-declared SVG so the icon
    // renderer can scale the artwork to any pixel size without blur.
    let contents = read_text(&scalable_svg_path());
    assert!(
        contents.contains("viewBox"),
        "scalable SVG must declare an explicit viewBox",
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
    // height; pin them to the size encoded in the install directory so a
    // rerasterization can't silently land a mis-sized fallback.
    const IHDR_OFFSET: usize = 16; // 8 magic + 4 chunk length + 4 chunk type
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
        let width = u32::from_be_bytes(bytes[IHDR_OFFSET..IHDR_OFFSET + 4].try_into().unwrap());
        let height =
            u32::from_be_bytes(bytes[IHDR_OFFSET + 4..IHDR_OFFSET + 8].try_into().unwrap());
        assert_eq!(
            (width, height),
            (size, size),
            "{} IHDR dimensions must equal the hicolor directory size",
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
fn symbolic_svg_is_well_formed_svg_root() {
    let contents = read_text(&symbolic_svg_path());
    assert!(
        contents.contains("<svg") && contents.contains("</svg>"),
        "symbolic SVG must contain a well-formed <svg> root element",
    );
}

#[test]
fn symbolic_svg_uses_currentcolor_for_recoloring() {
    // GNOME-style symbolic icons recolor on the fly: the body must use
    // currentColor so the Adwaita palette can tint it against the active
    // foreground. A hardcoded fill renders tinted-wrong on dark themes.
    let contents = read_text(&symbolic_svg_path());
    assert!(
        contents.contains("currentColor") || contents.contains("currentcolor"),
        "symbolic SVG must use currentColor so the Adwaita palette can recolor it",
    );
}

// --- Desktop entry / install consistency -------------------------------------

#[test]
fn desktop_entry_icon_key_matches_app_id() {
    let path = workspace_root()
        .join("data")
        .join(format!("{APP_ID}.desktop"));
    let contents = read_text(&path);
    assert!(
        contents
            .lines()
            .any(|line| line == format!("Icon={APP_ID}")),
        "{} must set Icon={APP_ID} so the hicolor lookup resolves by app id",
        path.display(),
    );
}

#[test]
fn makefile_installs_the_full_hicolor_set() {
    let path = workspace_root().join("Makefile");
    let contents = read_text(&path);
    assert!(
        contents.contains("GTK_ICON_SIZES"),
        "Makefile must define GTK_ICON_SIZES for the sized-PNG install loop",
    );
    for &size in HICOLOR_PNG_SIZES {
        assert!(
            contents.contains(&format!(" {size}")) || contents.contains(&format!("{size} ")),
            "Makefile GTK_ICON_SIZES must include {size}",
        );
    }
    assert!(
        contents.contains(&format!("{APP_ID}-symbolic.svg")),
        "Makefile must install the symbolic icon variant",
    );
}

#[test]
fn nfpm_gtk_packaging_ships_the_full_hicolor_set() {
    let path = workspace_root().join("packaging").join("nfpm-gtk.yaml");
    let contents = read_text(&path);
    let mut expected = vec![
        format!("./data/icons/hicolor/scalable/apps/{APP_ID}.svg"),
        format!("/usr/share/icons/hicolor/scalable/apps/{APP_ID}.svg"),
        format!("./data/icons/hicolor/symbolic/apps/{APP_ID}-symbolic.svg"),
        format!("/usr/share/icons/hicolor/symbolic/apps/{APP_ID}-symbolic.svg"),
    ];
    for &size in HICOLOR_PNG_SIZES {
        expected.push(format!(
            "./data/icons/hicolor/{size}x{size}/apps/{APP_ID}.png"
        ));
        expected.push(format!(
            "/usr/share/icons/hicolor/{size}x{size}/apps/{APP_ID}.png"
        ));
    }
    for entry in expected {
        assert!(
            contents.contains(&entry),
            "packaging/nfpm-gtk.yaml must reference {entry}",
        );
    }
}
