//! The window icon, decoded from the bundled .ico, and the title bar.

pub fn window_icon_rgba(size: u32) -> Vec<u8> {
    const ICO: &[u8] = include_bytes!("../../assets/secblitz.ico");
    ico_frame(ICO, size).unwrap_or_default()
}

fn ico_frame(ico: &[u8], size: u32) -> Option<Vec<u8>> {
    let count = u16::from_le_bytes([*ico.get(4)?, *ico.get(5)?]) as usize;
    for i in 0..count {
        let entry = ico.get(6 + 16 * i..22 + 16 * i)?;
        let width = if entry[0] == 0 {
            256
        } else {
            u32::from(entry[0])
        };
        if width != size {
            continue;
        }
        let len = u32::from_le_bytes(entry[8..12].try_into().ok()?) as usize;
        let offset = u32::from_le_bytes(entry[12..16].try_into().ok()?) as usize;
        let mut reader = png::Decoder::new(ico.get(offset..offset.checked_add(len)?)?)
            .read_info()
            .ok()?;
        let mut pixels = vec![0; reader.output_buffer_size()];
        let frame = reader.next_frame(&mut pixels).ok()?;
        let rgba = frame.color_type == png::ColorType::Rgba
            && frame.bit_depth == png::BitDepth::Eight
            && frame.width == size
            && frame.height == size;
        pixels.truncate(frame.buffer_size());
        return rgba.then_some(pixels);
    }
    None
}

pub fn window_icon() -> Option<iced::window::Icon> {
    iced::window::icon::from_rgba(window_icon_rgba(64), 64, 64).ok()
}

/// Keeps Windows' own title bar buttons, snapping and dragging, but without the icon and name
/// (they stay on the taskbar) and in the app's colours, so the window reads as one surface.
/// Windows 10 cannot colour a title bar; it keeps the plain one.
pub fn match_title_bar(palette: super::theme::Palette) -> iced::Task<()> {
    iced::window::latest().and_then(move |id| {
        iced::window::run(id, move |window| {
            #[cfg(windows)]
            blend(window, palette);
            #[cfg(not(windows))]
            let _ = (window, palette);
        })
    })
}

#[cfg(windows)]
fn blend(window: &dyn iced::window::Window, palette: super::theme::Palette) {
    use core::ffi::c_void;
    use iced::window::raw_window_handle::RawWindowHandle;
    use windows_sys::Win32::{
        Graphics::Dwm::{
            DwmSetWindowAttribute, DWMWA_CAPTION_COLOR, DWMWA_USE_IMMERSIVE_DARK_MODE,
        },
        UI::{
            Controls::{SetWindowThemeAttribute, WTA_NONCLIENT, WTA_OPTIONS, WTNCA_NODRAWCAPTION},
            Shell::SetWindowSubclass,
            WindowsAndMessaging::{
                GetWindowLongPtrW, SendMessageW, SetWindowLongPtrW, SetWindowPos, GWL_EXSTYLE,
                ICON_BIG, ICON_SMALL, SWP_FRAMECHANGED, SWP_NOMOVE, SWP_NOSIZE, SWP_NOZORDER,
                WM_SETICON, WS_EX_DLGMODALFRAME,
            },
        },
    };
    let Ok(handle) = window.window_handle() else {
        return;
    };
    let RawWindowHandle::Win32(win32) = handle.as_raw() else {
        return;
    };
    let hwnd = win32.hwnd.get() as *mut c_void;
    let options = WTA_OPTIONS {
        dwFlags: WTNCA_NODRAWCAPTION,
        dwMask: WTNCA_NODRAWCAPTION,
    };
    let dark = i32::from(palette.mode == super::theme::Mode::Dark);
    let caption = colorref(palette.bg);
    // SAFETY: `hwnd` is this app's live window, borrowed for the duration of the callback, and
    // each pointer refers to a local value of exactly the size passed. The results are ignored:
    // a refusal only leaves Windows' usual title bar.
    unsafe {
        // Windows ignores WTNCA_NODRAWICON. A dialog frame whose icon was taken away draws none,
        // and has no hidden menu button where it was. winit rewrites the extended style whenever
        // the window changes state, so the hook keeps the frame, and it hands the icon to Alt+Tab
        // and the taskbar, which ask for it.
        SetWindowSubclass(hwnd, Some(title_bar_hook), 1, 0);
        let ex = GetWindowLongPtrW(hwnd, GWL_EXSTYLE);
        SetWindowLongPtrW(hwnd, GWL_EXSTYLE, ex | WS_EX_DLGMODALFRAME as isize);
        SendMessageW(hwnd, WM_SETICON, ICON_SMALL as usize, 0);
        SendMessageW(hwnd, WM_SETICON, ICON_BIG as usize, 0);
        SetWindowPos(
            hwnd,
            core::ptr::null_mut(),
            0,
            0,
            0,
            0,
            SWP_FRAMECHANGED | SWP_NOMOVE | SWP_NOSIZE | SWP_NOZORDER,
        );
        SetWindowThemeAttribute(
            hwnd,
            WTA_NONCLIENT,
            (&raw const options).cast(),
            size_of::<WTA_OPTIONS>() as u32,
        );
        DwmSetWindowAttribute(
            hwnd,
            DWMWA_USE_IMMERSIVE_DARK_MODE as u32,
            (&raw const dark).cast(),
            size_of::<i32>() as u32,
        );
        DwmSetWindowAttribute(
            hwnd,
            DWMWA_CAPTION_COLOR as u32,
            (&raw const caption).cast(),
            size_of::<u32>() as u32,
        );
    }
}

/// The shield from the program's resources, large and small, loaded once and kept.
#[cfg(windows)]
fn shield(big: bool) -> isize {
    use windows_sys::Win32::{
        System::LibraryLoader::GetModuleHandleW,
        UI::WindowsAndMessaging::{
            GetSystemMetrics, LoadImageW, IMAGE_ICON, SM_CXICON, SM_CXSMICON,
        },
    };
    static ICONS: std::sync::OnceLock<(isize, isize)> = std::sync::OnceLock::new();
    let load = |metric| {
        // SAFETY: resource 1 is the icon compiled into this program, and the handle is never
        // destroyed, so it stays valid for every caller.
        unsafe {
            let size = GetSystemMetrics(metric);
            LoadImageW(
                GetModuleHandleW(core::ptr::null()),
                1 as _,
                IMAGE_ICON,
                size,
                size,
                0,
            ) as isize
        }
    };
    let (large, small) = *ICONS.get_or_init(|| (load(SM_CXICON), load(SM_CXSMICON)));
    if big {
        large
    } else {
        small
    }
}

#[cfg(windows)]
unsafe extern "system" fn title_bar_hook(
    hwnd: windows_sys::Win32::Foundation::HWND,
    msg: u32,
    wparam: usize,
    lparam: isize,
    id: usize,
    _: usize,
) -> isize {
    use windows_sys::Win32::UI::{
        Shell::{DefSubclassProc, RemoveWindowSubclass},
        WindowsAndMessaging::{
            GWL_EXSTYLE, ICON_BIG, STYLESTRUCT, WM_GETICON, WM_NCDESTROY, WM_STYLECHANGING,
            WS_EX_DLGMODALFRAME,
        },
    };
    // SAFETY: Windows passes a valid STYLESTRUCT with WM_STYLECHANGING, and the hook is removed
    // before the window is gone.
    unsafe {
        match msg {
            WM_STYLECHANGING if wparam as i32 == GWL_EXSTYLE => {
                (*(lparam as *mut STYLESTRUCT)).styleNew |= WS_EX_DLGMODALFRAME;
            }
            WM_GETICON => {
                let own = DefSubclassProc(hwnd, msg, wparam, lparam);
                return if own != 0 {
                    own
                } else {
                    shield(wparam == ICON_BIG as usize)
                };
            }
            WM_NCDESTROY => {
                RemoveWindowSubclass(hwnd, Some(title_bar_hook), id);
            }
            _ => {}
        }
        DefSubclassProc(hwnd, msg, wparam, lparam)
    }
}

/// Windows colours are 0x00BBGGRR.
#[cfg(any(windows, test))]
fn colorref(color: iced::Color) -> u32 {
    let channel = |c: f32| (c.clamp(0.0, 1.0) * 255.0).round() as u32;
    channel(color.r) | channel(color.g) << 8 | channel(color.b) << 16
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn icon_has_expected_size_and_shape() {
        let px = window_icon_rgba(32);
        assert_eq!(px.len(), 32 * 32 * 4);
        let at = |x: usize, y: usize| &px[(y * 32 + x) * 4..(y * 32 + x) * 4 + 4];
        assert_eq!(at(0, 0)[3], 0, "corner is transparent");
        assert_eq!(at(7, 13)[..3], [255, 255, 255], "shield outline is white");
        assert_eq!(at(3, 16)[..3], [0x18, 0x18, 0x1B], "the tile is ink");
        assert!(
            at(11, 13)[..3].iter().all(|&c| c < 0x30),
            "inside the shield is dark"
        );
        assert_eq!(at(15, 11)[..3], [255, 255, 255], "the bolt is white");
        assert_eq!(window_icon_rgba(64).len(), 64 * 64 * 4);
        assert!(window_icon_rgba(33).is_empty(), "no frame, no icon");
        assert!(window_icon().is_some());
    }

    #[test]
    fn title_bar_colours_are_in_windows_order() {
        assert_eq!(
            colorref(iced::Color::from_rgb8(0xF7, 0xF7, 0xF8)),
            0x00F8F7F7
        );
        assert_eq!(
            colorref(iced::Color::from_rgb8(0x12, 0x34, 0x56)),
            0x00563412
        );
    }
}
