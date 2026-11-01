//! Heavy HEVC / MP4 corpus round-trip validation.
//!
//! Run with:
//! ```text
//! cargo test --release --test heavy_tests heavy_hevc_mp4 -- --ignored --nocapture
//! ```

pub mod mp4_container {
    use std::fs;
    use std::path::{Path, PathBuf};
    use std::process::Command;
    use std::sync::Mutex;
    use std::time::Duration;

    use strhide::stego::Freshness;
    use strhide::stego::hevc::{embed_hevc, extract_hevc, probe_hevc_capacity};

    pub static FFMPEG_SERIAL_LOCK: Mutex<()> = Mutex::new(());

    const PASSWORD: &str = "Mp4CorpusValidation#2026";
    const MIN_PSNR_DB: f64 = 30.0;
    const CORPUS: [&str; 2] = ["VID_20261002_154545.mp4", "IMG_0033.MOV"];

    fn corpus_dir() -> Option<PathBuf> {
        if let Ok(val) = std::env::var("STRHIDE_HEVC_DIR") {
            let p = PathBuf::from(val);
            if p.is_dir() {
                return Some(p);
            }
        }
        let dir = PathBuf::from("../temp/testhevc");
        dir.is_dir().then_some(dir)
    }

    fn ffmpeg_available() -> bool {
        Command::new("ffmpeg")
            .arg("-version")
            .output()
            .map(|o| o.status.success())
            .unwrap_or(false)
    }

    fn wait_with_timeout(
        child: &mut std::process::Child,
        timeout: Duration,
    ) -> Result<std::process::ExitStatus, String> {
        let start = std::time::Instant::now();
        loop {
            if let Some(status) = child
                .try_wait()
                .map_err(|e| format!("try_wait failed: {e}"))?
            {
                return Ok(status);
            }
            if start.elapsed() > timeout {
                let _ = child.kill();
                let _ = child.wait();
                return Err("ffmpeg process timed out (killed)".to_string());
            }
            std::thread::sleep(Duration::from_millis(50));
        }
    }

    pub fn run_ffmpeg_with_timeout(args: &[&str], timeout: Duration) -> Result<String, String> {
        use std::io::Read;
        let mut child = Command::new("ffmpeg")
            .args(args)
            .stdin(std::process::Stdio::null())
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::piped())
            .spawn()
            .map_err(|e| format!("cannot run ffmpeg: {e}"))?;
        let mut stderr = child.stderr.take().ok_or("no stderr")?;
        let _ = wait_with_timeout(&mut child, timeout)?;
        let mut log = String::new();
        let _ = stderr.read_to_string(&mut log);
        Ok(log)
    }

    fn psnr_and_complaints(cover: &Path, stego: &Path) -> Result<(f64, Vec<String>), String> {
        let cov_str = cover.to_str().ok_or("invalid cover path")?;
        let stg_str = stego.to_str().ok_or("invalid stego path")?;
        let log = run_ffmpeg_with_timeout(
            &[
                "-hide_banner",
                "-nostdin",
                "-i",
                cov_str,
                "-i",
                stg_str,
                "-lavfi",
                "[0:v][1:v]psnr",
                "-f",
                "null",
                "-",
            ],
            Duration::from_secs(30),
        )?;
        let noise: Vec<String> = log
            .lines()
            .filter(|line| {
                if line.starts_with(' ') || line.starts_with('\t') {
                    return false;
                }
                let lower = line.to_ascii_lowercase();
                [
                    "error", "invalid", "corrupt", "missing", "truncat", "failed",
                ]
                .iter()
                .any(|needle| lower.contains(needle))
                    && !lower.contains("psnr")
            })
            .map(str::to_string)
            .collect();
        let psnr = log
            .lines()
            .filter_map(|line| line.split("average:").nth(1))
            .filter_map(|tail| tail.split_whitespace().next())
            .filter_map(|value| value.parse::<f64>().ok())
            .next_back()
            .ok_or_else(|| format!("ffmpeg produced no PSNR summary:\n{log}"))?;
        Ok((psnr, noise))
    }

    fn top_level_boxes(data: &[u8]) -> Vec<(String, usize, usize, usize)> {
        let mut out = Vec::new();
        let mut pos = 0usize;
        while pos + 8 <= data.len() {
            let size32 =
                u32::from_be_bytes([data[pos], data[pos + 1], data[pos + 2], data[pos + 3]]);
            let tag = String::from_utf8_lossy(&data[pos + 4..pos + 8]).to_string();
            let (hdr, size) = if size32 == 1 {
                let mut b = [0u8; 8];
                b.copy_from_slice(data.get(pos + 8..pos + 16).unwrap_or(&[0u8; 8]));
                (16usize, u64::from_be_bytes(b) as usize)
            } else if size32 == 0 {
                (8usize, data.len() - pos)
            } else {
                (8usize, size32 as usize)
            };
            if size < hdr || pos + size > data.len() {
                break;
            }
            out.push((tag, pos, pos + hdr, pos + size));
            pos += size;
        }
        out
    }

    #[test]
    #[ignore = "requires ffmpeg on PATH and the local temp/testhevc corpus"]
    pub fn heavy_hevc_mp4_corpus_roundtrip() {
        let _lock = FFMPEG_SERIAL_LOCK.lock().unwrap();
        if !ffmpeg_available() {
            eprintln!("[SKIP] ffmpeg not found on PATH");
            return;
        }
        let Some(dir) = corpus_dir() else {
            eprintln!("[SKIP] testhevc corpus not found");
            return;
        };

        let payload: Vec<u8> = (0..2048u32).map(|i| ((i * 37 + 11) % 256) as u8).collect();
        for (index, name) in CORPUS.iter().enumerate() {
            let cover_path = dir.join(name);
            if !cover_path.is_file() {
                continue;
            }
            let cover = fs::read(&cover_path).unwrap_or_else(|e| panic!("{name}: {e}"));
            let mut advertised = None;
            if index == 0 {
                let capacity =
                    probe_hevc_capacity(&cover, &strhide::stego::format::DEFAULT_HEVC_FORMAT)
                        .unwrap_or_else(|e| panic!("{name}: capacity probe failed: {e}"));
                assert!(
                    capacity >= payload.len(),
                    "{name}: capacity {capacity} B cannot hold {} B",
                    payload.len()
                );
                advertised = Some(capacity);
            }

            let stego = embed_hevc(
                &cover,
                &payload,
                Some(PASSWORD),
                None,
                &strhide::stego::format::DEFAULT_HEVC_FORMAT,
                Freshness::Random,
            )
            .unwrap_or_else(|e| panic!("{name}: embed failed: {e}"));
            assert_eq!(
                stego.len(),
                cover.len(),
                "{name}: an MP4 embed must not resize the container (Delta = 0)"
            );

            let cover_boxes = top_level_boxes(&cover);
            let stego_boxes = top_level_boxes(&stego);
            assert_eq!(
                cover_boxes.len(),
                stego_boxes.len(),
                "{name}: the top-level box layout changed"
            );
            for ((tag, _, cp, ce), (_, _, sp, se)) in cover_boxes.iter().zip(stego_boxes.iter()) {
                let identical = cover[*cp..*ce] == stego[*sp..*se];
                if tag == "mdat" {
                    assert!(!identical, "{name}: mdat must carry the payload");
                } else {
                    assert!(identical, "{name}: box `{tag}` must be byte-identical");
                }
            }

            let recovered = extract_hevc(
                &stego,
                Some(PASSWORD),
                None,
                &strhide::stego::format::DEFAULT_HEVC_FORMAT,
                &strhide::core::control::Control::none(),
            )
            .unwrap_or_else(|e| panic!("{name}: extract failed: {e}"));
            assert_eq!(recovered, payload, "{name}: round-trip must be byte-exact");

            let stego_path = std::env::temp_dir()
                .join(format!("strhide-hevc-mp4-{}-{name}", std::process::id()));
            fs::write(&stego_path, &stego).expect("write stego carrier");
            let (psnr, noise) = psnr_and_complaints(&cover_path, &stego_path)
                .unwrap_or_else(|e| panic!("{name}: ffmpeg: {e}"));
            let _ = fs::remove_file(&stego_path);

            println!(
                "[MP4] {name}: capacity={}, PSNR={psnr:.2} dB",
                advertised
                    .map(|c| format!("{c} B"))
                    .unwrap_or_else(|| "not probed".into())
            );
            assert!(
                noise.is_empty(),
                "{name}: ffmpeg reported trouble decoding the stego carrier: {noise:?}"
            );
            assert!(
                psnr >= MIN_PSNR_DB,
                "{name}: PSNR {psnr:.2} dB is below the {MIN_PSNR_DB:.0} dB floor"
            );
        }
    }
}
