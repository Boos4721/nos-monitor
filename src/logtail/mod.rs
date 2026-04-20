pub mod json_line;

use crate::config::StartPosition;
use crate::detect::InputEvent;
use std::fs::File;
use std::io::{BufRead, BufReader, Seek, SeekFrom};
use std::os::unix::fs::MetadataExt;
use std::path::PathBuf;
use std::thread;
use std::time::Duration;
use tokio::sync::mpsc;

pub fn follow_file(
    path: PathBuf,
    start_position: StartPosition,
    node_addr: Option<String>,
    client_id: Option<String>,
    tx: mpsc::Sender<InputEvent>,
) -> anyhow::Result<()> {
    loop {
        match open_reader(&path, start_position) {
            Ok((mut reader, mut inode, mut last_pos)) => {
                let mut buf = String::new();
                loop {
                    buf.clear();
                    match reader.read_line(&mut buf) {
                        Ok(0) => {
                            thread::sleep(Duration::from_millis(200));
                            if let Ok(meta) = std::fs::metadata(&path) {
                                let new_inode = meta.ino();
                                let new_len = meta.len();
                                if new_inode != inode || new_len < last_pos {
                                    break;
                                }
                            }
                        }
                        Ok(_) => {
                            last_pos = reader.stream_position().unwrap_or(last_pos);
                            let line = buf.trim_end_matches(['\n', '\r']).to_string();
                            if tx
                                .blocking_send(InputEvent::LogLine {
                                    path: path.clone(),
                                    line,
                                    node_addr: node_addr.clone(),
                                    client_id: client_id.clone(),
                                })
                                .is_err()
                            {
                                return Ok(());
                            }
                        }
                        Err(_) => {
                            thread::sleep(Duration::from_millis(200));
                        }
                    }
                }

                if let Ok(meta) = std::fs::metadata(&path) {
                    inode = meta.ino();
                }
                let _ = inode;
            }
            Err(_) => {
                thread::sleep(Duration::from_secs(1));
            }
        }
    }
}

fn open_reader(path: &PathBuf, start_position: StartPosition) -> anyhow::Result<(BufReader<File>, u64, u64)> {
    let mut f = File::open(path)?;
    let meta = f.metadata()?;
    let inode = meta.ino();

    match start_position {
        StartPosition::End => {
            f.seek(SeekFrom::End(0))?;
        }
        StartPosition::Beginning => {
            f.seek(SeekFrom::Start(0))?;
        }
    }

    let pos = f.stream_position().unwrap_or(0);
    Ok((BufReader::new(f), inode, pos))
}
