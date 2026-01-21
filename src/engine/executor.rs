use crate::core::error::RustChainError;
use crate::engine::mission_loader::{MissionFile, MissionTask};
use std::fs::{OpenOptions, create_dir_all};
use std::io::{Write, Read};
use std::path::Path;

pub fn run_mission(mission: &MissionFile) -> Result<(), RustChainError> {
    for task in &mission.tasks {
        match task.op.as_str() {
            "create" => {
                let path = Path::new(&task.file);
                if let Some(parent) = path.parent() {
                    create_dir_all(parent)?;
                }
                let mut file = OpenOptions::new()
                    .create(true)
                    .write(true)
                    .truncate(true)
                    .open(&task.file)?;
                file.write_all(task.edit.as_bytes())?;
            }

            "edit" => {
                let path = Path::new(&task.file);
                if !path.exists() {
                    return Err(RustChainError::Exec(format!("File not found: {}", &task.file)));
                }

                let mut original = String::new();
                std::fs::File::open(&task.file)?.read_to_string(&mut original)?;
                let merged = format!("{}\n{}", original.trim_end(), task.edit.trim_start());
                std::fs::write(&task.file, merged)?;
            }

            _ => {
                return Err(RustChainError::Exec(format!("Unknown op: {}", task.op)));
            }
        }
    }
    Ok(())
}
