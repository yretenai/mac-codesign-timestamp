use std::fs;
use std::path::PathBuf;

use anyhow::anyhow;
use chrono::{DateTime, Utc};
use cryptographic_message_syntax::SignedData;
use goblin::mach::{load_command::CommandVariant, Mach, MachO};
use scroll::{Pread, Pwrite, SizeWith};
use serde::Deserialize;

#[derive(Deserialize)]
#[serde()]
struct BundleInfo {
    #[serde(rename = "CFBundleExecutable")]
    pub cf_bundle_executable: Option<String>,
}

#[repr(C)]
#[derive(Clone, Copy, Default, Pread, Pwrite, SizeWith)]
struct CodeSigningSuperBlob {
    magic: u32,
    length: u32,
    count: u32,
}

#[repr(C)]
#[derive(Clone, Copy, Default, Pread, Pwrite, SizeWith)]
struct CodeSigningBlobIndex {
    slot: u32,
    offset: u32,
}

#[repr(C)]
#[derive(Clone, Copy, Default, Pread, Pwrite, SizeWith)]
struct CodeSigningBlobWrapper {
    magic: u32,
    length: u32,
}

pub const CSMAGIC_EMBEDDED_SIGNATURE: u32 = 0xfade0cc0;
pub const CSMAGIC_EMBEDDED_SIGNATURE_OLD: u32 = 0xfade0b02;
pub const CSSLOT_CMS_SIGNATURE: u32 = 0x10000;

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();

    for argument in args {
        match process_macho(&argument) {
            Ok(time) => {
                println!("{}\t{}", argument, time.format("%Y-%m-%d %H:%M:%S"));
            }
            Err(e) => {
                eprintln!("{}\t{}", argument, e);
            }
        }
    }
}

fn process_macho(argument: &String) -> anyhow::Result<DateTime<Utc>> {
    if !fs::exists(&argument)? && !argument.ends_with(".app") {
        let combined = argument.clone() + ".app";
        return process_macho(&combined);
    }

    if fs::metadata(&argument)?.is_dir() {
        let info_path = PathBuf::from(&argument).join("Contents/Info.plist");
        let bundle: BundleInfo = plist::from_file(info_path)?;
        return match bundle.cf_bundle_executable {
            Some(cf_bundle_executable) => {
                let bundle_executable = match PathBuf::from(&argument)
                    .join("Contents/MacOS")
                    .join(cf_bundle_executable)
                    .into_os_string()
                    .into_string()
                {
                    Ok(bundle_executable) => bundle_executable,
                    Err(_) => return Err(anyhow!("cannot convert path")),
                };
                process_macho(&bundle_executable)
            }
            None => Err(anyhow!("not an app bundle")),
        };
    }

    let bytes = fs::read(&argument)?;
    let macho = Mach::parse(&bytes)?;

    use goblin::mach::Mach::*;
    match macho {
        Fat(fat) => {
            use goblin::mach::SingleArch::*;
            match fat.get(0)? {
                MachO(binary) => {
                    let offset = fat.arches()?.first().unwrap().offset as usize;
                    process_macho_binary(binary, &bytes, offset)
                }
                _ => Err(anyhow!("not a macho")),
            }
        }
        Binary(binary) => process_macho_binary(binary, &bytes, 0),
    }
}

fn process_macho_binary(
    binary: MachO,
    bytes: &[u8],
    offset: usize,
) -> anyhow::Result<DateTime<Utc>> {
    for load_command in binary.load_commands {
        if let CommandVariant::CodeSignature(code_signature) = load_command.command {
            let data_start = code_signature.dataoff as usize + offset;
            let data_end = data_start + code_signature.datasize as usize;
            return process_macho_code_signature(&bytes[data_start..data_end]);
        }
    }

    Err(anyhow!("no codesign"))
}

fn process_macho_code_signature(bytes: &[u8]) -> anyhow::Result<DateTime<Utc>> {
    let mut offset = 0;
    let header = bytes.gread_with::<CodeSigningSuperBlob>(&mut offset, scroll::BE)?;

    if header.magic != CSMAGIC_EMBEDDED_SIGNATURE && header.magic != CSMAGIC_EMBEDDED_SIGNATURE_OLD
    {
        return Err(anyhow!("invalid signature"));
    }

    for _ in 0..header.count {
        let blob_index = bytes.gread_with::<CodeSigningBlobIndex>(&mut offset, scroll::BE)?;
        if blob_index.slot != CSSLOT_CMS_SIGNATURE {
            continue;
        }

        let mut signature_offset = blob_index.offset as usize;
        let blob_header =
            bytes.gread_with::<CodeSigningBlobWrapper>(&mut signature_offset, scroll::BE)?;
        let signature_end = signature_offset + blob_header.length as usize;
        let signature = &bytes[signature_offset..signature_end];

        // this is actually BER
        let cms = SignedData::parse_ber(signature)?;
        for signer in cms.signers() {
            let attributes = match signer.signed_attributes() {
                Some(attrs) => attrs,
                None => continue,
            };

            if let Some(time) = attributes.signing_time() {
                return Ok(time.clone());
            }
        }
    }

    Err(anyhow!("no signature found"))
}
