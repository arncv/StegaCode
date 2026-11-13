use std::{
    fs,
    io::{self, IsTerminal, Write},
    path::{Path, PathBuf},
    process::ExitCode,
};

use anyhow::{bail, Context, Result};
use clap::{Parser, Subcommand};
use image::RgbaImage;
use tempfile::NamedTempFile;
use zeroize::Zeroizing;

#[derive(Parser)]
#[command(
    version,
    about = "Hide files in PNG images, with optional password encryption"
)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Hide a file in an image and save a lossless PNG
    Encode {
        #[arg(short, long)]
        image: PathBuf,
        #[arg(short, long)]
        file: PathBuf,
        #[arg(short, long)]
        output: PathBuf,
        /// Encrypt using a password entered at a hidden prompt
        #[arg(long, conflicts_with = "password_file")]
        encrypt: bool,
        /// Read a password from a file instead of prompting; enables encryption
        #[arg(long)]
        password_file: Option<PathBuf>,
        /// Replace an existing output file
        #[arg(long)]
        force: bool,
    },
    /// Extract a file; encrypted images prompt for a password automatically
    Decode {
        #[arg(short, long)]
        image: PathBuf,
        /// Output path; defaults to the validated embedded basename
        #[arg(short, long)]
        output: Option<PathBuf>,
        /// Read the decryption password from a file instead of prompting
        #[arg(long)]
        password_file: Option<PathBuf>,
        /// Replace an existing output file
        #[arg(long)]
        force: bool,
    },
    /// Show the exact maximum payload size in bytes
    Capacity {
        #[arg(short, long)]
        image: PathBuf,
        /// Basename to embed (its UTF-8 byte length affects capacity)
        #[arg(long, default_value = "secret.txt")]
        name: String,
        /// Include encryption overhead in the calculation
        #[arg(long)]
        encrypted: bool,
    },
}

fn main() -> ExitCode {
    match run(Cli::parse()) {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("error: {error:#}");
            ExitCode::FAILURE
        }
    }
}

fn open_image(path: &Path) -> Result<RgbaImage> {
    image::ImageReader::open(path)
        .with_context(|| format!("cannot open image {}", path.display()))?
        .with_guessed_format()
        .context("cannot determine image format")?
        .decode()
        .with_context(|| format!("cannot decode image {}", path.display()))
        .map(|image| image.to_rgba8())
}

fn read_password(
    prompt: bool,
    file: Option<&Path>,
    confirm: bool,
) -> Result<Option<Zeroizing<Vec<u8>>>> {
    let password = if let Some(path) = file {
        let mut bytes = Zeroizing::new(fs::read(path).context("cannot read password file")?);
        // Remove one conventional line ending, preserving spaces and other bytes.
        if bytes.last() == Some(&b'\n') {
            bytes.pop();
            if bytes.last() == Some(&b'\r') {
                bytes.pop();
            }
        }
        bytes
    } else if prompt {
        if !io::stdin().is_terminal() {
            bail!("a password is required; use --password-file in noninteractive sessions");
        }
        let entered = Zeroizing::new(
            rpassword::prompt_password("Password: ").context("cannot read password")?,
        );
        if confirm {
            let confirmation = Zeroizing::new(
                rpassword::prompt_password("Confirm password: ")
                    .context("cannot confirm password")?,
            );
            if *entered != *confirmation {
                bail!("passwords do not match");
            }
        }
        Zeroizing::new(entered.as_bytes().to_vec())
    } else {
        return Ok(None);
    };
    if password.is_empty() {
        bail!("password cannot be empty");
    }
    Ok(Some(password))
}

// A temporary file in the destination directory allows atomic replacement. Without
// --force, persist_noclobber refuses existing files, including dangling symlinks.
fn write_output(
    path: &Path,
    force: bool,
    write: impl FnOnce(&mut NamedTempFile) -> Result<()>,
) -> Result<()> {
    let parent = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    let mut temp = NamedTempFile::new_in(parent)
        .with_context(|| format!("cannot create output in {}", parent.display()))?;
    write(&mut temp)?;
    temp.as_file().sync_all().context("cannot flush output")?;
    let result = if force {
        temp.persist(path)
    } else {
        temp.persist_noclobber(path)
    };
    result.map_err(|error| error.error).with_context(|| {
        format!(
            "cannot save {} (existing files require --force)",
            path.display()
        )
    })?;
    Ok(())
}

fn run(cli: Cli) -> Result<()> {
    match cli.command {
        Commands::Encode {
            image,
            file,
            output,
            encrypt,
            password_file,
            force,
        } => {
            if !output
                .extension()
                .is_some_and(|ext| ext.eq_ignore_ascii_case("png"))
            {
                bail!(
                    "encoded output must have a .png extension; lossy formats destroy hidden data"
                );
            }
            let mut image = open_image(&image)?;
            let name = file
                .file_name()
                .and_then(|name| name.to_str())
                .context("input file needs a UTF-8 basename")?;
            let encrypted = encrypt || password_file.is_some();
            let available = stegacode::capacity(&image, name, encrypted)?;
            let metadata = fs::metadata(&file)
                .with_context(|| format!("cannot read input {}", file.display()))?;
            if !metadata.is_file() {
                bail!("input must be a regular file");
            }
            if metadata.len() > available as u64 {
                bail!(
                    "input is {} bytes; image has space for {available}",
                    metadata.len()
                );
            }
            let data = Zeroizing::new(
                fs::read(&file).with_context(|| format!("cannot read input {}", file.display()))?,
            );
            let password = read_password(encrypt, password_file.as_deref(), true)?;
            stegacode::encode(
                &mut image,
                &data,
                name,
                password.as_ref().map(|p| p.as_slice()),
            )?;
            write_output(&output, force, |temp| {
                image
                    .write_to(temp, image::ImageFormat::Png)
                    .context("cannot encode output PNG")
            })?;
            println!("Encoded {} bytes into {}", data.len(), output.display());
        }
        Commands::Decode {
            image,
            output,
            password_file,
            force,
        } => {
            let image = open_image(&image)?;
            let info = stegacode::inspect(&image)?;
            let password = read_password(info.encrypted, password_file.as_deref(), false)?;
            let decoded = stegacode::decode(&image, password.as_ref().map(|p| p.as_slice()))?;
            let data = Zeroizing::new(decoded.data);
            let output = output.unwrap_or_else(|| PathBuf::from(decoded.name));
            write_output(&output, force, |temp| {
                temp.write_all(&data).context("cannot write decoded file")
            })?;
            println!("Decoded {} bytes into {}", data.len(), output.display());
        }
        Commands::Capacity {
            image,
            name,
            encrypted,
        } => {
            let image = open_image(&image)?;
            println!("{} bytes", stegacode::capacity(&image, &name, encrypted)?);
        }
    }
    Ok(())
}
