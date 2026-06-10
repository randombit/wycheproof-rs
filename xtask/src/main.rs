use std::collections::{BTreeMap, BTreeSet};
use std::env;
use std::ffi::OsStr;
use std::fs;
use std::io;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

type Result<T> = std::result::Result<T, String>;

#[derive(Debug, Clone)]
struct ManifestEntry {
    file_name: String,
    local_dir: PathBuf,
}

#[derive(Debug, Clone)]
struct Source {
    repo_url: String,
    upstream_ref: String,
    data_dir: String,
}

#[derive(Debug)]
struct VerifyArgs {
    manifest: PathBuf,
    hashes: PathBuf,
    source: PathBuf,
    crate_filter: Option<String>,
    offline: bool,
    report_only: bool,
    drift_check: bool,
}

fn main() {
    if let Err(err) = run() {
        eprintln!("{}", err);
        std::process::exit(1);
    }
}

fn run() -> Result<()> {
    let repo_root = repo_root();
    let args = parse_args(&repo_root)?;

    if args.offline {
        verify_offline(&repo_root, &args)
    } else {
        verify_against_upstream(&repo_root, &args)
    }
}

fn repo_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("xtask lives below repository root")
        .to_path_buf()
}

fn parse_args(repo_root: &Path) -> Result<VerifyArgs> {
    let mut it = env::args().skip(1);
    match it.next().as_deref() {
        Some("verify-data") => {}
        _ => return Err(usage()),
    }

    let mut args = VerifyArgs {
        manifest: repo_root.join("scripts/wycheproof-data-manifest.tsv"),
        hashes: repo_root.join("scripts/wycheproof-data-sha256.tsv"),
        source: repo_root.join("scripts/wycheproof-source.env"),
        crate_filter: None,
        offline: false,
        report_only: false,
        drift_check: false,
    };

    while let Some(arg) = it.next() {
        match arg.as_str() {
            "--all" => {}
            "--offline" => args.offline = true,
            "--report-only" => args.report_only = true,
            "--drift-check" => {
                args.report_only = true;
                args.drift_check = true;
            }
            "--crate" => {
                args.crate_filter = Some(
                    it.next()
                        .ok_or_else(|| "--crate requires a crate name".to_string())?,
                );
            }
            "--manifest" => {
                args.manifest = repo_root.join(
                    it.next()
                        .ok_or_else(|| "--manifest requires a path".to_string())?,
                );
            }
            "--hashes" => {
                args.hashes = repo_root.join(
                    it.next()
                        .ok_or_else(|| "--hashes requires a path".to_string())?,
                );
            }
            "--source" => {
                args.source = repo_root.join(
                    it.next()
                        .ok_or_else(|| "--source requires a path".to_string())?,
                );
            }
            "--upstream-ref" => {
                let upstream_ref = it
                    .next()
                    .ok_or_else(|| "--upstream-ref requires a ref".to_string())?;
                let source = read_source(&args.source)?;
                write_temp_source(repo_root, &source, &upstream_ref, &mut args)?;
            }
            _ => return Err(format!("unknown argument: {}\n\n{}", arg, usage())),
        }
    }

    Ok(args)
}

fn usage() -> String {
    "usage: cargo run -p xtask -- verify-data [--all] [--offline] [--crate NAME] [--report-only] [--drift-check]"
        .to_string()
}

fn write_temp_source(
    repo_root: &Path,
    source: &Source,
    upstream_ref: &str,
    args: &mut VerifyArgs,
) -> Result<()> {
    let path = repo_root
        .join("target")
        .join("xtask")
        .join("wycheproof-source.override.env");
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).map_err(|e| format!("create {}: {}", parent.display(), e))?;
    }
    fs::write(
        &path,
        format!(
            "UPSTREAM_REPO_URL={}\nUPSTREAM_REF={}\nUPSTREAM_DATA_DIR={}\n",
            source.repo_url, upstream_ref, source.data_dir
        ),
    )
    .map_err(|e| format!("write {}: {}", path.display(), e))?;
    args.source = path;
    Ok(())
}

fn verify_against_upstream(repo_root: &Path, args: &VerifyArgs) -> Result<()> {
    let source = read_source(&args.source)?;
    let manifest = filtered_manifest(read_manifest(&args.manifest)?, &args.crate_filter);
    ensure_manifest_local_files(
        repo_root,
        &manifest,
        &args.crate_filter,
        args.report_only,
        args.drift_check,
    )?;

    let tmp = repo_root
        .join("target")
        .join("wycheproof-upstream")
        .join(std::process::id().to_string());
    let extract = tmp.join("extract");
    fs::create_dir_all(&extract).map_err(|e| format!("create {}: {}", extract.display(), e))?;

    let archive = tmp.join("wycheproof.tar.gz");
    command(
        "curl",
        &[
            "-fsSL",
            "--retry",
            "3",
            "--connect-timeout",
            "15",
            "--max-time",
            "180",
            &format!("{}/archive/{}.tar.gz", source.repo_url, source.upstream_ref),
            "-o",
            archive
                .to_str()
                .ok_or_else(|| "non-utf8 archive path".to_string())?,
        ],
    )?;
    command(
        "tar",
        &[
            "-xzf",
            archive
                .to_str()
                .ok_or_else(|| "non-utf8 archive path".to_string())?,
            "-C",
            extract
                .to_str()
                .ok_or_else(|| "non-utf8 extract path".to_string())?,
        ],
    )?;

    let upstream_root = first_dir(&extract)?;
    let upstream_data = upstream_root.join(&source.data_dir);
    if !upstream_data.is_dir() {
        return Err(format!(
            "missing upstream data dir {}",
            upstream_data.display()
        ));
    }

    let mut problems = Vec::new();
    if args.crate_filter.is_none() {
        let upstream_files = json_names_in_dir(&upstream_data)?;
        let manifest_files = manifest
            .iter()
            .map(|entry| entry.file_name.clone())
            .collect::<BTreeSet<_>>();
        compare_sets(
            "upstream files absent from manifest",
            "manifest files absent upstream",
            &upstream_files,
            &manifest_files,
            &mut problems,
        );
    }

    for entry in &manifest {
        let upstream_path = upstream_data.join(&entry.file_name);
        let local_path = repo_root.join(&entry.local_dir).join(&entry.file_name);
        if !upstream_path.is_file() {
            problems.push(format!("missing upstream file {}", upstream_path.display()));
            continue;
        }
        if !local_path.is_file() {
            problems.push(format!("missing local file {}", local_path.display()));
            continue;
        }
        let upstream_bytes = fs::read(&upstream_path)
            .map_err(|e| format!("read {}: {}", upstream_path.display(), e))?;
        let local_bytes =
            fs::read(&local_path).map_err(|e| format!("read {}: {}", local_path.display(), e))?;
        if upstream_bytes != local_bytes {
            problems.push(format!(
                "content mismatch: {} vs {}",
                local_path.display(),
                upstream_path.display()
            ));
        }
    }

    let _ = fs::remove_dir_all(&tmp);
    finish(
        problems,
        args.report_only,
        args.drift_check,
        &format!(
            "verified {} local files against {}@{}:{}",
            manifest.len(),
            source.repo_url,
            source.upstream_ref,
            source.data_dir
        ),
    )
}

fn verify_offline(repo_root: &Path, args: &VerifyArgs) -> Result<()> {
    let manifest = filtered_manifest(read_manifest(&args.manifest)?, &args.crate_filter);
    ensure_manifest_local_files(
        repo_root,
        &manifest,
        &args.crate_filter,
        args.report_only,
        args.drift_check,
    )?;
    let hashes = read_hashes(&args.hashes)?;
    let mut problems = Vec::new();

    for entry in &manifest {
        let path = entry_path(&entry.local_dir, &entry.file_name);
        let abs = repo_root.join(&path);
        let expected = match hashes.get(&path) {
            Some(hash) => hash,
            None => {
                problems.push(format!("missing hash entry for {}", path.display()));
                continue;
            }
        };
        let actual = sha256_file(&abs)?;
        if actual != *expected {
            problems.push(format!(
                "sha256 mismatch for {}: expected {}, got {}",
                path.display(),
                expected,
                actual
            ));
        }
    }

    if args.crate_filter.is_none() {
        let manifest_paths = manifest
            .iter()
            .map(|entry| entry_path(&entry.local_dir, &entry.file_name))
            .collect::<BTreeSet<_>>();
        let hash_paths = hashes.keys().cloned().collect::<BTreeSet<_>>();
        compare_sets(
            "manifest paths absent from hash list",
            "hash paths absent from manifest",
            &manifest_paths,
            &hash_paths,
            &mut problems,
        );
    }

    finish(
        problems,
        args.report_only,
        args.drift_check,
        &format!(
            "verified {} local files against SHA-256 manifest",
            manifest.len()
        ),
    )
}

fn finish(
    problems: Vec<String>,
    report_only: bool,
    drift_check: bool,
    success: &str,
) -> Result<()> {
    if problems.is_empty() {
        println!("{}", success);
        Ok(())
    } else {
        for problem in &problems {
            eprintln!("{}", problem);
        }
        if drift_check {
            eprintln!("drift-check mode: {} problem(s)", problems.len());
            std::process::exit(20);
        } else if report_only {
            eprintln!("report-only mode: {} problem(s)", problems.len());
            Ok(())
        } else {
            Err(format!(
                "verification failed with {} problem(s)",
                problems.len()
            ))
        }
    }
}

fn ensure_manifest_local_files(
    repo_root: &Path,
    manifest: &[ManifestEntry],
    crate_filter: &Option<String>,
    report_only: bool,
    drift_check: bool,
) -> Result<()> {
    let mut problems = Vec::new();
    let mut seen_files = BTreeSet::new();
    let mut manifest_paths = BTreeSet::new();

    for entry in manifest {
        if !seen_files.insert(entry.file_name.clone()) && crate_filter.is_none() {
            problems.push(format!("duplicate manifest file name {}", entry.file_name));
        }
        let path = entry_path(&entry.local_dir, &entry.file_name);
        if !repo_root.join(&path).is_file() {
            problems.push(format!(
                "manifest points to missing file {}",
                path.display()
            ));
        }
        manifest_paths.insert(path);
    }

    let local_files = local_vector_files(repo_root, crate_filter)?;
    compare_sets(
        "local files absent from manifest",
        "manifest paths absent from local files",
        &local_files,
        &manifest_paths,
        &mut problems,
    );

    finish(
        problems,
        report_only,
        drift_check,
        "manifest covers local vector files",
    )
}

fn read_source(path: &Path) -> Result<Source> {
    let content =
        fs::read_to_string(path).map_err(|e| format!("read {}: {}", path.display(), e))?;
    let mut map = BTreeMap::new();
    for line in content.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let mut parts = line.splitn(2, '=');
        let key = parts.next().unwrap().trim();
        let value = parts
            .next()
            .ok_or_else(|| format!("invalid source line: {}", line))?
            .trim();
        map.insert(key.to_string(), value.to_string());
    }
    Ok(Source {
        repo_url: map
            .remove("UPSTREAM_REPO_URL")
            .ok_or_else(|| "UPSTREAM_REPO_URL missing".to_string())?,
        upstream_ref: map
            .remove("UPSTREAM_REF")
            .ok_or_else(|| "UPSTREAM_REF missing".to_string())?,
        data_dir: map
            .remove("UPSTREAM_DATA_DIR")
            .ok_or_else(|| "UPSTREAM_DATA_DIR missing".to_string())?,
    })
}

fn read_manifest(path: &Path) -> Result<Vec<ManifestEntry>> {
    let content =
        fs::read_to_string(path).map_err(|e| format!("read {}: {}", path.display(), e))?;
    let mut entries = Vec::new();
    for (idx, line) in content.lines().enumerate() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let fields = line.split('\t').collect::<Vec<_>>();
        if fields.len() != 2 {
            return Err(format!(
                "{}:{}: expected two tab-separated fields",
                path.display(),
                idx + 1
            ));
        }
        entries.push(ManifestEntry {
            file_name: fields[0].to_string(),
            local_dir: PathBuf::from(fields[1]),
        });
    }
    Ok(entries)
}

fn read_hashes(path: &Path) -> Result<BTreeMap<PathBuf, String>> {
    let content =
        fs::read_to_string(path).map_err(|e| format!("read {}: {}", path.display(), e))?;
    let mut hashes = BTreeMap::new();
    for (idx, line) in content.lines().enumerate() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let fields = line.split('\t').collect::<Vec<_>>();
        if fields.len() != 2 {
            return Err(format!(
                "{}:{}: expected two tab-separated fields",
                path.display(),
                idx + 1
            ));
        }
        hashes.insert(PathBuf::from(fields[1]), fields[0].to_string());
    }
    Ok(hashes)
}

fn filtered_manifest(
    entries: Vec<ManifestEntry>,
    crate_filter: &Option<String>,
) -> Vec<ManifestEntry> {
    match crate_filter {
        Some(filter) => entries
            .into_iter()
            .filter(|entry| crate_matches(&entry.local_dir, filter))
            .collect(),
        None => entries,
    }
}

fn crate_matches(local_dir: &Path, filter: &str) -> bool {
    let normalized = filter.strip_prefix("wycheproof-ng-").unwrap_or(filter);
    let mut parts = local_dir.components();
    match (parts.next(), parts.next()) {
        (Some(first), Some(second)) if first.as_os_str() == "crates" => {
            second.as_os_str() == normalized || second.as_os_str() == filter
        }
        _ => false,
    }
}

fn entry_path(local_dir: &Path, file_name: &str) -> PathBuf {
    local_dir.join(file_name)
}

fn local_vector_files(
    repo_root: &Path,
    crate_filter: &Option<String>,
) -> Result<BTreeSet<PathBuf>> {
    let mut files = BTreeSet::new();
    let crates_dir = repo_root.join("crates");
    for crate_dir in read_dir_sorted(&crates_dir)? {
        let rel_crate_dir = crate_dir
            .strip_prefix(repo_root)
            .map_err(|e| format!("strip repo root from {}: {}", crate_dir.display(), e))?;
        if crate_filter
            .as_ref()
            .map(|filter| !crate_matches(rel_crate_dir, filter))
            .unwrap_or(false)
        {
            continue;
        }
        let data_dir = crate_dir.join("src/data");
        if !data_dir.is_dir() {
            continue;
        }
        for file in read_dir_sorted(&data_dir)? {
            if file.extension() == Some(OsStr::new("json")) {
                files.insert(
                    file.strip_prefix(repo_root)
                        .map_err(|e| format!("strip repo root from {}: {}", file.display(), e))?
                        .to_path_buf(),
                );
            }
        }
    }
    Ok(files)
}

fn json_names_in_dir(dir: &Path) -> Result<BTreeSet<String>> {
    let mut names = BTreeSet::new();
    for file in read_dir_sorted(dir)? {
        if file.extension() == Some(OsStr::new("json")) {
            let name = file
                .file_name()
                .and_then(OsStr::to_str)
                .ok_or_else(|| format!("non-utf8 file name {}", file.display()))?;
            names.insert(name.to_string());
        }
    }
    Ok(names)
}

fn compare_sets<T: Ord + std::fmt::Debug>(
    missing_left_label: &str,
    missing_right_label: &str,
    left: &BTreeSet<T>,
    right: &BTreeSet<T>,
    problems: &mut Vec<String>,
) {
    for item in left.difference(right) {
        problems.push(format!("{}: {:?}", missing_left_label, item));
    }
    for item in right.difference(left) {
        problems.push(format!("{}: {:?}", missing_right_label, item));
    }
}

fn read_dir_sorted(dir: &Path) -> Result<Vec<PathBuf>> {
    let mut entries = fs::read_dir(dir)
        .map_err(|e| format!("read dir {}: {}", dir.display(), e))?
        .map(|entry| entry.map(|entry| entry.path()))
        .collect::<io::Result<Vec<_>>>()
        .map_err(|e| format!("read dir {}: {}", dir.display(), e))?;
    entries.sort();
    Ok(entries)
}

fn first_dir(dir: &Path) -> Result<PathBuf> {
    read_dir_sorted(dir)?
        .into_iter()
        .find(|path| path.is_dir())
        .ok_or_else(|| format!("no extracted directory in {}", dir.display()))
}

fn command(program: &str, args: &[&str]) -> Result<()> {
    let status = Command::new(program)
        .args(args)
        .stdin(Stdio::null())
        .status()
        .map_err(|e| format!("run {}: {}", program, e))?;
    if status.success() {
        Ok(())
    } else {
        Err(format!("{} exited with {}", program, status))
    }
}

fn sha256_file(path: &Path) -> Result<String> {
    let path_str = path
        .to_str()
        .ok_or_else(|| format!("non-utf8 path {}", path.display()))?;
    if let Ok(hash) = sha256_with("sha256sum", &[path_str]) {
        return Ok(hash);
    }
    sha256_with("shasum", &["-a", "256", path_str])
}

fn sha256_with(program: &str, args: &[&str]) -> Result<String> {
    let output = Command::new(program)
        .args(args)
        .stdin(Stdio::null())
        .output()
        .map_err(|e| format!("run {}: {}", program, e))?;
    if !output.status.success() {
        return Err(format!("{} exited with {}", program, output.status));
    }
    let stdout = String::from_utf8(output.stdout)
        .map_err(|e| format!("{} output not utf8: {}", program, e))?;
    stdout
        .split_whitespace()
        .next()
        .map(|hash| hash.to_string())
        .ok_or_else(|| format!("{} produced no hash", program))
}
