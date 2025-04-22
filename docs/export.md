# Vulnerawise Export Command Guide

The `export` command allows users to export vulnerability data in JSON or CSV format.

## Usage
```sh
vulnerawise export [flags]
```

## Flags
- `--output-file` → File to export all results into
- `--output-dir` → Directory to organize exported results by year
- `--cve` → Comma-separated list of CVE IDs to export
- `--batch-size` → Group records into batch files of this size (default: `0` for individual files)
- `--format` → Export format (`json` or `csv`; CSV only supported with --output-file)

## Example
```sh
vulnerawise export --output-file cve_data.json
```
