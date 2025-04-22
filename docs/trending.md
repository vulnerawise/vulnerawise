# Vulnerawise Trending Command Guide

The `trending` command displays the most trending CVEs based on computed scores.

## Usage
```sh
vulnerawise trending [flags]
```

## Flags
- `--limit` → Number of trending results to return (default: `10`)
- `--offset` → Pagination offset (default: `0`)
- `--format` → Output format (`table` or `json`)

## Example
```sh
vulnerawise trending --limit 5 --format json
```
