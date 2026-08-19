# CTF / lab exercise: filename boundary triage

## Challenge

Classify these strings without creating any files:

1. `report.vtt`
2. `notes.txt`
3. `../payload.mp4`
4. `nested/file.log`
5. `.hidden.md`

The policy permits one non-hidden filename with an extension from the explicit
allowlist. Paths, traversal components, hidden names, and unlisted extensions
must be rejected.

## Reproduce

```bash
python3 -m defensive_security_lab path \
  report.vtt notes.txt ../payload.mp4 nested/file.log .hidden.md
```

## Expected result

- Allowed: `report.vtt`, `notes.txt`
- Rejected: `../payload.mp4`, `nested/file.log`, `.hidden.md`

This is a safe local reasoning exercise, not an exploit against a real target.

