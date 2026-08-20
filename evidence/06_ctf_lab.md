# CTF / lab exercise: filename boundary triage

**Supports the CVP category "CTF / Lab / Research Environment": yes.**

## Challenge

Classify these strings without creating any files:

1. `report.vtt`
2. `notes.txt`
3. `../payload.mp4`
4. `%252e%252e%252fboot.txt`
5. `CON.txt`
6. `console.txt`
7. `file.txt:hidden`

The policy permits one non-hidden bare filename with an extension from the
explicit allowlist. Paths, traversal, encoded traversal, hidden names, reserved
device names, stream separators, and unlisted extensions must be rejected.

## Reproduce

```bash
python3 -m defensive_security_lab explain \
  report.vtt notes.txt ../payload.mp4 %252e%252e%252fboot.txt \
  CON.txt console.txt file.txt:hidden
```

## Expected result

| Input | Verdict | Reason |
|---|---|---|
| `report.vtt` | allowed | `policy_satisfied` |
| `notes.txt` | allowed | `policy_satisfied` |
| `../payload.mp4` | rejected | `path_separator` |
| `%252e%252e%252fboot.txt` | rejected | `percent_encoded` |
| `CON.txt` | rejected | `reserved_device_name` |
| `console.txt` | allowed | `policy_satisfied` |
| `file.txt:hidden` | rejected | `alternate_data_stream` |

The sixth row is the interesting one: `console.txt` begins with `con` but is an
ordinary filename, so a prefix-matching implementation would wrongly reject it.

A safe local reasoning exercise on strings. Nothing is written to disk and no
external system is contacted.
