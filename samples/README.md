Synthetic, inert HTTP request shapes used only to test
`analysis/extract_php2shell.py`. They reproduce the *string shape* the
published PHP2Shell chain uses (session id in the POST body, an
upload-progress field, serialized-object markers in a multipart filename).

They contain no exploit: no leaked or hard-coded addresses, no valid
serialized object, no payload. Sending them at a patched or unpatched server
does nothing but create a session file.

`02-legit-upload-progress.http` is the false-positive baseline: a normal
client using session.upload_progress the way it was designed.
