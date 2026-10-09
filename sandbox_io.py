"""Sandbox file upload via gzip+base64 (NFLBench pattern: text compresses ~85%, cutting the
shell-arg payload ~10x versus the SDK's base64 upload).

The sandbox /run endpoint rejects request bodies over ~4 MiB, so the base64 payload is sent
in chunks appended to a temp file, then decoded into a sibling temp file and moved into place.
Each call's exit code is checked; failures raise a short RuntimeError that never echoes the
payload."""

import base64
import gzip
import posixpath
import shlex
import uuid

UPLOAD_CHUNK_CHARS = 1_000_000


async def upload_text(sandbox, remote_path: str, content: str) -> None:
    if not content.endswith("\n"):
        content += "\n"
    gz = gzip.compress(content.encode("utf-8"))
    b64 = base64.b64encode(gz).decode("ascii")
    chunks = [b64[i:i + UPLOAD_CHUNK_CHARS] for i in range(0, len(b64), UPLOAD_CHUNK_CHARS)] or [""]

    tag = uuid.uuid4().hex
    dest = shlex.quote(remote_path)
    tmp_b64 = shlex.quote(f"/tmp/.upload-{tag}.b64")
    tmp_out = shlex.quote(f"{remote_path}.upload-{tag}")
    parent = shlex.quote(posixpath.dirname(remote_path) or ".")

    for i, chunk in enumerate(chunks):
        redirect = ">" if i == 0 else ">>"
        cmd = f"printf %s '{chunk}' {redirect} {tmp_b64}"
        if i == 0:
            cmd = f"mkdir -p {parent} && {cmd}"
        if i == len(chunks) - 1:
            cmd = (
                f"set -o pipefail; {cmd} && base64 -d < {tmp_b64} | gunzip > {tmp_out} && "
                f"mv -f {tmp_out} {dest}; rc=$?; rm -f {tmp_b64} {tmp_out}; exit $rc"
            )
        output, code = await sandbox.run(cmd)
        if code != 0:
            if i < len(chunks) - 1:
                await sandbox.run(f"rm -f {tmp_b64}")
            raise RuntimeError(
                f"upload to {remote_path} failed at chunk {i + 1}/{len(chunks)} (exit {code}): {output[-500:]}"
            )
