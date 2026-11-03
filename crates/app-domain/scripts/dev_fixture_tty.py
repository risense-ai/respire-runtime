"""Linux-only hidden-input driver for disposable synthetic CLI fixtures."""
import os
import selectors
import signal
import subprocess
import sys
import time


def run_hidden(argv, *, prompts, cwd, env, timeout):
    """Feed ordered prompts over a no-echo controlling TTY, never argv/logs."""
    if not sys.platform.startswith("linux"):
        raise RuntimeError("fixture_tty_requires_linux")
    # Native Windows profile smoke imports the legacy reporter for its crypto
    # helpers, but never invokes this Linux-only terminal driver.
    import fcntl
    import pty
    import termios
    if any(arg.split("=", 1)[0] in ("--pass", "--super", "--secret-key", "--new-super") for arg in argv):
        raise RuntimeError("fixture_secret_argument_forbidden")
    prompts = [(marker.encode(), answer.encode()) for marker, answer in prompts]
    if any(not marker or b"\n" in answer or b"\r" in answer for marker, answer in prompts):
        raise RuntimeError("fixture_invalid_prompt_input")
    master, slave = pty.openpty()
    child = None
    try:
        attrs = termios.tcgetattr(slave)
        attrs[3] &= ~(termios.ECHO | termios.ECHONL)
        termios.tcsetattr(slave, termios.TCSANOW, attrs)

        def terminal():
            os.setsid()
            fcntl.ioctl(0, termios.TIOCSCTTY, 0)

        child = subprocess.Popen(argv, stdin=slave, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            cwd=cwd, env=env, preexec_fn=terminal)
        os.close(slave)
        slave = None
        deadline = time.monotonic() + timeout
        output = {"stdout": bytearray(), "stderr": bytearray()}
        cursor = 0
        with selectors.DefaultSelector() as selector:
            selector.register(child.stdout, selectors.EVENT_READ, "stdout")
            selector.register(child.stderr, selectors.EVENT_READ, "stderr")
            while selector.get_map():
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    raise RuntimeError("fixture_tty_timeout")
                for key, _ in selector.select(min(remaining, 0.1)):
                    chunk = os.read(key.fileobj.fileno(), 65536)
                    if not chunk:
                        selector.unregister(key.fileobj)
                        continue
                    output[key.data].extend(chunk)
                    if sum(map(len, output.values())) > 4 * 1024 * 1024:
                        raise RuntimeError("fixture_tty_output_limit")
                if cursor < len(prompts):
                    marker, answer = prompts[cursor]
                    if marker in output["stdout"]:
                        # Input is refused if the child unexpectedly enables echo.
                        if termios.tcgetattr(master)[3] & (termios.ECHO | termios.ECHONL):
                            raise RuntimeError("fixture_tty_echo_enabled")
                        output["stdout"] = output["stdout"].replace(marker, b"", 1)
                        os.write(master, answer + b"\n")
                        cursor += 1
            child.wait(timeout=max(0.01, deadline - time.monotonic()))
        if child.returncode == 0 and cursor != len(prompts):
            raise RuntimeError("fixture_tty_missing_prompt")
        # Never return supplied secrets, including when a broken child echoes them.
        for name, value in output.items():
            for _, answer in prompts:
                if len(answer) > 1:
                    value = value.replace(answer, b"[redacted]")
            output[name] = bytes(value)
        return subprocess.CompletedProcess(argv, child.returncode, output["stdout"], output["stderr"])
    except subprocess.TimeoutExpired:
        raise RuntimeError("fixture_tty_timeout") from None
    finally:
        if child is not None:
            # Also stop descendants retaining stdout/stderr after the CLI exits.
            try:
                os.killpg(child.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
            child.wait()
            child.stdout.close()
            child.stderr.close()
        os.close(master)
        if slave is not None:
            os.close(slave)
