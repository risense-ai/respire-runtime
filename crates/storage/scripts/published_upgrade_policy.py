"""Explicit historical gaps; a missing asset is never a general skip rule."""
ARM_TARGETS = frozenset({"aarch64-unknown-linux-gnu", "aarch64-unknown-linux-musl"})
ABSENT_ARM_RELEASES = frozenset({"v1.0.15", "v1.0.16", "v1.0.17-dev.12"})
ABSENT_WINDOWS_ARM_RELEASES = frozenset({"v1.0.15", "v1.0.16"})


def select_upgrade_sources(sources, target, profile):
    if profile == "full":
        return sources
    if profile != "critical":
        raise ValueError(f"unknown upgrade profile: {profile}")
    for tag in sorted(sources, key=lambda tag: tuple(map(int, tag[1:].split("."))), reverse=True):
        assets = [asset["name"] for asset in sources[tag]["assets"]]
        if platform_applicability(tag, target, assets) is None:
            return {tag: sources[tag]}
    if sources and target == "x86_64-apple-darwin":
        return {}
    raise ValueError(f"no applicable formal stable upgrade source: {target}")


def platform_applicability(tag, target, asset_names):
    extension = ".exe" if "windows" in target else ""
    required = {f"rsrs-{target}{extension}", f"rsrs-{target}-runtime.tar.gz", f"cli-build-{target}.json"}
    present = required.intersection(asset_names)
    if present == required:
        return None
    if target in ARM_TARGETS and tag in ABSENT_ARM_RELEASES and not present:
        return "Linux ARM64 was not distributed for this exact release"
    if target == "aarch64-pc-windows-msvc" and tag in ABSENT_WINDOWS_ARM_RELEASES and not present:
        return "Windows ARM64 was not distributed for this exact release"
    if target == "x86_64-apple-darwin" and tuple(map(int, tag.removeprefix("v").split("-")[0].split("."))) < (1, 0, 20) and not present:
        return "Intel macOS was not distributed before 1.0.20"
    raise ValueError(f"missing platform artifact: {tag} {target}; present={sorted(present)}")
