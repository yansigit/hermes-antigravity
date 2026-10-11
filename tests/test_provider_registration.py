import sys

# Ensure Hermes agent is in sys.path dynamically
from pathlib import Path

hermes_agent_dir = Path.home() / ".hermes" / "hermes-agent"
if hermes_agent_dir.is_dir() and str(hermes_agent_dir) not in sys.path:
    sys.path.insert(0, str(hermes_agent_dir))
from providers import get_provider_profile  # noqa: E402


def test_antigravity_profile_registered():
    profile = get_provider_profile("antigravity")
    assert profile is not None
    assert profile.name == "antigravity"
    assert "google-antigravity" in profile.aliases
    assert "agy" in profile.aliases
    assert profile.supports_vision is True
    assert profile.default_aux_model == "gemini-3.8-flash"


def test_antigravity_create_client_hook():
    profile = get_provider_profile("antigravity")
    assert profile is not None
    client = profile.create_client()
    assert client is not None
    assert hasattr(client, "chat")
    assert hasattr(client.chat, "completions")
    assert hasattr(client.chat.completions, "create")

def test_antigravity_model_flow_hook():
    # The plugin owns a callable model flow for `hermes model` integration.
    import importlib.util
    from pathlib import Path
    init_path = Path(__file__).resolve().parent.parent / "__init__.py"
    spec = importlib.util.spec_from_file_location("_ag_init", init_path)
    assert spec is not None and spec.loader is not None
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    assert callable(getattr(mod, "_model_flow_antigravity", None))
    # Core registration is core-owned: only assert it when the core
    # exposes the flow registry (older cores had _PROVIDER_MODEL_FLOWS;
    # newer cores wire flows natively).
    try:
        import hermes_cli.main as _m
    except ImportError:
        return
    flows = getattr(_m, "_PROVIDER_MODEL_FLOWS", None)
    if flows is None:
        return
    assert "antigravity" in flows
    assert callable(flows["antigravity"])


def test_antigravity_skips_models_health_probe():
    # Google has no REST /models on this base URL (catalog is
    # fetchAvailableModels) — the profile must opt out of the probe.
    profile = get_provider_profile("antigravity")
    assert profile is not None
    assert profile.supports_health_check is False


def test_declared_env_vars_match_what_the_code_reads():
    """Catalog rule 5: declared capabilities must match reality.

    Every env var on the profile must be read by auth.py (no dead
    declarations like the old ANTIGRAVITY_API_KEY), and every
    ANTIGRAVITY_*/GOOGLE_OAUTH_TOKEN name the code reads must be declared
    (no silent reads like the old missing REFRESH_TOKEN/PROJECT_ID pair).
    """
    import re
    from pathlib import Path

    profile = get_provider_profile("antigravity")
    assert profile is not None
    declared = set(profile.env_vars)

    source = (Path(__file__).resolve().parent.parent / "auth.py").read_text()
    read = set(re.findall(r'os\.environ\.get\("([A-Z_]+)"', source))

    assert declared == read, (
        f"declared={sorted(declared)} read={sorted(read)}")


def test_client_imports_as_package_submodule():
    """client.py must import as a package submodule (antigravity.client).

    Hermes loads the plugin as a package, so client.py's relative imports
    (from .auth, from .models, from .quota) must resolve. A regression that
    turns a relative import into a bare one (from quota) raises
    ModuleNotFoundError inside the package branch, falls into the except
    ImportError branch, and that one fails too — breaking plugin load while
    the repo-root test suite still passes (absolute fallbacks resolve there).

    This imports client.py as a submodule of the real plugin package from its
    parent directory, so relative imports must genuinely resolve.
    """
    import importlib
    from pathlib import Path

    repo = Path(__file__).resolve().parent.parent
    package_name = repo.name  # 'antigravity'
    parent = str(repo.parent)
    added = parent not in sys.path
    if added:
        sys.path.insert(0, parent)
    # Drop any cached copy so we exercise a fresh package import.
    for name in list(sys.modules):
        if name == package_name or name.startswith(f"{package_name}."):
            del sys.modules[name]
    try:
        mod = importlib.import_module(f"{package_name}.client")
    except ModuleNotFoundError as exc:
        raise AssertionError(
            f"{package_name}.client failed to import as a package "
            f"(relative import broken?): {exc}") from exc
    finally:
        if added:
            sys.path.remove(parent)
    # The package branch must have provided these, not the except fallback.
    assert hasattr(mod, "TUNED_OPENER")
    assert hasattr(mod, "AntigravityClient")
