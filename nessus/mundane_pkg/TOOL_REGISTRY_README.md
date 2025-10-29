# Tool Registry System

## Overview

The mundane tool now uses a centralized **Tool Registry** pattern that makes adding and removing tools trivial. Instead of editing multiple files with hardcoded tool definitions, you now only need to add a single entry to the registry.

## Architecture

### Components

1. **[tool_registry.py](tool_registry.py)** - Core registry infrastructure
   - `Tool` dataclass: Defines tool metadata and behavior
   - `TOOL_REGISTRY`: Global dictionary storing all registered tools
   - Helper functions: `get_tool()`, `get_available_tools()`, etc.

2. **[tool_definitions.py](tool_definitions.py)** - Tool registration
   - `register_all_tools()`: Registers all available tools
   - This is where you add new tools

3. **[tools.py](tools.py)** - Command builders
   - `build_nmap_cmd()`, `build_netexec_cmd()`, etc.
   - Pure functions that construct commands from parameters

4. **[mundane.py](../mundane.py)** - Workflow functions
   - `_build_nmap_workflow()`, `_build_netexec_workflow()`, etc.
   - Interactive prompts to gather parameters from users

## How It Works

```
User selects tool from menu
         ↓
choose_tool() reads from TOOL_REGISTRY (data-driven)
         ↓
Returns tool id (e.g., "nmap")
         ↓
Dispatch looks up Tool in registry
         ↓
Calls Tool.workflow_builder() to gather params
         ↓
Calls Tool.command_builder() to construct command
         ↓
Command is displayed for review/execution
```

## Adding a New Tool

### Example: Adding "gobuster"

**Before (required editing 4 files, ~150 lines of code):**
- Edit `tools.py`: Add menu print statement and tool_mapping entry
- Edit `tools.py`: Add `build_gobuster_cmd()` function
- Edit `mundane.py`: Add `_build_gobuster_workflow()` function
- Edit `mundane.py`: Add `elif tool_choice == "gobuster":` to dispatch

**After (edit 3 files, ~80 lines of code):**

#### Step 1: Write the command builder in `tools.py`

```python
# ========== Command Builders ==========

def build_gobuster_cmd(
    mode: str,
    url: str,
    wordlist: Path,
    output_file: Path,
    extensions: Optional[str] = None,
) -> list[str]:
    """
    Build gobuster command for directory/DNS brute forcing.

    Args:
        mode: Gobuster mode (dir, dns, vhost)
        url: Target URL or domain
        wordlist: Path to wordlist file
        output_file: Path to save results
        extensions: Optional file extensions (e.g., "php,html,txt")

    Returns:
        Command as list of strings for subprocess execution
    """
    cmd = ["gobuster", mode, "-u", url, "-w", str(wordlist), "-o", str(output_file)]

    if extensions and mode == "dir":
        cmd.extend(["-x", extensions])

    return cmd
```

#### Step 2: Write the workflow function in `mundane.py`

```python
def _build_gobuster_workflow(
    workdir: Path,
    results_dir: Path,
    oabase: Path,
) -> Optional[Tuple[Union[str, List[str]], Union[str, List[str]], str]]:
    """
    Build gobuster command through interactive prompts.

    Args:
        workdir: Working directory path
        results_dir: Results output directory
        oabase: Output file base path

    Returns:
        Tuple of (command, display_command, artifact_note) or None if interrupted
    """
    from mundane_pkg.tools import build_gobuster_cmd

    # Prompt for mode
    header("Gobuster Mode")
    print("[1] dir  - Directory/file brute forcing")
    print("[2] dns  - DNS subdomain brute forcing")
    print("[3] vhost - Virtual host brute forcing")

    try:
        mode_choice = input("Choose mode (default: dir): ").strip() or "1"
    except KeyboardInterrupt:
        return None

    mode_map = {"1": "dir", "2": "dns", "3": "vhost"}
    mode = mode_map.get(mode_choice, "dir")

    # Prompt for target URL/domain
    try:
        url = input("Target URL or domain: ").strip()
    except KeyboardInterrupt:
        return None

    if not url:
        warn("No target provided.")
        return None

    # Prompt for wordlist
    try:
        wordlist_input = input("Wordlist path (or Enter for /usr/share/wordlists/dirb/common.txt): ").strip()
    except KeyboardInterrupt:
        return None

    wordlist = Path(wordlist_input) if wordlist_input else Path("/usr/share/wordlists/dirb/common.txt")

    if not wordlist.exists():
        warn(f"Wordlist not found: {wordlist}")
        return None

    # Prompt for extensions (dir mode only)
    extensions = None
    if mode == "dir":
        try:
            extensions = input("File extensions (comma-separated, e.g., php,html,txt or Enter to skip): ").strip()
        except KeyboardInterrupt:
            return None

    # Build output path
    output_file = oabase.parent / f"{oabase.name}.gobuster.{mode}.txt"

    # Build command
    cmd = build_gobuster_cmd(mode, url, wordlist, output_file, extensions)

    return cmd, cmd, f"Gobuster output: {output_file}"
```

#### Step 3: Register the tool in `tool_definitions.py`

Add this to the `register_all_tools()` function:

```python
def register_all_tools() -> None:
    """Register all available tools in the tool registry."""
    import mundane as mundane_module
    from . import tools

    # ... existing tool registrations ...

    # ========================================================================
    # TOOL 5: gobuster
    # ========================================================================
    register_tool(
        Tool(
            id="gobuster",
            name="gobuster",
            description="Directory/DNS brute forcing",
            workflow_builder=mundane_module._build_gobuster_workflow,
            command_builder=tools.build_gobuster_cmd,
            requires=["gobuster"],
            menu_order=5,
            options={
                "modes": ["dir", "dns", "vhost"],
                "supports_extensions": True,
            },
        )
    )
```

**That's it!** The tool will automatically appear in the menu, no other changes needed.

## Tool Registration Reference

### Tool Dataclass Fields

```python
@dataclass
class Tool:
    id: str                    # Unique identifier (e.g., "nmap", "gobuster")
    name: str                  # Display name in menus
    description: str           # Short description shown to users
    workflow_builder: Callable # Function that gathers params interactively
    command_builder: Optional[Callable]  # Function that builds command
    requires: list[str]        # Required system binaries (for checking)
    menu_order: int            # Display position (lower = earlier)
    options: dict[str, Any]    # Tool-specific metadata (optional)
```

### Field Guidelines

- **id**: Use lowercase, no spaces. This is used in dispatch logic.
- **name**: Human-readable name, can include spaces/capitalization.
- **description**: Keep it concise (2-5 words). Shown as: `[1] nmap — Network mapper`
- **workflow_builder**: Reference to function in `mundane.py` that prompts user for parameters.
- **command_builder**: Reference to function in `tools.py` that builds the command. Can be `None` for special tools like metasploit.
- **requires**: List of binary names (e.g., `["nmap"]`, `["nxc", "netexec"]`). Used for availability checking.
- **menu_order**: Integer for display order. Lower numbers appear first (1, 2, 3...).
- **options**: Dictionary for tool-specific settings. Examples:
  - `{"supports_udp": True}` for nmap
  - `{"protocols": ["smb", "ftp", ...]}` for netexec
  - `{"supports_placeholders": True}` for custom commands

## Workflow Function Signature

Workflow functions can have any signature based on what they need from the tool execution context. Common parameters:

```python
def _build_mytool_workflow(
    tcp_ips: Path,           # TCP IP list file
    udp_ips: Path,           # UDP IP list file
    tcp_sockets: Path,       # TCP host:port list file
    ports_str: str,          # Comma-separated ports
    workdir: Path,           # Working directory
    results_dir: Path,       # Results output directory
    oabase: Path,            # Output file base path
    use_sudo: bool,          # Whether sudo is available
) -> Optional[Tuple[Union[str, List[str]], Union[str, List[str]], str]]:
    """
    Returns:
        Tuple of (command, display_command, artifact_note) or None if cancelled

        - command: Actual command to execute (str or list)
        - display_command: Command to show user (may be same as command)
        - artifact_note: Message about where output will be saved

        Return None to cancel/go back to menu.
    """
```

**Note:** Different workflows may return different tuple structures. For example:
- nmap/custom: `(cmd, display_cmd, artifact_note)`
- netexec: `(cmd, display_cmd, artifact_note, relay_path)`

You must update the dispatch logic in `mundane.py` if your workflow returns a different structure.

## Command Builder Function Signature

Command builders should be pure functions with clear type hints:

```python
def build_mytool_cmd(
    param1: str,
    param2: Path,
    param3: Optional[bool] = False,
) -> list[str]:
    """
    Build mytool command.

    Args:
        param1: Description of param1
        param2: Description of param2
        param3: Description of param3

    Returns:
        Command as list of strings for subprocess execution
    """
    cmd = ["mytool", "--flag", param1]

    if param2:
        cmd.extend(["--output", str(param2)])

    if param3:
        cmd.append("--verbose")

    return cmd
```

### Best Practices

1. **Return `list[str]`** for subprocess execution (preferred)
   - Example: `["nmap", "-A", "-p", "80,443", "target.com"]`
2. **Return `str`** only if shell features are needed (pipes, redirects, etc.)
   - Example: `"cat file.txt | grep pattern > output.txt"`
3. **Use type hints** for all parameters and return value
4. **Add docstrings** with clear parameter descriptions
5. **Convert Path objects to strings** when adding to command list

## Removing a Tool

Simply comment out or delete the `register_tool()` call in `tool_definitions.py`. The tool will immediately disappear from menus.

```python
# Temporarily disable nmap
# register_tool(Tool(id="nmap", ...))
```

## Advanced: Checking Tool Availability

The registry supports checking if required binaries are available:

```python
from mundane_pkg import get_available_tools

# Get all tools (regardless of binary availability)
all_tools = get_available_tools(check_requirements=False)

# Get only tools whose binaries are installed on system
available_tools = get_available_tools(check_requirements=True)
```

This is useful for showing users only tools they can actually run.

## Migration Notes

### Before Registry (Old Pattern)

- **4 files** to edit when adding a tool
- **Hardcoded** menu displays
- **Brittle** if/elif dispatch chains
- **No type safety** (string literals everywhere)
- **~150 lines** of code per tool

### After Registry (New Pattern)

- **3 files** to edit (1 registry entry + 2 functions)
- **Data-driven** menus (auto-update)
- **Registry-based** dispatch (cleaner)
- **Type-safe** Tool objects
- **~80 lines** of code per tool
- **47% reduction** in effort

## Future Enhancements

Possible improvements to consider:

1. **External Configuration**: Load tools from YAML/JSON files
2. **Plugin System**: Auto-discover tool modules in a plugins directory
3. **Unified Workflow Signature**: Normalize workflow function parameters
4. **Command Validation**: Pre-execution validation of commands
5. **Dry-Run Mode**: Test command building without execution
6. **Tool Dependencies**: Check for required Python packages, not just binaries
7. **Tool Categories**: Group tools (scanners, brute forcers, etc.)

## Troubleshooting

### "No tools available in registry"

The registry is empty. Check that:
1. `tool_definitions.py` is imported in `__init__.py`
2. `register_all_tools()` is called at module load
3. No exceptions during tool registration

### "Tool 'xyz' registered but not implemented in dispatch"

You registered a tool but didn't add handling in the dispatch section of `mundane.py` (around line 890). Each tool needs a corresponding `if/elif` block to call its workflow builder with the correct parameters.

### Import errors or circular dependencies

The registration happens in `tool_definitions.py` which imports `mundane` and `tools` at function call time (not module load time) to avoid circular imports. If you get import errors:
1. Check that imports are inside `register_all_tools()` function
2. Verify `tool_definitions` is imported last in `__init__.py`

## Questions?

For questions or issues with the tool registry system, please open an issue on the project repository.
