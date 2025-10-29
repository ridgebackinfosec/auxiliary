# Unified Workflow Pattern Guide

## Overview

Mundane now uses a **Unified Workflow Pattern** that standardizes how tool workflows receive parameters and return results. This eliminates tool-specific parameter lists and return value unpacking in dispatch logic.

## Key Benefits

✅ **Single signature for all workflows** - No more scattered parameter lists
✅ **Type-safe contexts** - ToolContext dataclass with all fields
✅ **Clean dispatch code** - Build context once, use everywhere
✅ **Easy to extend** - Add context fields without touching all workflows
✅ **Self-documenting** - ToolContext shows all available fields

## Architecture

### Before (Tool-Specific Parameters)

```python
# Dispatch had different parameter lists per tool
if tool_choice == "nmap":
    result = workflow(tcp_ips, udp_ips, ports_str, use_sudo, oabase)
elif tool_choice == "netexec":
    result = workflow(tcp_ips, oabase)  # Different params!
elif tool_choice == "custom":
    result = workflow(tcp_ips, udp_ips, tcp_sockets, ports_str,
                     workdir, results_dir, oabase)  # Even more!
```

**Problems:**
- Each tool needs custom dispatch code
- Adding parameters requires touching all workflows
- No type safety
- Hard to refactor

### After (Unified Context)

```python
# Build context once
ctx = ToolContext(
    tcp_ips=tcp_ips,
    udp_ips=udp_ips,
    tcp_sockets=tcp_sockets,
    ports_str=ports_str,
    use_sudo=use_sudo,
    workdir=workdir,
    results_dir=results_dir,
    oabase=oabase,
    scan_dir=scan_dir,
    sev_dir=sev_dir,
    plugin_url=plugin_url,
    chosen_file=chosen,
)

# Same call for ALL tools!
result = selected_tool.workflow_builder(ctx)
```

**Benefits:**
- Single, clean dispatch code
- Add context fields in one place
- Type-safe with dataclasses
- Easy to refactor

## Core Types

### ToolContext

Standardized parameter object passed to all workflows.

**File:** `mundane_pkg/tool_context.py`

```python
@dataclass
class ToolContext:
    """Unified context for all tool workflows."""

    # Input files
    tcp_ips: Path        # TCP IP list
    udp_ips: Path        # UDP IP list
    tcp_sockets: Path    # host:port list

    # Configuration
    ports_str: str       # Comma-separated ports
    use_sudo: bool       # Sudo availability

    # Output paths
    workdir: Path        # Working directory
    results_dir: Path    # Results directory
    oabase: Path         # Output base path
    scan_dir: Path       # Scan directory
    sev_dir: Path        # Severity directory

    # Optional metadata
    plugin_url: Optional[str] = None    # Nessus plugin URL
    chosen_file: Optional[Path] = None  # Selected file
```

**Usage in workflows:**
```python
def _build_mytool_workflow(ctx: ToolContext) -> Optional[CommandResult]:
    # Access what you need
    ips = ctx.tcp_ips
    ports = ctx.ports_str
    output = ctx.oabase

    # ... build command ...
```

### CommandResult

Standardized return type from all workflows.

```python
@dataclass
class CommandResult:
    """Unified return type from workflows."""

    command: Union[str, List[str]]          # Actual command
    display_command: Union[str, List[str]]  # Shown to user
    artifact_note: str                      # Output location note
    relay_path: Optional[Path] = None       # Optional relay file
```

**Usage in workflows:**
```python
return CommandResult(
    command=cmd,
    display_command=cmd,
    artifact_note=f"Output: {output_file}",
    relay_path=None,  # Optional
)
```

## Adding a New Tool

### Step 1: Write Command Builder (`mundane_pkg/tools.py`)

```python
def build_mytool_cmd(param1: str, param2: Path, output: Path) -> list[str]:
    """Build mytool command."""
    return ["mytool", "--flag", param1, "-i", str(param2), "-o", str(output)]
```

### Step 2: Write Workflow (`mundane.py`)

**Use ToolContext parameter and return CommandResult:**

```python
def _build_mytool_workflow(ctx: ToolContext) -> Optional[CommandResult]:
    """
    Build mytool command through interactive prompts.

    Args:
        ctx: Unified tool context containing all parameters

    Returns:
        CommandResult with command details, or None if cancelled
    """
    from mundane_pkg.tool_context import CommandResult
    from mundane_pkg.tools import build_mytool_cmd

    # Gather user input
    try:
        param1 = input("Enter param1: ").strip()
        param2 = Path(input("File path: ").strip())
    except KeyboardInterrupt:
        return None  # User cancelled

    # Validation
    if not param1:
        warn("No param1 provided.")
        return None

    # Use context fields
    output = ctx.oabase.parent / f"{ctx.oabase.name}.mytool.txt"

    # Build command
    cmd = build_mytool_cmd(param1, param2, output)

    # Return unified result
    return CommandResult(
        command=cmd,
        display_command=cmd,
        artifact_note=f"MyTool output: {output}",
    )
```

### Step 3: Register Tool (`mundane_pkg/tool_definitions.py`)

```python
register_tool(
    Tool(
        id="mytool",
        name="mytool",
        description="Brief description",
        workflow_builder=mundane_module._build_mytool_workflow,
        command_builder=tools.build_mytool_cmd,
        requires=["mytool"],
        menu_order=5,
    )
)
```

**That's it!** The unified dispatch handles everything automatically.

## Dispatch Logic (Automatic)

The dispatch code in `mundane.py` is now completely generic:

```python
# Build context once (all tools use this)
ctx = ToolContext(
    tcp_ips=tcp_ips,
    udp_ips=udp_ips,
    # ... all fields ...
)

# Call workflow (same for all tools!)
result = selected_tool.workflow_builder(ctx)

# Handle cancellation
if result is None:
    if tool_choice in ("nmap", "custom"):
        break
    else:
        continue

# Extract results (same for all tools!)
cmd = result.command
display_cmd = result.display_command
artifact_note = result.artifact_note
nxc_relay_path = result.relay_path
```

**No tool-specific code needed!**

## Migration Guide (Old → New)

### Old Workflow Style

```python
def _build_mytool_workflow(
    tcp_ips: Path,
    udp_ips: Path,
    ports_str: str,
    output: Path,
) -> Optional[Tuple[List[str], List[str], str]]:
    # ... logic ...
    return cmd, cmd, f"Output: {output}"
```

### New Workflow Style

```python
def _build_mytool_workflow(ctx: ToolContext) -> Optional[CommandResult]:
    from mundane_pkg.tool_context import CommandResult

    # Access params via ctx
    tcp_ips = ctx.tcp_ips
    udp_ips = ctx.udp_ips
    ports_str = ctx.ports_str
    output = ctx.oabase

    # ... same logic ...

    return CommandResult(
        command=cmd,
        display_command=cmd,
        artifact_note=f"Output: {output}",
    )
```

### Changes Required

1. **Signature:** `ctx: ToolContext` instead of individual params
2. **Return type:** `Optional[CommandResult]` instead of tuple
3. **Import:** Add `from mundane_pkg.tool_context import CommandResult`
4. **Return statement:** `return CommandResult(...)` instead of tuple
5. **Parameter access:** `ctx.field_name` instead of `field_name`

## Best Practices

### 1. Use Only What You Need

```python
def _build_simple_tool_workflow(ctx: ToolContext) -> Optional[CommandResult]:
    # Only access fields you actually use
    output = ctx.oabase

    # Don't need to use all ctx fields!
```

### 2. Handle Cancellation

```python
try:
    user_input = input("Enter value: ")
except KeyboardInterrupt:
    return None  # Signals user cancelled
```

### 3. Validate Input

```python
if not user_input:
    warn("No input provided.")
    return None  # Cancellation
```

### 4. Use Type Hints

```python
def _build_mytool_workflow(ctx: ToolContext) -> Optional[CommandResult]:
    # Type hints enable IDE autocomplete and type checking
```

## Common Patterns

### Pattern 1: Simple Command

```python
def _build_simple_workflow(ctx: ToolContext) -> Optional[CommandResult]:
    from mundane_pkg.tool_context import CommandResult

    output = ctx.oabase.parent / f"{ctx.oabase.name}.simple.txt"
    cmd = ["simple-tool", "-i", str(ctx.tcp_ips), "-o", str(output)]

    return CommandResult(
        command=cmd,
        display_command=cmd,
        artifact_note=f"Output: {output}",
    )
```

### Pattern 2: With User Prompts

```python
def _build_interactive_workflow(ctx: ToolContext) -> Optional[CommandResult]:
    from mundane_pkg.tool_context import CommandResult

    try:
        mode = input("Mode (a/b/c): ").strip() or "a"
        target = input("Target: ").strip()
    except KeyboardInterrupt:
        return None

    if not target:
        warn("No target provided.")
        return None

    output = ctx.oabase.parent / f"{ctx.oabase.name}.interactive.txt"
    cmd = ["interactive-tool", mode, target, str(output)]

    return CommandResult(
        command=cmd,
        display_command=cmd,
        artifact_note=f"Output: {output}",
    )
```

### Pattern 3: With Relay Files (like netexec)

```python
def _build_relay_workflow(ctx: ToolContext) -> Optional[CommandResult]:
    from mundane_pkg.tool_context import CommandResult

    output = ctx.oabase.parent / f"{ctx.oabase.name}.main.txt"
    relay = ctx.oabase.parent / f"{ctx.oabase.name}.relay.txt"

    cmd = ["relay-tool", str(ctx.tcp_ips), str(output), str(relay)]

    return CommandResult(
        command=cmd,
        display_command=cmd,
        artifact_note=f"Output: {output}",
        relay_path=relay,  # Will be shown in artifacts section
    )
```

## Troubleshooting

### TypeError: missing required positional argument

**Problem:** Old workflow signature used, but dispatch passes ToolContext.

**Solution:** Update workflow signature to accept `ctx: ToolContext`.

### AttributeError: 'ToolContext' object has no attribute 'X'

**Problem:** Trying to access field that doesn't exist in ToolContext.

**Solution:** Check `tool_context.py` for available fields, or add new field if needed.

### Return value unpacking error

**Problem:** Workflow returns tuple instead of CommandResult.

**Solution:** Return `CommandResult(...)` instead of tuple.

## See Also

- [tool_context.py](mundane_pkg/tool_context.py) - ToolContext and CommandResult definitions
- [TOOL_REGISTRY_README.md](mundane_pkg/TOOL_REGISTRY_README.md) - Tool registry architecture
- [ADDING_TOOLS_QUICKSTART.md](ADDING_TOOLS_QUICKSTART.md) - Quick reference for adding tools
