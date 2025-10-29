# Quick Start: Adding a New Tool to Mundane

This guide shows you how to add a new tool to mundane in **3 simple steps**.

## Before You Start

Make sure you understand:
- **Command Builder**: A function that constructs the command string/list
- **Workflow Builder**: A function that prompts the user for parameters
- **Tool Registry**: A central database of all available tools

## The 3-Step Process

### Step 1: Write Command Builder (in `mundane_pkg/tools.py`)

Add a function that takes parameters and returns a command:

```python
def build_mytool_cmd(
    param1: str,
    param2: Path,
    output_file: Path,
) -> list[str]:
    """
    Build mytool command.

    Args:
        param1: Description
        param2: Description
        output_file: Where to save results

    Returns:
        Command as list of strings
    """
    return ["mytool", "--option", param1, "--input", str(param2), "-o", str(output_file)]
```

### Step 2: Write Workflow Builder (in `mundane.py`)

Add a function that gathers user input and calls the command builder:

```python
def _build_mytool_workflow(
    workdir: Path,
    results_dir: Path,
    oabase: Path,
) -> Optional[Tuple[Union[str, List[str]], Union[str, List[str]], str]]:
    """
    Build mytool command through interactive prompts.

    Returns:
        Tuple of (command, display_command, artifact_note) or None if cancelled
    """
    from mundane_pkg.tools import build_mytool_cmd

    # Prompt for parameters
    try:
        param1 = input("Enter param1: ").strip()
        param2 = Path(input("Enter param2 path: ").strip())
    except KeyboardInterrupt:
        return None

    if not param1:
        warn("No param1 provided.")
        return None

    # Build output path
    output_file = oabase.parent / f"{oabase.name}.mytool.txt"

    # Build command
    cmd = build_mytool_cmd(param1, param2, output_file)

    return cmd, cmd, f"MyTool output: {output_file}"
```

### Step 3: Register in Tool Registry (in `mundane_pkg/tool_definitions.py`)

Add your tool to the `register_all_tools()` function:

```python
def register_all_tools() -> None:
    import mundane as mundane_module
    from . import tools

    # ... existing registrations ...

    # ========================================================================
    # TOOL 5: mytool  <-- Change this number
    # ========================================================================
    register_tool(
        Tool(
            id="mytool",                                    # Unique ID (lowercase)
            name="mytool",                                  # Display name
            description="Brief description",                # Shown in menu
            workflow_builder=mundane_module._build_mytool_workflow,  # Your workflow function
            command_builder=tools.build_mytool_cmd,        # Your command builder
            requires=["mytool"],                           # Required binaries
            menu_order=5,                                  # Menu position (1-based)
            options={},                                    # Optional metadata
        )
    )
```

### Step 4: Update Dispatch (in `mundane.py`, line ~890)

Add handling for your tool's workflow in the dispatch section:

```python
        elif tool_choice == "mytool":
            result = selected_tool.workflow_builder(
                workdir,
                results_dir,
                oabase,
            )
            if result is None:
                break
            cmd, display_cmd, artifact_note = result
```

**Note**: The parameters you pass depend on what your workflow function needs. Common options:
- `tcp_ips`, `udp_ips` - IP list files
- `tcp_sockets` - Host:port list file
- `ports_str` - Comma-separated ports
- `use_sudo` - Whether sudo is available
- `workdir`, `results_dir`, `oabase` - Paths for output

## That's It!

Your tool will now appear in the menu automatically. No need to edit menu display code or tool mappings.

## Complete Example: Adding "nikto"

### 1. Command Builder (`tools.py`)

```python
def build_nikto_cmd(
    target: str,
    port: int,
    ssl: bool,
    output_file: Path,
) -> list[str]:
    """Build nikto web scanner command."""
    cmd = ["nikto", "-h", target, "-p", str(port)]

    if ssl:
        cmd.append("-ssl")

    cmd.extend(["-o", str(output_file), "-Format", "txt"])

    return cmd
```

### 2. Workflow Builder (`mundane.py`)

```python
def _build_nikto_workflow(
    workdir: Path,
    oabase: Path,
) -> Optional[Tuple[List[str], List[str], str]]:
    """Build nikto command through prompts."""
    from mundane_pkg.tools import build_nikto_cmd

    try:
        target = input("Target host/IP: ").strip()
        port_input = input("Port (default: 80): ").strip() or "80"
        ssl = yesno("Use SSL?", default="n")
    except KeyboardInterrupt:
        return None

    if not target:
        warn("No target provided.")
        return None

    port = int(port_input)
    output_file = oabase.parent / f"{oabase.name}.nikto.txt"

    cmd = build_nikto_cmd(target, port, ssl, output_file)

    return cmd, cmd, f"Nikto output: {output_file}"
```

### 3. Register (`tool_definitions.py`)

```python
    register_tool(
        Tool(
            id="nikto",
            name="nikto",
            description="Web server scanner",
            workflow_builder=mundane_module._build_nikto_workflow,
            command_builder=tools.build_nikto_cmd,
            requires=["nikto"],
            menu_order=5,
        )
    )
```

### 4. Dispatch (`mundane.py`)

```python
        elif tool_choice == "nikto":
            result = selected_tool.workflow_builder(workdir, oabase)
            if result is None:
                break
            cmd, display_cmd, artifact_note = result
```

## Tips

- **Keep command builders pure** - no user input, just parameter transformation
- **Keep workflows interactive** - all prompts and validation here
- **Use type hints** - makes debugging easier
- **Handle KeyboardInterrupt** - return `None` to cancel gracefully
- **Validate input** - check for empty strings, missing files, etc.
- **Test incrementally** - run mundane after each step to catch errors early

## Need More Help?

See [TOOL_REGISTRY_README.md](mundane_pkg/TOOL_REGISTRY_README.md) for detailed documentation.
