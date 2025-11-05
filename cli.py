#!/usr/bin/env python3
"""
Main CLI dispatcher for auxiliary tools.

Usage:
    auxiliary <tool> [args...]
    auxiliary --list
    auxiliary --help
"""
import sys

# Tool registry mapping command names to their modules and descriptions
TOOLS = {
    'find-dc': {
        'module': 'dns.find_domain_controllers',
        'description': 'Discover Windows Domain Controllers via SRV lookups'
    },
    'reverse-dns': {
        'module': 'dns.reverse_dns',
        'description': 'Perform reverse DNS lookups on IP lists'
    },
    'extract-ips': {
        'module': 'network.chaos_ip_extract',
        'description': 'Extract and sort valid IPv4 addresses from files'
    },
    'masscan': {
        'module': 'network.masscan_to_targets',
        'description': 'Parse masscan output to extract target IPs'
    },
    'gobuster': {
        'module': 'web.gobuster_to_eyewitness',
        'description': 'Convert Gobuster output to EyeWitness URLs'
    },
    'split-lines': {
        'module': 'files.split_lines',
        'description': 'Split files into fixed-line batches'
    },
    'split-creds': {
        'module': 'files.split_creds',
        'description': 'Split credential dumps into user/password files'
    },
    'iptables': {
        'module': 'firewall.apply_iptables_blocks',
        'description': 'Manage iptables OUTPUT DROP rules'
    }
}

def print_help():
    """Display help information about the CLI."""
    print("auxiliary - Ridgeback InfoSec security utilities")
    print()
    print("Usage:")
    print("  auxiliary <tool> [args...]")
    print("  auxiliary --list")
    print("  auxiliary --help")
    print()
    print("Available tools:")
    for name, info in sorted(TOOLS.items()):
        print(f"  {name:15s} - {info['description']}")
    print()
    print("Examples:")
    print("  auxiliary find-dc --domain example.corp")
    print("  auxiliary reverse-dns --input ips.txt --output hostnames.txt")
    print("  auxiliary extract-ips --input ~/chaos --output ~/order")
    print("  auxiliary masscan masscan_output --output targets")
    print("  auxiliary gobuster gobuster.txt http://example.com urls.txt")
    print("  auxiliary split-lines --input targets --lines 1000")
    print("  auxiliary split-creds --glob 'creds-*.txt' --dedupe-users")
    print("  auxiliary iptables --ranges-file ranges.txt --apply")
    print()
    print("For tool-specific help, run: auxiliary <tool> --help")

def print_tools():
    """List all available tools."""
    print("Available auxiliary tools:")
    for name, info in sorted(TOOLS.items()):
        print(f"  {name:15s} - {info['description']}")

def main():
    """Main entry point for the auxiliary CLI dispatcher."""
    if len(sys.argv) < 2 or sys.argv[1] in ['-h', '--help']:
        print_help()
        return 0

    if sys.argv[1] == '--list':
        print_tools()
        return 0

    tool_name = sys.argv[1]

    if tool_name not in TOOLS:
        print(f"Error: Unknown tool '{tool_name}'", file=sys.stderr)
        print(f"Run 'auxiliary --list' to see available tools.", file=sys.stderr)
        return 1

    # Import the tool module dynamically and call its main function
    tool_info = TOOLS[tool_name]
    module_name = tool_info['module']

    try:
        # Import the module dynamically
        parts = module_name.split('.')
        module = __import__(module_name, fromlist=[parts[-1]])

        # Call the tool's main function with remaining arguments
        return module.main(sys.argv[2:])
    except ImportError as e:
        print(f"Error: Failed to import tool module '{module_name}': {e}", file=sys.stderr)
        return 2
    except AttributeError:
        print(f"Error: Tool module '{module_name}' does not have a main() function", file=sys.stderr)
        return 3
    except Exception as e:
        print(f"Error: Tool execution failed: {e}", file=sys.stderr)
        import traceback
        traceback.print_exc()
        return 4

if __name__ == '__main__':
    sys.exit(main())
