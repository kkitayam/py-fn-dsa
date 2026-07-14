#!/usr/bin/env python3
"""Build and run upstream c-fn-dsa tests."""

import subprocess
import sys
from pathlib import Path


def run_command(cmd, cwd=None):
    """Run command and return exit code."""
    rendered = cmd if isinstance(cmd, str) else " ".join(cmd)
    print(f"Running: {rendered}")
    if isinstance(cmd, str):
        result = subprocess.run(cmd, cwd=cwd, shell=True)
    else:
        result = subprocess.run(cmd, cwd=cwd)
    return result.returncode


def find_msvc_setup_script():
    """Find vcvars setup script and arguments for x64 builds."""
    roots = [
        Path("C:/Program Files (x86)/Microsoft Visual Studio"),
        Path("C:/Program Files/Microsoft Visual Studio"),
    ]
    editions = ["BuildTools", "Community", "Professional", "Enterprise"]
    for root in roots:
        if not root.exists():
            continue
        for version_dir in sorted(root.glob("*"), reverse=True):
            for edition in editions:
                build_dir = (
                    version_dir
                    / edition
                    / "VC"
                    / "Auxiliary"
                    / "Build"
                )
                vcvars64 = build_dir / "vcvars64.bat"
                if vcvars64.exists():
                    return vcvars64, []
                vcvarsall = build_dir / "vcvarsall.bat"
                if vcvarsall.exists():
                    return vcvarsall, ["x64"]
    return None


def main():
    """Build and run upstream tests."""
    vendor_dir = Path(__file__).parent.parent / "vendor" / "c-fn-dsa"
    
    if not vendor_dir.exists():
        print(f"Error: vendor/c-fn-dsa not found at {vendor_dir}")
        return 1
    
    print(f"Building upstream tests in {vendor_dir}...")
    
    # Determine Makefile based on OS
    if sys.platform == "win32":
        makefile = "Makefile.win32"
        msvc_setup = find_msvc_setup_script()
        if msvc_setup is None:
            print("Error: vcvars setup script not found")
            return 1
        setup_script, setup_args = msvc_setup
        setup_args_str = " ".join(setup_args)
        make_cmd = f'call "{setup_script}" {setup_args_str} && nmake /f {makefile}'.strip()
    else:
        makefile = "Makefile"
        make_cmd = ["make"]
    
    # Build tests
    print(f"\nBuilding with {makefile}...")
    if sys.platform == "win32":
        exit_code = run_command(make_cmd, cwd=str(vendor_dir))
    else:
        exit_code = run_command(make_cmd + [makefile], cwd=str(vendor_dir))
    
    if exit_code != 0:
        print(f"Error building tests (exit code {exit_code})")
        return exit_code
    
    # Run tests
    test_program = "test_fndsa.exe" if sys.platform == "win32" else "test_fndsa"
    test_path = vendor_dir / test_program
    
    if not test_path.exists():
        print(f"Error: test program {test_path} not found")
        return 1
    
    print(f"\nRunning {test_program}...")
    exit_code = run_command([str(test_path)])
    
    return exit_code


if __name__ == "__main__":
    sys.exit(main())
