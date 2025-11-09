#!/usr/bin/env python3
"""
TOCTOU Test Case Generator - JSON to Curl Config Format
Reads TOCTOU.json and generates organized test cases using curl's config file format.
"""

import argparse
import json
import os
import sys
from typing import Dict, List, Any


class CurlConfigGenerator:
    """Generates curl config files from request components."""
    
    @staticmethod
    def generate_config(components: Dict[str, Any], http_version: str = None, 
                       chunked: bool = False, timeout: float = None) -> str:
        """Generate a curl config block for a single request."""
        lines = []
        
        # Add URL
        lines.append(f'url = "{components["url"]}"')
        
        # Add request method
        if components.get("request"):
            lines.append(f'request = {components["request"]}')
        
        # Add HTTP version
        if http_version:
            if http_version == "1.0":
                lines.append("http1.0")
            elif http_version == "1.1":
                lines.append("http1.1")
            elif http_version == "2":
                lines.append("http2")
        
        # Add timeout
        if timeout:
            lines.append(f"max-time = {timeout}")
        
        # Add chunked encoding header
        if chunked:
            lines.append('header = "Transfer-Encoding: chunked"')
        
        # Add headers
        if components.get("headers"):
            for header in components["headers"]:
                lines.append(f'header = "{header}"')
        
        # Add cookies
        if components.get("cookies"):
            cookie_string = "; ".join(components["cookies"])
            lines.append(f'cookie = "{cookie_string}"')
        
        # Add data
        if components.get("data"):
            # Escape quotes in data
            data = components["data"].replace('"', '\\"')
            lines.append(f'data = "{data}"')
        
        return "\n".join(lines)
    
    @staticmethod
    def create_parallel_config(config1: str, config2: str) -> str:
        """Create a parallel config with two requests using 'next' separator."""
        return f"{config1}\n\nnext\n\n{config2}\n\n# Both requests execute in parallel\nparallel"
    
    @staticmethod
    def create_sequential_config(config1: str, config2: str, delay_ms: int = 0) -> str:
        """Create a sequential config with delay between requests."""
        result = config1
        
        if delay_ms > 0:
            result += f"\n\n# Wait {delay_ms}ms before next request"
        
        result += f"\n\nnext\n\n{config2}"
        
        return result


class TOCTOUTestOrganizer:
    """Organizes TOCTOU test cases into proper directory structure."""
    
    def __init__(self, json_data: Dict[str, Any], output_dir: str = "./toctou_tests"):
        self.json_data = json_data
        self.output_dir = output_dir
        self.requests = json_data.get("requests", [])
        
    def create_directory_structure(self, idx: int) -> Dict[str, str]:
        """Create directory structure for a given index and return paths."""
        base_path = os.path.join(self.output_dir, f"idx_{idx}")
        
        paths = {
            "idempotence_parallel": os.path.join(base_path, "Idempotence", "Parallel"),
            "idempotence_sequential": os.path.join(base_path, "Idempotence", "Sequential"),
            "atomicity_parallel": os.path.join(base_path, "Atomicity", "Parallel"),
            "atomicity_sequential": os.path.join(base_path, "Atomicity", "Sequential"),
            "conservation_parallel": os.path.join(base_path, "Conservation", "Parallel"),
            "conservation_sequential": os.path.join(base_path, "Conservation", "Sequential"),
        }
        
        # Create all directories
        for path in paths.values():
            os.makedirs(path, exist_ok=True)
        
        return paths
    
    def generate_all_tests(self):
        """Generate all test cases for all requests in the JSON."""
        if not self.requests:
            print("No requests found in JSON file", file=sys.stderr)
            return
        
        for request in self.requests:
            idx = request.get("index")
            if not idx:
                continue
            
            print(f"\nProcessing request index {idx}...")
            components = request.get("components", {})
            
            if not components:
                print(f"  Warning: No components found for index {idx}")
                continue
            
            # Create directory structure
            paths = self.create_directory_structure(idx)
            
            # Generate test cases
            self._generate_idempotence_tests(idx, components, paths)
            self._generate_atomicity_tests(idx, components, paths)
            
            print(f"  ✓ Generated all test cases for index {idx}")
    
    def _generate_idempotence_tests(self, idx: int, components: Dict, paths: Dict):
        """Generate idempotence test cases (no timeout, no chunked, basic delays)."""
        config_gen = CurlConfigGenerator()
        
        # Test 1: Basic Parallel
        config1 = config_gen.generate_config(components)
        config2 = config_gen.generate_config(components)
        parallel_config = config_gen.create_parallel_config(config1, config2)
        self._write_config(paths["idempotence_parallel"], "config1.txt", parallel_config, 
                          "Basic parallel execution")
        
        # Test 2: Basic Sequential with 10ms delay
        sequential_config = config_gen.create_sequential_config(config1, config2, delay_ms=10)
        self._write_config(paths["idempotence_sequential"], "config1.txt", sequential_config,
                          "Sequential with 10ms delay (Note: delay must be handled externally)")
        
        # Test 3-5: HTTP version variants - Parallel
        http_versions = ["1.0", "1.1", "2"]
        for i, version in enumerate(http_versions, start=2):
            config1_v = config_gen.generate_config(components, http_version=version)
            config2_v = config_gen.generate_config(components, http_version=version)
            parallel_v = config_gen.create_parallel_config(config1_v, config2_v)
            self._write_config(paths["idempotence_parallel"], f"config{i}.txt", parallel_v,
                             f"Parallel execution with HTTP/{version}")
        
        # Test 6-8: HTTP version variants - Sequential
        for i, version in enumerate(http_versions, start=2):
            config1_v = config_gen.generate_config(components, http_version=version)
            config2_v = config_gen.generate_config(components, http_version=version)
            sequential_v = config_gen.create_sequential_config(config1_v, config2_v, delay_ms=10)
            self._write_config(paths["idempotence_sequential"], f"config{i}.txt", sequential_v,
                             f"Sequential with 10ms delay, HTTP/{version}")
    
    def _generate_atomicity_tests(self, idx: int, components: Dict, paths: Dict):
        """Generate atomicity test cases (with timeout or chunked)."""
        config_gen = CurlConfigGenerator()
        http_versions = ["1.0", "1.1", "2"]
        
        # ===== PARALLEL TESTS =====
        config_num = 1
        
        # Test 1: Parallel with timeout on first request
        config1 = config_gen.generate_config(components, timeout=0.5)
        config2 = config_gen.generate_config(components)
        parallel_timeout = config_gen.create_parallel_config(config1, config2)
        self._write_config(paths["atomicity_parallel"], f"config{config_num}.txt", 
                          parallel_timeout, "Parallel with timeout (0.5s) on first request")
        config_num += 1
        
        # Test 2: Parallel with chunked encoding
        config1_chunk = config_gen.generate_config(components, chunked=True)
        config2_chunk = config_gen.generate_config(components, chunked=True)
        parallel_chunk = config_gen.create_parallel_config(config1_chunk, config2_chunk)
        self._write_config(paths["atomicity_parallel"], f"config{config_num}.txt",
                          parallel_chunk, "Parallel with chunked encoding")
        config_num += 1
        
        # Test 3: Parallel with timeout + chunked
        config1_both = config_gen.generate_config(components, timeout=0.5, chunked=True)
        config2_both = config_gen.generate_config(components, chunked=True)
        parallel_both = config_gen.create_parallel_config(config1_both, config2_both)
        self._write_config(paths["atomicity_parallel"], f"config{config_num}.txt",
                          parallel_both, "Parallel with timeout and chunked encoding")
        config_num += 1
        
        # Test 4-6: Parallel with HTTP versions + timeout
        for version in http_versions:
            config1_v = config_gen.generate_config(components, http_version=version, timeout=0.5)
            config2_v = config_gen.generate_config(components, http_version=version)
            parallel_v = config_gen.create_parallel_config(config1_v, config2_v)
            self._write_config(paths["atomicity_parallel"], f"config{config_num}.txt",
                             parallel_v, f"Parallel with timeout, HTTP/{version}")
            config_num += 1
        
        # Test 7-9: Parallel with HTTP versions + chunked
        for version in http_versions:
            config1_v = config_gen.generate_config(components, http_version=version, chunked=True)
            config2_v = config_gen.generate_config(components, http_version=version, chunked=True)
            parallel_v = config_gen.create_parallel_config(config1_v, config2_v)
            self._write_config(paths["atomicity_parallel"], f"config{config_num}.txt",
                             parallel_v, f"Parallel with chunked, HTTP/{version}")
            config_num += 1
        
        # Test 10-12: Parallel with HTTP versions + timeout + chunked
        for version in http_versions:
            config1_v = config_gen.generate_config(components, http_version=version, timeout=0.5, chunked=True)
            config2_v = config_gen.generate_config(components, http_version=version, chunked=True)
            parallel_v = config_gen.create_parallel_config(config1_v, config2_v)
            self._write_config(paths["atomicity_parallel"], f"config{config_num}.txt",
                             parallel_v, f"Parallel with timeout and chunked, HTTP/{version}")
            config_num += 1
        
        # ===== SEQUENTIAL TESTS =====
        config_num = 1
        
        # Test 1: Sequential with timeout before second request
        config1 = config_gen.generate_config(components, timeout=0.1)
        config2 = config_gen.generate_config(components)
        sequential_timeout_before = config_gen.create_sequential_config(config1, config2)
        self._write_config(paths["atomicity_sequential"], f"config{config_num}.txt",
                          sequential_timeout_before, 
                          "Sequential with timeout (0.1s) completing before second request")
        config_num += 1
        
        # Test 2: Sequential with timeout during second request
        config1 = config_gen.generate_config(components, timeout=0.2)
        config2 = config_gen.generate_config(components)
        sequential_timeout_during = config_gen.create_sequential_config(config1, config2)
        self._write_config(paths["atomicity_sequential"], f"config{config_num}.txt",
                          sequential_timeout_during,
                          "Sequential with timeout (0.2s) - timing requires external script")
        config_num += 1
        
        # Test 3: Sequential with chunked encoding
        config1_chunk = config_gen.generate_config(components, chunked=True)
        config2_chunk = config_gen.generate_config(components, chunked=True)
        sequential_chunk = config_gen.create_sequential_config(config1_chunk, config2_chunk, delay_ms=10)
        self._write_config(paths["atomicity_sequential"], f"config{config_num}.txt",
                          sequential_chunk, "Sequential with chunked encoding and 10ms delay")
        config_num += 1
        
        # Test 4: Sequential with timeout + chunked (before second request)
        config1_both = config_gen.generate_config(components, timeout=0.1, chunked=True)
        config2_both = config_gen.generate_config(components, chunked=True)
        sequential_both_before = config_gen.create_sequential_config(config1_both, config2_both)
        self._write_config(paths["atomicity_sequential"], f"config{config_num}.txt",
                          sequential_both_before, "Sequential with timeout and chunked (timeout before)")
        config_num += 1
        
        # Test 5: Sequential with timeout + chunked (during second request)
        config1_both = config_gen.generate_config(components, timeout=0.2, chunked=True)
        config2_both = config_gen.generate_config(components, chunked=True)
        sequential_both_during = config_gen.create_sequential_config(config1_both, config2_both)
        self._write_config(paths["atomicity_sequential"], f"config{config_num}.txt",
                          sequential_both_during, "Sequential with timeout and chunked (timeout during)")
        config_num += 1
        
        # Test 6-8: Sequential with HTTP versions + timeout (before)
        for version in http_versions:
            config1_v = config_gen.generate_config(components, http_version=version, timeout=0.1)
            config2_v = config_gen.generate_config(components, http_version=version)
            sequential_v = config_gen.create_sequential_config(config1_v, config2_v)
            self._write_config(paths["atomicity_sequential"], f"config{config_num}.txt",
                             sequential_v, f"Sequential with timeout before, HTTP/{version}")
            config_num += 1
        
        # Test 9-11: Sequential with HTTP versions + timeout (during)
        for version in http_versions:
            config1_v = config_gen.generate_config(components, http_version=version, timeout=0.2)
            config2_v = config_gen.generate_config(components, http_version=version)
            sequential_v = config_gen.create_sequential_config(config1_v, config2_v)
            self._write_config(paths["atomicity_sequential"], f"config{config_num}.txt",
                             sequential_v, f"Sequential with timeout during, HTTP/{version}")
            config_num += 1
        
        # Test 12-14: Sequential with HTTP versions + chunked
        for version in http_versions:
            config1_v = config_gen.generate_config(components, http_version=version, chunked=True)
            config2_v = config_gen.generate_config(components, http_version=version, chunked=True)
            sequential_v = config_gen.create_sequential_config(config1_v, config2_v, delay_ms=10)
            self._write_config(paths["atomicity_sequential"], f"config{config_num}.txt",
                             sequential_v, f"Sequential with chunked, HTTP/{version}")
            config_num += 1
        
        # Test 15-17: Sequential with HTTP versions + timeout + chunked (before)
        for version in http_versions:
            config1_v = config_gen.generate_config(components, http_version=version, timeout=0.1, chunked=True)
            config2_v = config_gen.generate_config(components, http_version=version, chunked=True)
            sequential_v = config_gen.create_sequential_config(config1_v, config2_v)
            self._write_config(paths["atomicity_sequential"], f"config{config_num}.txt",
                             sequential_v, f"Sequential with timeout+chunked before, HTTP/{version}")
            config_num += 1
        
        # Test 18-20: Sequential with HTTP versions + timeout + chunked (during)
        for version in http_versions:
            config1_v = config_gen.generate_config(components, http_version=version, timeout=0.2, chunked=True)
            config2_v = config_gen.generate_config(components, http_version=version, chunked=True)
            sequential_v = config_gen.create_sequential_config(config1_v, config2_v)
            self._write_config(paths["atomicity_sequential"], f"config{config_num}.txt",
                             sequential_v, f"Sequential with timeout+chunked during, HTTP/{version}")
            config_num += 1
    
    def _write_config(self, directory: str, filename: str, content: str, description: str):
        """Write a config file with a comment header."""
        filepath = os.path.join(directory, filename)
        
        header = f"""# TOCTOU Test Case Configuration
# Description: {description}
# Generated for curl --config usage
#
# Usage: curl --config {filename}
#
# Note: For sequential tests with delays, you may need external scripting
# to enforce timing between requests.

"""
        
        full_content = header + content
        
        with open(filepath, 'w') as f:
            f.write(full_content)
        
        print(f"    Created: {filepath}")
    
    def create_master_readme(self):
        """Create a README explaining the structure and usage."""
        readme_path = os.path.join(self.output_dir, "README.md")
        
        content = """# TOCTOU Test Cases

## Directory Structure

```
toctou_tests/
├── idx_N/                    # One folder per request index
│   ├── Idempotence/         # Tests without timeouts/chunked
│   │   ├── Parallel/        # Parallel execution tests
│   │   │   ├── config1.txt  # Basic parallel
│   │   │   ├── config2.txt  # HTTP/1.0 variant
│   │   │   ├── config3.txt  # HTTP/1.1 variant
│   │   │   └── config4.txt  # HTTP/2 variant
│   │   └── Sequential/      # Sequential execution tests
│   │       ├── config1.txt  # Basic sequential (10ms)
│   │       ├── config2.txt  # HTTP/1.0 variant
│   │       ├── config3.txt  # HTTP/1.1 variant
│   │       └── config4.txt  # HTTP/2 variant
│   ├── Atomicity/           # Tests with timeouts/chunked
│   │   ├── Parallel/        # Various parallel timeout/chunked tests
│   │   └── Sequential/      # Various sequential timeout/chunked tests
│   └── Conservation/        # TBD
│       ├── Parallel/
│       └── Sequential/
```

## Test Categories

### Idempotence
Tests basic race conditions without artificial timing manipulation:
- Plain parallel execution
- Basic sequential with minimal delay (10ms)
- HTTP version variants (1.0, 1.1, 2)

### Atomicity
Tests that probe atomic operations and transaction boundaries:
- Requests with timeouts
- Requests with chunked transfer encoding
- Combinations of above with HTTP version variants

### Conservation
Reserved for future test cases (TBD)

## Usage

### Running a single test:
```bash
curl --config idx_1/Idempotence/Parallel/config1.txt
```

### Running all tests in a category:
```bash
for config in idx_1/Idempotence/Parallel/*.txt; do
    echo "Running $config"
    curl --config "$config"
done
```

### With output files:
```bash
# Edit config file to add output directive, or redirect:
curl --config config1.txt > response1.json 2> error1.log
```

## Important Notes

### Sequential Tests with Delays
Curl's config format doesn't natively support delays between sequential requests.
For tests requiring specific timing (e.g., 10ms delay), you need external scripting:

```bash
curl --config request1.txt
sleep 0.01
curl --config request2.txt
```

### Timeout Tests
Tests with `max-time` will timeout if the server doesn't respond quickly enough.
This is intentional for TOCTOU testing.

### Parallel Execution
Configs with the `parallel` directive will execute all requests simultaneously.
This is curl's native parallel feature.

### HTTP Version Support
Ensure your curl supports HTTP/2:
```bash
curl --version | grep HTTP2
```

## Analyzing Results

Look for:
1. **Race conditions**: Different responses for identical parallel requests
2. **State inconsistencies**: Sequential requests showing unexpected state changes
3. **Timeout behavior**: How system handles incomplete requests
4. **Protocol differences**: Behavior variations across HTTP versions

## Test Execution Tips

1. **Run multiple times**: Race conditions are probabilistic
2. **Monitor server logs**: Check for concurrent access patterns
3. **Capture timing**: Use tools like `time` or add timestamps
4. **Compare outputs**: Use diff to compare parallel request results

## Example: Running Full Test Suite

```bash
#!/bin/bash
# Run all tests for index 1

for category in Idempotence Atomicity Conservation; do
    for mode in Parallel Sequential; do
        dir="idx_1/${category}/${mode}"
        if [ -d "$dir" ]; then
            echo "=== Testing ${category} - ${mode} ==="
            for config in "$dir"/*.txt; do
                if [ -f "$config" ]; then
                    echo "Running $(basename $config)..."
                    curl --config "$config" -o /dev/null -w "Time: %{time_total}s, HTTP: %{http_code}\\n"
                fi
            done
        fi
    done
done
```
"""
        
        with open(readme_path, 'w') as f:
            f.write(content)
        
        print(f"\n✓ Created master README: {readme_path}")


def main():
    parser = argparse.ArgumentParser(
        description='Generate organized TOCTOU test cases from JSON file',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Example JSON format:
{
  "metadata": {
    "total_requests": 2,
    "export_date": "...",
    "format_version": "1.0"
  },
  "requests": [
    {
      "index": 1,
      "method": "POST",
      "url": "https://example.com/api/endpoint",
      "components": {
        "url": "https://example.com/api/endpoint",
        "request": "POST",
        "headers": ["Content-Type: application/json", "Authorization: Bearer token"],
        "cookies": ["session=abc123"],
        "data": "{\\"key\\":\\"value\\"}"
      }
    }
  ]
}

Usage:
  %(prog)s -f toctou.json
  %(prog)s -f toctou.json -o my_tests/
        """
    )
    
    parser.add_argument('-f', '--file', required=True,
                       help='Path to TOCTOU JSON file')
    parser.add_argument('-o', '--output-dir', default='./toctou_tests',
                       help='Output directory for test cases (default: ./toctou_tests)')
    
    args = parser.parse_args()
    
    # Read JSON file
    try:
        with open(args.file, 'r', encoding='utf-8') as f:
            json_data = json.load(f)
    except FileNotFoundError:
        print(f"Error: File '{args.file}' not found", file=sys.stderr)
        sys.exit(1)
    except json.JSONDecodeError as e:
        print(f"Error: Invalid JSON in '{args.file}': {e}", file=sys.stderr)
        sys.exit(1)
    
    # Validate JSON structure
    if "requests" not in json_data:
        print("Error: JSON must contain 'requests' key", file=sys.stderr)
        sys.exit(1)
    
    # Generate test cases
    organizer = TOCTOUTestOrganizer(json_data, args.output_dir)
    
    print(f"Generating TOCTOU test cases...")
    print(f"Output directory: {args.output_dir}")
    print(f"Total requests: {len(organizer.requests)}")
    
    organizer.generate_all_tests()
    organizer.create_master_readme()
    
    print(f"\n✓ All test cases generated successfully!")
    print(f"✓ Test cases organized in: {args.output_dir}/")
    print(f"\nTo run a test:")
    print(f"  curl --config {args.output_dir}/idx_1/Idempotence/Parallel/config1.txt")


if __name__ == '__main__':
    main()
