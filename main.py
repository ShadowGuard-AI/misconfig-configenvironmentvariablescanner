import argparse
import os
import re
import json
import yaml
import logging
import sys

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

class ConfigEnvironmentVariableScanner:
    """
    Scans configuration files and environment variables for hardcoded credentials,
    API keys, and other sensitive information.
    """

    def __init__(self):
        """
        Initializes the ConfigEnvironmentVariableScanner with regex patterns for
        sensitive information.
        """
        self.patterns = {
            "api_key": r"(?i)(api_key|apikey|secret_key|secretkey)\s*[:=]\s*[\"']?([a-zA-Z0-9_-]+)[\"']?",
            "password": r"(?i)(password|pwd)\s*[:=]\s*[\"']?([a-zA-Z0-9!@#$%^&*()_+-=]+)[\"']?",
            "aws_key": r"(?i)(aws_access_key_id|aws_secret_access_key)\s*[:=]\s*[\"']?([A-Za-z0-9/+=]+)[\"']?",
            "jwt_token": r"([Ee][yJj][0-9a-zA-Z\-\_]+\.[Ee][yJj][0-9a-zA-Z\-\_]+\.[0-9a-zA-Z\-\_\+\/\=]+)"

        }

    def scan_file(self, file_path):
        """
        Scans a single file for sensitive information using regex patterns.

        Args:
            file_path (str): The path to the file to scan.

        Returns:
            list: A list of findings (dictionaries) with file path, line number,
                  and matched pattern.
        """
        findings = []
        try:
            with open(file_path, 'r') as f:
                for i, line in enumerate(f):
                    for pattern_name, pattern in self.patterns.items():
                        match = re.search(pattern, line)
                        if match:
                            findings.append({
                                "file": file_path,
                                "line": i + 1,
                                "pattern": pattern_name,
                                "match": match.group(0).strip()
                            })
        except FileNotFoundError:
            logging.error(f"File not found: {file_path}")
        except Exception as e:
            logging.error(f"Error reading file {file_path}: {e}")
        return findings

    def scan_environment_variables(self):
        """
        Scans environment variables for sensitive information using regex patterns.

        Returns:
            list: A list of findings (dictionaries) with variable name,
                  and matched pattern.
        """
        findings = []
        for var_name, var_value in os.environ.items():
            for pattern_name, pattern in self.patterns.items():
                match = re.search(pattern, var_value)
                if match:
                    findings.append({
                        "environment_variable": var_name,
                        "pattern": pattern_name,
                        "match": match.group(0).strip()
                    })
        return findings

    def process_directory(self, directory):
        """
        Recursively scans a directory for configuration files and scans them.

        Args:
            directory (str): The directory to scan.

        Returns:
            list: A list of findings (dictionaries) from all scanned files.
        """
        findings = []
        for root, _, files in os.walk(directory):
            for file in files:
                file_path = os.path.join(root, file)
                findings.extend(self.scan_file(file_path))
        return findings


def setup_argparse():
    """
    Sets up the argument parser for the command line interface.

    Returns:
        argparse.ArgumentParser: The argument parser object.
    """
    parser = argparse.ArgumentParser(description="Scans configuration files and environment variables for sensitive information.")
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("-f", "--file", help="Path to a single file to scan.")
    group.add_argument("-d", "--directory", help="Path to a directory to scan recursively.")
    group.add_argument("-e", "--environment", action="store_true", help="Scan environment variables.")
    parser.add_argument("-o", "--output", help="Path to output file (JSON format).", default=None) #Add option to output to file
    return parser


def main():
    """
    Main function to parse arguments, perform the scan, and print results.
    """
    parser = setup_argparse()
    args = parser.parse_args()

    scanner = ConfigEnvironmentVariableScanner()
    all_findings = []

    if args.file:
        all_findings = scanner.scan_file(args.file)
    elif args.directory:
        all_findings = scanner.process_directory(args.directory)
    elif args.environment:
        all_findings = scanner.scan_environment_variables()
    
    if args.output: #If output file is specified, write to file.
        try:
            with open(args.output, 'w') as outfile:
                json.dump(all_findings, outfile, indent=4)
            logging.info(f"Findings written to {args.output}")
        except Exception as e:
            logging.error(f"Error writing to output file: {e}")


    if all_findings:
        print("Potential secrets found:")
        for finding in all_findings:
            print(finding)
    else:
        print("No potential secrets found.")


if __name__ == "__main__":
    main()


# Usage Examples:
# 1. Scan a single file:
#    python misconfig-ConfigEnvironmentVariableScanner.py -f config.yaml

# 2. Scan a directory recursively:
#    python misconfig-ConfigEnvironmentVariableScanner.py -d /path/to/config/files

# 3. Scan environment variables:
#    python misconfig-ConfigEnvironmentVariableScanner.py -e

# 4. Output findings to JSON file:
#    python misconfig-ConfigEnvironmentVariableScanner.py -f config.yaml -o findings.json

# Offensive Tool Steps:
# 1.  Gather configuration files from target system (e.g., using `find`, `locate`, or `grep`).
# 2.  Run the scanner against gathered files.
# 3.  Analyze the findings for exploitable credentials or API keys.
# 4.  Use the discovered credentials to access resources or escalate privileges.
# 5.  Attempt to identify the origin of the discovered secrets to prevent future leaks.