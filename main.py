import argparse
import os
import re
import json
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
            # The token pattern is the odd one out: it needs no key name
            # beside it, because a JWT carries its own shape. It only
            # recognises the common eyJ opening of a JSON header, so a
            # token built on a differently ordered or padded header can
            # pass under it unnoticed.
            "jwt_token": r"([Ee][yJj][0-9a-zA-Z\-\_]+\.[Ee][yJj][0-9a-zA-Z\-\_]+\.[0-9a-zA-Z\-\_\+\/\=]+)"

        }
        # Scan bookkeeping: a run that read nothing must not report a
        # clean result, so main reads these counters.
        self.files_scanned = 0
        self.lines_scanned = 0
        self.read_errors = 0
        self.scanned_paths = []

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
                self.files_scanned += 1
                self.scanned_paths.append(os.path.realpath(file_path))
                for i, line in enumerate(f):
                    self.lines_scanned += 1
                    # The value character sets in these patterns are where my
                    # coverage ends. A secret containing a dot, a space, or a
                    # character outside the set for its pattern is matched only
                    # up to that character, or not at all, and a value assigned
                    # with no key name on the same line is invisible to the three
                    # named patterns entirely.
                    for pattern_name, pattern in self.patterns.items():
                        match = re.search(pattern, line)
                        if match:
                            # The matched value is never stored,
                            # printed, or written out. A finding
                            # carries the pattern kind, file, and line
                            # only.
                            findings.append({
                                "file": file_path,
                                "line": i + 1,
                                "pattern": pattern_name,
                                "key": match.group(1) if match.groups() else pattern_name
                            })
        except FileNotFoundError:
            self.read_errors += 1
            logging.error(f"File not found: {file_path}")
        except Exception as e:
            self.read_errors += 1
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
        sensitive_name = re.compile(r"(?i)(api[_-]?key|secret|password|passwd|pwd|token|aws_|credential)")
        for var_name, var_value in os.environ.items():
            self.lines_scanned += 1
            # The keyword of an environment secret sits in the
            # variable name, so search name and value together.
            search_text = f"{var_name}={var_value}"
            matched = False
            for pattern_name, pattern in self.patterns.items():
                match = re.search(pattern, search_text)
                if match:
                    findings.append({
                        "environment_variable": var_name,
                        "pattern": pattern_name
                    })
                    # A variable can collect one finding per pattern, plus the
                    # name based one is the only duplicate I suppress. The same
                    # variable can therefore appear several times in my output
                    # under different pattern names, which a reader counting
                    # findings should know before treating the count as a count
                    # of distinct secrets.
                    matched = True
            # This fallback judges the name alone, so an ordinary switch
            # like TOKEN_ENABLED set to true is reported as a finding,
            # while a variable actually named API_KEY with an empty value
            # escapes, because the empty value fails the test on the left
            # and the named patterns above need at least one value
            # character to match.
            if not matched and var_value and sensitive_name.search(var_name):
                findings.append({
                    "environment_variable": var_name,
                    "pattern": "sensitive_name"
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
                # A directory scan opens every file in the tree as text,
                # whatever it is. Binary files raise on decode, are counted
                # as read errors, and contribute nothing, and os.walk does
                # not follow directory symlinks, so a tree reached only
                # through a link is skipped in silence.
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
        if not os.path.isfile(args.file):
            logging.error(f"File not found: {args.file}")
            print("Nothing was scanned: the named file does not exist.")
            sys.exit(1)
        all_findings = scanner.scan_file(args.file)
    elif args.directory:
        if not os.path.isdir(args.directory):
            logging.error(f"Directory not found: {args.directory}")
            print("Nothing was scanned: the named directory does not exist.")
            sys.exit(1)
        all_findings = scanner.process_directory(args.directory)
    elif args.environment:
        all_findings = scanner.scan_environment_variables()

    scanned_anything = scanner.lines_scanned > 0 or (args.environment and len(os.environ) > 0)
    if args.environment:
        scanned_anything = len(os.environ) > 0
    if not scanned_anything:
        print("Nothing was scanned.")
        sys.exit(1)

    if args.output:
        resolved_output = os.path.realpath(args.output)
        # The refusal list holds only files that were actually opened.
        # An output path inside a scanned directory that did not exist
        # when the walk passed is not in it, so the findings file can
        # still land inside the tree I just scanned, ready to be
        # scanned itself on the next run.
        if resolved_output in scanner.scanned_paths:
            logging.error("Output path is one of the scanned files; refusing to overwrite it.")
            print("Error: the output path must not be a scanned file.")
            sys.exit(1)
        try:
            with open(args.output, 'w') as outfile:
                json.dump(all_findings, outfile, indent=4)
            logging.info(f"Findings written to {args.output}")
        except Exception as e:
            logging.error(f"Error writing to output file: {e}")
            sys.exit(1)

    if all_findings:
        print("Potential secrets found:")
        for finding in all_findings:
            print(finding)
        sys.exit(1)
    else:
        print("No potential secrets found.")
        sys.exit(0)


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