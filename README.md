![Banner](banner.png)

# misconfig-ConfigEnvironmentVariableScanner
Scans configuration files and environment variables for hardcoded credentials, API keys, and other sensitive information. Reports potential vulnerabilities due to exposing these secrets. Uses regex patterns and potential integration with existing secret scanning libraries. - Focused on Check for misconfigurations in configuration files or infrastructure definitions

## Install
`git clone https://github.com/ShadowGuardAI/misconfig-configenvironmentvariablescanner`

Findings never carry the matched value. A finding names the pattern kind, the file and line, or the environment variable name, and nothing else, in the terminal output and in the JSON written with `-o`.

The output path may not be one of the scanned files; naming one is refused at exit 1 and the scanned file is left untouched.

Environment mode checks each variable name together with its value, because the keyword of an environment secret usually sits in the name.

Exit codes: 1 when any finding is reported, and 1 when nothing was scanned (a missing file or directory, an empty directory, or a file that cannot be read). 0 only for a clean scan of real content.

## Usage
`./misconfig-configenvironmentvariablescanner [params]`

## Parameters
- `-h`: Show help message and exit
- `-o`: No description provided

## License
Copyright (c) ShadowGuardAI
