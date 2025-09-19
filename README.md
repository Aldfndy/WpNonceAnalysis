# WPNonceAnalysis — WordPress Nonce Static Analysis (PHPCS Standard)

**WPNonceAnalysis** is a custom **PHP_CodeSniffer (PHPCS)** standard that detects **nonce generation, verification, and implementation quality** in WordPress codebases to mitigate CSRF risks. Designed for **research/theses**.

## Key Features
- **Nonce Generation Sniff** — flags missing nonce generation in common WordPress contexts (forms, `add_meta_box` callbacks, AJAX handlers, REST endpoints).
- **Nonce Verification Sniff** — flags missing verification when reading `$_POST`, `$_GET`, `$_REQUEST`, `$_FILES`, including awareness of activation/deactivation/uninstall hooks.
- **Nonce Implementation Quality Sniff** — heuristics for action specificity and pairing with **capability checks**.

> Built on top of **PHP_CodeSniffer** and follows the `Standards/WPNonceAnalysis/Sniffs/...` structure so it can be registered via `installed_paths`.

## Requirements
- PHP **>= 7.4**
- Composer
- `squizlabs/php_codesniffer` **^3.7**

## Install (Local Development)
```bash
git clone https://github.com/Aldfndy/wp-nonce-analysis.git
cd wp-nonce-analysis
composer install

# Register the standard
vendor/bin/phpcs --config-set installed_paths "$(pwd)"
vendor/bin/phpcs -i  # ensure 'WPNonceAnalysis' is listed
```

## Usage
```bash
# Lint a plugin/theme path
vendor/bin/phpcs --standard=WPNonceAnalysis path/to/wordpress-plugin

# With sources and summary
vendor/bin/phpcs -s --report=summary --standard=WPNonceAnalysis path/to/wordpress-plugin
```

## Project Layout
```
WPNonceAnalysis/
  ├─ ruleset.xml
  └─ Sniffs/
     └─ Security/
        ├─ NonceGenerationSniff.php
        ├─ NonceVerificationSniff.php
        └─ NonceImplementationQualitySniff.php
```
