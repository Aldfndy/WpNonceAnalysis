# Examples

## `wpnonce-demo` WordPress Plugin
A minimal plugin demonstrating how **WPNonceAnalysis** behaves on insecure vs secure patterns.

### Install
1. Zip the `wpnonce-demo/` folder or copy it to your local WordPress site's `wp-content/plugins/wpnonce-demo/`.
2. Activate **WP Nonce Demo (Insecure vs Secure)** from the WordPress admin.

### Try It
- Go to **Nonce Demo** menu in the admin.
- Submit **Insecure Form** → should be flagged by the sniffs (missing nonce generation & verification).
- Submit **Secure Form** → passes nonce checks.

### Lint
From the project root (where WPNonceAnalysis is registered):
```bash
vendor/bin/phpcs -s --report=summary --standard=WPNonceAnalysis examples/wpnonce-demo
```
