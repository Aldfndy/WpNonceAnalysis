<?php
/**
 * Plugin Name: WP Nonce Demo (Insecure vs Secure)
 * Description: Demo plugin to showcase how WPNonceAnalysis flags missing nonce generation/verification.
 * Version: 0.1.0
 * Author: Aldi Fandiya Akbar
 * License: MIT
 */

if (!defined('ABSPATH')) { exit; }

add_action('admin_menu', function () {
    add_menu_page(
        'Nonce Demo',
        'Nonce Demo',
        'manage_options',
        'wpnonce-demo',
        'wpnonce_demo_render_page'
    );
});

function wpnonce_demo_render_page() {
    ?>
    <div class="wrap">
        <h1>WP Nonce Demo</h1>
        <p>This page renders two forms:</p>
        <ol>
            <li><strong>Insecure</strong> form — intentionally missing nonce generation and verification.</li>
            <li><strong>Secure</strong> form — includes nonce generation, and the handler verifies it.</li>
        </ol>

        <h2>Insecure Form</h2>
        <form method="POST" action="<?php echo admin_url('admin-post.php'); ?>">
            <input type="hidden" name="action" value="wpnonce_demo_insecure_save">
            <label>Option (insecure): <input type="text" name="demo_option_insecure" /></label>
            <button type="submit" class="button button-primary">Save (Insecure)</button>
        </form>

        <hr/>

        <h2>Secure Form</h2>
        <form method="POST" action="<?php echo admin_url('admin-post.php'); ?>">
            <input type="hidden" name="action" value="wpnonce_demo_secure_save">
            <?php wp_nonce_field('wpnonce_demo_secure_action', 'wpnonce_demo_secure_nonce'); ?>
            <label>Option (secure): <input type="text" name="demo_option_secure" /></label>
            <button type="submit" class="button button-primary">Save (Secure)</button>
        </form>
    </div>
    <?php
}

// Insecure handler: no nonce verification (should be flagged by NonceVerificationSniff)
add_action('admin_post_wpnonce_demo_insecure_save', function () {
    if (isset($_POST['demo_option_insecure'])) {
        // Intentionally no nonce verification here
        update_option('wpnonce_demo_insecure', sanitize_text_field($_POST['demo_option_insecure']));
    }
    wp_redirect(admin_url('admin.php?page=wpnonce-demo&saved=insecure'));
    exit;
});

// Secure handler: properly verifies nonce
add_action('admin_post_wpnonce_demo_secure_save', function () {
    if (!isset($_POST['wpnonce_demo_secure_nonce']) ||
        !wp_verify_nonce($_POST['wpnonce_demo_secure_nonce'], 'wpnonce_demo_secure_action')) {
        wp_die('Nonce verification failed');
    }

    if (isset($_POST['demo_option_secure'])) {
        update_option('wpnonce_demo_secure', sanitize_text_field($_POST['demo_option_secure']));
    }
    wp_redirect(admin_url('admin.php?page=wpnonce-demo&saved=secure'));
    exit;
});
