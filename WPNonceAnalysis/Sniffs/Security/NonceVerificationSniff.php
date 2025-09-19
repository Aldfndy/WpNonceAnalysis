<?php
/**
 * Enhanced nonce verification checks for CSRF research.
 * This sniff detects the PRESENCE or ABSENCE of nonce verification in various contexts.
 * It has been refined to be aware of plugin activation, deactivation, and uninstall hooks.
 * It does not check the quality of the nonce implementation.
 */
namespace PHP_CodeSniffer\Standards\WPNonceAnalysis\Sniffs\Security;

use PHP_CodeSniffer\Sniffs\Sniff;
use PHP_CodeSniffer\Files\File;

class NonceVerificationSniff implements Sniff
{
    /** @var array A list of superglobals that should be verified with nonces. */
    protected $superglobals = ['$_POST', '$_GET', '$_REQUEST', '$_FILES'];
    
    /** @var array A list of nonce verification functions. */
    protected $nonceVerificationFunctions = ['wp_verify_nonce', 'check_admin_referer', 'check_ajax_referer'];
    
    /** @var array A list of data modification functions that should be protected. */
    protected $dataModificationFunctions = [
        'wp_insert_post', 'wp_update_post', 'wp_delete_post', 'wp_trash_post', 'wp_untrash_post',
        'add_post_meta', 'update_post_meta', 'delete_post_meta',
        'add_term_meta', 'update_term_meta', 'delete_term_meta',
        'add_user_meta', 'update_user_meta', 'delete_user_meta',
        'add_metadata', 'update_metadata', 'delete_metadata',
        'add_option', 'update_option', 'delete_option',
        'add_site_option', 'update_site_option', 'delete_site_option',
        'wp_insert_user', 'wp_update_user', 'wp_delete_user',
        'wp_set_current_user',
        'wp_insert_term', 'wp_update_term', 'wp_delete_term',
        'wp_insert_comment', 'wp_update_comment', 'wp_delete_comment',
        'wp_delete_attachment',
    ];

    /** @var array A list of critical security functions that should always be protected. */
    protected $criticalSecurityFunctions = [
        'wp_set_password', 'wp_set_auth_cookie', 'wp_clear_auth_cookie',
        'add_role', 'remove_role', 'WP_User::add_role', 'WP_User::remove_role', 'WP_User::set_role',
        'add_cap', 'remove_cap', 'WP_User::add_cap', 'WP_User::remove_cap',
        'grant_super_admin', 'revoke_super_admin',
        'wp_mail',
        'file_put_contents', 'fwrite', 'unlink', 'copy', 'move_uploaded_file', 'rename',
        'wp_upload_bits', 'wp_handle_upload', 'wp_insert_attachment',
        'WP_Filesystem::put_contents', 'WP_Filesystem::delete', 'WP_Filesystem::move', 'WP_Filesystem::copy',
        'activate_plugin', 'deactivate_plugins', 'delete_plugins',
        'switch_theme', 'delete_theme',
    ];
    
    /** @var array Functions generally considered safe for read-only operations. */
    protected $readOnlyOrSafeFunctions = [
        'echo', 'print', 'printf', 'sprintf', '_e', '_ex', 'esc_html_e', 'esc_attr_e',
        'esc_html', 'esc_attr', 'esc_js', 'esc_textarea', 'esc_url', 'esc_url_raw',
        'sanitize_text_field', 'sanitize_email', 'sanitize_file_name', 'sanitize_html_class',
        'sanitize_key', 'sanitize_meta', 'sanitize_mime_type', 'sanitize_option',
        'sanitize_sql_orderby', 'sanitize_title', 'sanitize_user', 'wp_check_invalid_utf8',
        'wp_kses', 'wp_kses_post', 'wp_kses_data', 'force_balance_tags',
        'absint', 'intval', 'floatval', 'boolval', 'strval',
        'get_option', 'get_site_option', 'get_transient', 'get_site_transient',
        'get_post_meta', 'get_term_meta', 'get_user_meta', 'get_comment_meta', 'has_meta',
        'get_post', 'get_posts', 'get_pages', 'get_children', 'get_post_types', 'get_taxonomies',
        'get_terms', 'get_term', 'get_term_by', 'get_term_children', 'get_term_link',
        'get_users', 'get_user_by', 'get_user_locale',
        'get_comments', 'get_comment',
        'get_the_title', 'get_the_content', 'get_permalink', 'get_the_excerpt',
        'get_query_var', 'get_search_query',
        'is_array', 'is_string', 'is_numeric', 'is_object', 'is_email', 'empty', 'isset', 'count',
        'in_array', 'array_key_exists', 'defined', 'current_time', 'date', 'strtotime',
        'add_query_arg', 'remove_query_arg',
        'wpdb::get_var', 'wpdb::get_row', 'wpdb::get_col', 'wpdb::get_results', 'wpdb::_weak_escape', 'wpdb::esc_like',
        'strcmp', 'strncmp', 'strcasecmp', 'strncasecmp', 'version_compare',
        'implode', 'explode', 'join', 'trim', 'ltrim', 'rtrim', 'strtolower', 'strtoupper', 'substr', 'strlen',
        'strpos', 'stripos', 'strrpos', 'strripos', 'strstr', 'stristr', 'str_replace', 'preg_match', 'preg_match_all',
        'json_decode',
        'maybe_unserialize', 'is_serialized',
        'is_home', 'is_front_page', 'is_single', 'is_singular', 'is_page', 'is_category', 'is_tag', 'is_tax',
        'is_archive', 'is_author', 'is_date', 'is_year', 'is_month', 'is_day', 'is_time', 'is_search', 'is_404',
        'is_admin', 'is_user_logged_in', 'is_super_admin', 'current_user_can', 'user_can',
        'has_shortcode', 'shortcode_exists',
        'wp_is_mobile',
    ];

    /** @var array Functions or contexts that are safe from CSRF. */
    protected $safeContexts = ['is_admin', 'is_user_logged_in', 'wp_doing_ajax', 'wp_doing_cron', 'wp_is_json_request', 'wp_is_xml_request', 'defined'];
    
    /** @var array Hooks that are generally safe contexts. */
    protected $safeHooks = ['init', 'wp_loaded', 'plugins_loaded', 'setup_theme', 'after_setup_theme', 'admin_init', 'wp_head', 'wp_footer', 'admin_head', 'admin_footer', 'login_head', 'login_footer'];

    /** @var array Keywords for identifying password-related functions. */
    protected $passwordRelatedFunctions = ['password_reset', 'reset_password', 'change_password', 'update_password', 'set_password'];
    
    /** @var array Plugin lifecycle hooks that do not require nonce verification. */
    protected $pluginLifecycleHooks = ['register_activation_hook', 'register_deactivation_hook'];
    
    public function register()
    {
        return [T_VARIABLE, T_STRING, T_FUNCTION];
    }
    
    public function process(File $phpcsFile, $stackPtr)
    {
        if (basename(strtolower($phpcsFile->getFilename())) === 'uninstall.php') {
            return;
        }

        $tokens = $phpcsFile->getTokens();
        $token  = $tokens[$stackPtr];
        
        if ($token['code'] === T_FUNCTION) {
            $this->checkPasswordRelatedFunction($phpcsFile, $stackPtr);
            return;
        }
        
        if ($token['code'] === T_VARIABLE && in_array($token['content'], $this->superglobals)) {
            $this->checkSuperglobalUsage($phpcsFile, $stackPtr);
            return;
        }
        
        $nextNonWhitespace = $phpcsFile->findNext(T_WHITESPACE, ($stackPtr + 1), null, true);
        if ($token['code'] === T_STRING && ($nextNonWhitespace === false || $tokens[$nextNonWhitespace]['code'] !== T_OPEN_PARENTHESIS)) {
            return;
        }

        if ($token['code'] === T_STRING) {
            $functionName = $token['content'];
            
            if (in_array($functionName, $this->pluginLifecycleHooks)) {
                return;
            }
            if (in_array($functionName, $this->dataModificationFunctions) || $this->isWpdbWriteMethod($phpcsFile, $stackPtr)) {
                $this->checkDataModificationFunction($phpcsFile, $stackPtr);
                return;
            }
            if (in_array($functionName, $this->criticalSecurityFunctions) || $this->isWpdbWriteMethod($phpcsFile, $stackPtr)) {
                $this->checkCriticalSecurityFunction($phpcsFile, $stackPtr);
                return;
            }
            if ($functionName === 'add_action') {
                $this->checkAjaxHandler($phpcsFile, $stackPtr);
                return;
            }
            if ($functionName === 'register_rest_route') {
                $this->checkRestApiEndpoint($phpcsFile, $stackPtr);
                return;
            }
        }
    }

    protected function isWpdbWriteMethod(File $phpcsFile, $stackPtr) {
        $tokens = $phpcsFile->getTokens();
        $methodName = $tokens[$stackPtr]['content'];
        $wpdbWriteMethods = ['query', 'insert', 'update', 'delete', 'replace'];

        if (in_array($methodName, $wpdbWriteMethods)) {
            $prevTokenPtr = $phpcsFile->findPrevious(T_WHITESPACE, $stackPtr - 1, null, true);
            if ($prevTokenPtr !== false && $tokens[$prevTokenPtr]['code'] === T_OBJECT_OPERATOR) {
                $objectVarPtr = $phpcsFile->findPrevious(T_WHITESPACE, $prevTokenPtr - 1, null, true);
                 if ($objectVarPtr !== false && $tokens[$objectVarPtr]['code'] === T_VARIABLE && $tokens[$objectVarPtr]['content'] === '$wpdb') {
                    if ($methodName === 'query') {
                        $openParen = $phpcsFile->findNext(T_WHITESPACE, $stackPtr + 1, null, true);
                        if ($openParen !== false && $tokens[$openParen]['code'] === T_OPEN_PARENTHESIS) {
                             $args = $this->getFunctionCallArguments($phpcsFile, $openParen);
                             if (isset($args[0]) && !empty($args[0])) {
                                 $firstArgToken = $tokens[$args[0][0]['ptr']];
                                 if ($firstArgToken['code'] === T_CONSTANT_ENCAPSED_STRING) {
                                     $queryString = strtoupper(trim($firstArgToken['content'], "'\""));
                                     $writeKeywords = ['INSERT', 'UPDATE', 'DELETE', 'REPLACE', 'ALTER', 'CREATE', 'DROP', 'TRUNCATE'];
                                     foreach($writeKeywords as $keyword) {
                                         if (strpos($queryString, $keyword) === 0) return true;
                                     }
                                     return false;
                                 }
                                 return true;
                             }
                        }
                        return true;
                    }
                    return true;
                }
            }
        }
        return false;
    }

    protected function checkPasswordRelatedFunction(File $phpcsFile, $stackPtr)
    {
        $tokens = $phpcsFile->getTokens();
        
        $functionNamePtr = $phpcsFile->findNext(T_STRING, $stackPtr + 1);
        if ($functionNamePtr === false) return;
        $functionName = $tokens[$functionNamePtr]['content'];
        
        $isPasswordFunctionByName = false;
        foreach ($this->passwordRelatedFunctions as $passwordFunctionKeyword) {
            if (stripos($functionName, $passwordFunctionKeyword) !== false) {
                $isPasswordFunctionByName = true;
                break;
            }
        }
        
        if (!isset($tokens[$stackPtr]['scope_opener']) || !isset($tokens[$stackPtr]['scope_closer'])) return;
        $functionStart = $tokens[$stackPtr]['scope_opener'];
        $functionEnd = $tokens[$stackPtr]['scope_closer'];
        
        $wpSetPasswordUsed = false;
        for ($i = ($functionStart + 1); $i < $functionEnd; $i++) {
            if ($tokens[$i]['code'] === T_STRING && $tokens[$i]['content'] === 'wp_set_password') {
                $wpSetPasswordUsed = true;
                break;
            }
        }
        
        if (!$isPasswordFunctionByName && !$wpSetPasswordUsed) return;
        
        $superglobalUsed = false;
        for ($i = ($functionStart + 1); $i < $functionEnd; $i++) {
            if ($tokens[$i]['code'] === T_VARIABLE && in_array($tokens[$i]['content'], $this->superglobals)) {
                $superglobalUsed = true;
                break;
            }
        }

        if (!$superglobalUsed && !$wpSetPasswordUsed) return;

        $nonceVerified = $this->isNonceVerifiedInScope($phpcsFile, $functionStart, $functionEnd);
        
        if (!$nonceVerified) {
            $phpcsFile->addError(
                'Password-related function "%s" processes user input or performs critical operations without nonce verification. This is a critical security issue.',
                $stackPtr, 'PasswordFunctionWithoutNonceVerification', [$functionName]
            );
        }
    }
    
    protected function checkSuperglobalUsage(File $phpcsFile, $stackPtr)
    {
        $tokens = $phpcsFile->getTokens();
        if ($this->isInSafeContext($phpcsFile, $stackPtr)) return;
        
        $functionPtr = $phpcsFile->getCondition($stackPtr, T_FUNCTION) ?: $phpcsFile->getCondition($stackPtr, T_CLOSURE);
        $scopeStart = 0;
        $scopeEnd   = $phpcsFile->numTokens - 1;
        if ($functionPtr !== false && isset($tokens[$functionPtr]['scope_opener'])) {
            $scopeStart = $tokens[$functionPtr]['scope_opener'];
            $scopeEnd   = $tokens[$functionPtr]['scope_closer'];
        }
        
        $nonceVerified = $this->isNonceVerifiedInScope($phpcsFile, $scopeStart, $scopeEnd) ||
                         $this->isInNonceVerificationConditional($phpcsFile, $stackPtr) ||
                         $this->isInNonceVerificationWrapper($phpcsFile, $functionPtr) ||
                         $this->isInSafeHook($phpcsFile, $functionPtr, $tokens);
        
        if ($nonceVerified) {
            return;
        }

        if ($this->isCriticalFunctionContext($phpcsFile, $functionPtr, $tokens[$stackPtr]['content'])) {
            $phpcsFile->addError(
                'Superglobal %s used without nonce verification in a security-critical context.',
                $stackPtr, 'SuperglobalWithoutNonceInCriticalContext', [$tokens[$stackPtr]['content']]
            );
        } else if ($this->isReadOnlyOperation($phpcsFile, $stackPtr, $tokens[$stackPtr]['content'], $scopeStart, $scopeEnd)) {
            $phpcsFile->addWarning(
                'Superglobal %s used without nonce verification in what appears to be a read-only context.',
                $stackPtr, 'SuperglobalWithoutNonceInReadOnly', [$tokens[$stackPtr]['content']]
            );
        } else {
            $phpcsFile->addError(
                'Superglobal %s used without nonce verification in a data modification or non-read-only context.',
                $stackPtr, 'SuperglobalWithoutNonceInDataModification', [$tokens[$stackPtr]['content']]
            );
        }
    }
    
    protected function checkDataModificationFunction(File $phpcsFile, $stackPtr)
    {
        if ($this->isInSafeContext($phpcsFile, $stackPtr)) return;
        
        $functionPtr = $phpcsFile->getCondition($stackPtr, T_FUNCTION) ?: $phpcsFile->getCondition($stackPtr, T_CLOSURE);
        if ($functionPtr === false) return;
        
        $tokens = $phpcsFile->getTokens();
        if (!isset($tokens[$functionPtr]['scope_opener']) || !isset($tokens[$functionPtr]['scope_closer'])) return;
        $scopeStart = $tokens[$functionPtr]['scope_opener'];
        $scopeEnd   = $tokens[$functionPtr]['scope_closer'];

        $nonceVerified = $this->isNonceVerifiedInScope($phpcsFile, $scopeStart, $scopeEnd) ||
                         $this->isInNonceVerificationConditional($phpcsFile, $stackPtr) ||
                         $this->isInNonceVerificationWrapper($phpcsFile, $functionPtr) ||
                         $this->isInSafeHook($phpcsFile, $functionPtr, $tokens);

        if ($nonceVerified) {
            return;
        }
        
        if ($this->isCriticalFunctionContext($phpcsFile, $functionPtr, $tokens[$stackPtr]['content'])) {
            $phpcsFile->addError(
                'Data modification function %s used without nonce verification in a security-critical context.',
                $stackPtr, 'DataModificationWithoutNonceInCriticalContext', [$tokens[$stackPtr]['content']]
            );
        } else {
            $phpcsFile->addWarning(
                'Data modification function %s used without nonce verification.',
                $stackPtr, 'DataModificationWithoutNonce', [$tokens[$stackPtr]['content']]
            );
        }
    }

    protected function checkCriticalSecurityFunction(File $phpcsFile, $stackPtr)
    {
        $tokens = $phpcsFile->getTokens();
        $functionContextPtr = $phpcsFile->getCondition($stackPtr, T_FUNCTION) ?: $phpcsFile->getCondition($stackPtr, T_CLOSURE);

        if ($this->isInSafeContext($phpcsFile, $stackPtr) || $this->isInSafeHook($phpcsFile, $functionContextPtr, $tokens)) {
            return;
        }

        $scopeStart = 0;
        $scopeEnd = $phpcsFile->numTokens - 1;
        if ($functionContextPtr !== false && isset($tokens[$functionContextPtr]['scope_opener'])) {
            $scopeStart = $tokens[$functionContextPtr]['scope_opener'];
            $scopeEnd = $tokens[$functionContextPtr]['scope_closer'];
        }
        
        $nonceVerified = $this->isNonceVerifiedInScope($phpcsFile, $scopeStart, $scopeEnd) ||
                         $this->isInNonceVerificationConditional($phpcsFile, $stackPtr) ||
                         $this->isInNonceVerificationWrapper($phpcsFile, $functionContextPtr);
        
        if ($nonceVerified) {
            return;
        }

        $phpcsFile->addError(
            'Critical security function %s is called without nonce verification.',
            $stackPtr, 'CriticalFunctionWithoutNonce', [$tokens[$stackPtr]['content']]
        );
    }
    
    protected function checkAjaxHandler(File $phpcsFile, $stackPtr) {
        $tokens = $phpcsFile->getTokens();
        
        $openParenthesis = $phpcsFile->findNext(T_WHITESPACE, $stackPtr + 1, null, true);
        if ($openParenthesis === false || $tokens[$openParenthesis]['code'] !== T_OPEN_PARENTHESIS) return;
        
        $args = $this->getFunctionCallArguments($phpcsFile, $openParenthesis);
        if (!isset($args[0]) || empty($args[0]) || $tokens[$args[0][0]['ptr']]['code'] !== T_CONSTANT_ENCAPSED_STRING) return;
        
        $hookName = trim($tokens[$args[0][0]['ptr']]['content'], "'\"");
        
        $isAjaxOrAdminPostAction = false;
        $ajaxPrefixes = ['wp_ajax_', 'admin_post_'];
        foreach($ajaxPrefixes as $prefix) {
            if (strpos($hookName, $prefix) === 0) {
                $isAjaxOrAdminPostAction = true;
                break;
            }
        }
        
        if (!$isAjaxOrAdminPostAction) return;
        if (!isset($args[1]) || empty($args[1])) return;

        $callbackTokens = $args[1];
        $callbackTokenPtr = $callbackTokens[0]['ptr'];
        
        $callbackScope = $this->getCallbackScopeDetails($phpcsFile, $callbackTokenPtr, $callbackTokens);

        if ($callbackScope) {
            $nonceVerified = $this->isNonceVerifiedInScope($phpcsFile, $callbackScope['start'], $callbackScope['end']);
            if (!$nonceVerified) {
                $phpcsFile->addError(
                    'AJAX/Admin Post action "%s" (callback: %s) does not appear to verify a nonce.',
                    $stackPtr,
                    'AjaxOrAdminPostWithoutNonceVerification',
                    [$hookName, $callbackScope['name']]
                );
            }
        }
    }
    
    protected function checkRestApiEndpoint(File $phpcsFile, $stackPtr) {
        $tokens = $phpcsFile->getTokens();
        
        $openParenthesis = $phpcsFile->findNext(T_WHITESPACE, $stackPtr + 1, null, true);
        if ($openParenthesis === false || $tokens[$openParenthesis]['code'] !== T_OPEN_PARENTHESIS) return;
        
        $args = $this->getFunctionCallArguments($phpcsFile, $openParenthesis);

        if (!isset($args[2]) || empty($args[2])) {
            $phpcsFile->addWarning(
                'REST API route registered via %s does not specify an arguments array containing a "permission_callback".',
                $stackPtr, 'RestApiMissingArgsArray', [$tokens[$stackPtr]['content']]
            );
            return;
        }

        $routeArgsTokenPtr = $args[2][0]['ptr'];
        
        if (!in_array($tokens[$routeArgsTokenPtr]['code'], [T_ARRAY, T_OPEN_SHORT_ARRAY, T_VARIABLE])) {
             $phpcsFile->addWarning(
                'REST API route registered via %s has an invalid arguments parameter; expected an array or variable.',
                $stackPtr, 'RestApiInvalidArgsParam', [$tokens[$stackPtr]['content']]
            );
            return;
        }

        if ($tokens[$routeArgsTokenPtr]['code'] === T_VARIABLE) {
            return;
        }

        $arrayStartPtr = ($tokens[$routeArgsTokenPtr]['code'] === T_ARRAY) ? $phpcsFile->findNext(T_OPEN_PARENTHESIS, $routeArgsTokenPtr + 1, null, true) : $routeArgsTokenPtr;
        $arrayEndPtr = $tokens[$arrayStartPtr]['parenthesis_closer'] ?? $tokens[$arrayStartPtr]['bracket_closer'] ?? null;

        if ($arrayStartPtr === false || $arrayEndPtr === null) {
            return;
        }
        
        if (!$this->hasPermissionCallback($phpcsFile, $arrayStartPtr, $arrayEndPtr)) {
            $phpcsFile->addWarning(
                'REST API route registered via %s does not appear to define a "permission_callback" in its arguments.',
                $stackPtr, 'RestApiMissingPermissionCallbackKey', [$tokens[$stackPtr]['content']]
            );
        }
    }
    
    /**
     * // MODIFIED: This function is now smarter.
     * It checks not just for the presence of a nonce verification call, but also
     * whether that call is wrapped in a logically flawed pattern.
     */
    protected function isNonceVerifiedInScope(File $phpcsFile, $start, $end) {
        $tokens = $phpcsFile->getTokens();
        for ($i = $start; $i < $end; $i++) {
            if ($tokens[$i]['code'] === T_STRING && in_array($tokens[$i]['content'], $this->nonceVerificationFunctions)) {
                $openParen = $phpcsFile->findNext(T_WHITESPACE, ($i + 1), null, true);
                if ($openParen !== false && $tokens[$openParen]['code'] === T_OPEN_PARENTHESIS) {
                    // Check if this specific verification call is part of a flawed logical pattern.
                    if ($this->isVerificationLogicFlawed($phpcsFile, $i)) {
                        // This verification is flawed. Add a specific error for it.
                        $phpcsFile->addError(
                            'A flawed nonce verification pattern was detected. The use of "isset() && !wp_verify_nonce()" can be bypassed if the nonce parameter is not sent at all, leading to a CSRF vulnerability.',
                            $i, // Attach the error to the function call itself.
                            'FlawedNonceLogic'
                        );
                        // Continue searching for another, potentially valid, verification call in the same scope.
                        continue;
                    }
                    // If we reach here, we found a verification call that is not flawed.
                    return true;
                }
            }
        }
        // No valid verification call was found in the entire scope.
        return false;
    }

    /**
     * // NEW METHOD: Checks for the specific flawed logic: if ( isset(...) && !verify_nonce(...) )
     *
     * @param \PHP_CodeSniffer\Files\File $phpcsFile The file being scanned.
     * @param int                         $stackPtr  The position of the nonce verification function call.
     * @return bool
     */
    protected function isVerificationLogicFlawed(File $phpcsFile, $stackPtr) {
        $tokens = $phpcsFile->getTokens();

        // 1. Check if the verification function is inside an `if` statement.
        $ifPtr = $phpcsFile->getCondition($stackPtr, T_IF);
        if ($ifPtr === false) {
            // Not inside an `if`, so it's not the specific flawed pattern we're looking for.
            // It might be `wp_verify_nonce(...) or die()`, which is fine.
            return false;
        }

        // 2. Get the tokens for the entire `if` condition.
        $conditionStart = $tokens[$ifPtr]['parenthesis_opener'];
        $conditionEnd   = $tokens[$ifPtr]['parenthesis_closer'];

        $hasIsset           = false;
        $hasLogicalAnd      = false;
        $isNonceCallNegated = false;

        // 3. Check if the nonce call is negated with `!`.
        $prevToken = $phpcsFile->findPrevious(T_WHITESPACE, $stackPtr - 1, $conditionStart, true);
        if ($prevToken !== false && $tokens[$prevToken]['code'] === T_BOOLEAN_NOT) {
            $isNonceCallNegated = true;
        }

        // 4. Scan the condition for `isset` and `&&`.
        for ($j = ($conditionStart + 1); $j < $conditionEnd; $j++) {
            $tokenCode = $tokens[$j]['code'];
            if ($tokenCode === T_ISSET) {
                $hasIsset = true;
            }
            if ($tokenCode === T_LOGICAL_AND) {
                $hasLogicalAnd = true;
            }
        }

        // 5. The logic is flawed if all parts of the dangerous pattern are present.
        if ($hasIsset && $hasLogicalAnd && $isNonceCallNegated) {
            return true;
        }

        return false;
    }
    
    protected function isInNonceVerificationConditional(File $phpcsFile, $stackPtr) {
        $tokens = $phpcsFile->getTokens();
        if (empty($tokens[$stackPtr]['conditions'])) return false;

        $conditionPtr = end($tokens[$stackPtr]['conditions']);
        if (!isset($tokens[$conditionPtr]) || !in_array($tokens[$conditionPtr]['code'], [T_IF, T_ELSEIF, T_ELSE])) return false;

        if (in_array($tokens[$conditionPtr]['code'], [T_IF, T_ELSEIF])) {
            $parenOpener = $tokens[$conditionPtr]['parenthesis_opener'];
            $parenCloser = $tokens[$conditionPtr]['parenthesis_closer'];
            for ($i = ($parenOpener + 1); $i < $parenCloser; $i++) {
                if ($tokens[$i]['code'] === T_STRING && in_array($tokens[$i]['content'], $this->nonceVerificationFunctions)) {
                    return true;
                }
            }
        }
        
        if ($tokens[$conditionPtr]['code'] === T_ELSE) {
            $prevIfPtr = $phpcsFile->findPrevious([T_IF, T_ELSEIF], $conditionPtr -1, null, false, null, true);
            if ($prevIfPtr !== false && isset($tokens[$prevIfPtr]['parenthesis_opener'])) {
                $parenOpener = $tokens[$prevIfPtr]['parenthesis_opener'];
                $parenCloser = $tokens[$prevIfPtr]['parenthesis_closer'];
                for ($i = ($parenOpener + 1); $i < $parenCloser; $i++) {
                    if ($tokens[$i]['code'] === T_STRING && in_array($tokens[$i]['content'], $this->nonceVerificationFunctions)) {
                        return true;
                    }
                }
            }
        }
        return false;
    }
    
    protected function isInNonceVerificationWrapper(File $phpcsFile, $functionPtr) {
        return false;
    }
    
    protected function isInSafeHook(File $phpcsFile, $functionContextPtr, $tokens) {
        if ($functionContextPtr === false) return false;

        $callbackName = null;
        if ($tokens[$functionContextPtr]['code'] === T_CLOSURE || $tokens[$functionContextPtr]['code'] === T_FN) {
            return false;
        } else {
            $funcNamePtr = $phpcsFile->findNext(T_STRING, $functionContextPtr + 1);
            if ($funcNamePtr !== false) {
                $callbackName = $tokens[$funcNamePtr]['content'];
            }
        }

        if ($callbackName === null) return false;

        $hookingFunctions = array_merge(['add_action', 'add_filter'], $this->pluginLifecycleHooks);
        
        $ptr = 0;
        while (($ptr = $phpcsFile->findNext(T_STRING, $ptr + 1)) !== false) {
            if (!in_array($tokens[$ptr]['content'], $hookingFunctions)) {
                continue;
            }

            $openParen = $phpcsFile->findNext(T_WHITESPACE, $ptr + 1, null, true);
            if ($openParen === false || $tokens[$openParen]['code'] === T_OPEN_PARENTHESIS) continue;
            
            $args = $this->getFunctionCallArguments($phpcsFile, $openParen);
            
            if (in_array($tokens[$ptr]['content'], $this->pluginLifecycleHooks)) {
                if (isset($args[1]) && !empty($args[1])) {
                    $hookCallbackToken = $tokens[$args[1][0]['ptr']];
                    if ($hookCallbackToken['code'] === T_CONSTANT_ENCAPSED_STRING && trim($hookCallbackToken['content'], "'\"") === $callbackName) {
                        return true;
                    }
                }
            } 
            elseif ($tokens[$ptr]['content'] === 'add_action' || $tokens[$ptr]['content'] === 'add_filter') {
                 if (isset($args[0]) && !empty($args[0]) && $tokens[$args[0][0]['ptr']]['code'] === T_CONSTANT_ENCAPSED_STRING &&
                     isset($args[1]) && !empty($args[1])) {
                
                    $hookName = trim($tokens[$args[0][0]['ptr']]['content'], "'\"");
                    $hookCallbackToken = $tokens[$args[1][0]['ptr']];

                    if ($hookCallbackToken['code'] === T_CONSTANT_ENCAPSED_STRING && trim($hookCallbackToken['content'], "'\"") === $callbackName) {
                        if (in_array($hookName, $this->safeHooks)) {
                            return true;
                        }
                    }
                }
            }
        }
        return false; 
    }
    
    protected function isInSafeContext(File $phpcsFile, $stackPtr) {
        $tokens = $phpcsFile->getTokens();
        if (empty($tokens[$stackPtr]['conditions'])) return false;

        foreach (array_reverse($tokens[$stackPtr]['conditions']) as $condPtr => $condCode) {
            if (in_array($condCode, [T_IF, T_ELSEIF])) {
                if (!isset($tokens[$condPtr]['parenthesis_opener']) || !isset($tokens[$condPtr]['parenthesis_closer'])) continue;
                $parenOpener = $tokens[$condPtr]['parenthesis_opener'];
                $parenCloser = $tokens[$condPtr]['parenthesis_closer'];
                for ($i = ($parenOpener + 1); $i < $parenCloser; $i++) {
                    if ($tokens[$i]['code'] === T_STRING && in_array($tokens[$i]['content'], $this->safeContexts)) {
                        return true;
                    }
                }
            }
        }
        return false;
    }
    
    protected function isReadOnlyOperation(File $phpcsFile, $superglobalPtr, $superglobalName, $scopeStart, $scopeEnd) {
        $tokens = $phpcsFile->getTokens();
        $variablesToCheck = [$superglobalName];

        for ($i = $superglobalPtr; $i < $scopeEnd; $i++) {
            $currentToken = $tokens[$i];

            if ($currentToken['code'] === T_STRING &&
                (in_array($currentToken['content'], $this->dataModificationFunctions) ||
                 in_array($currentToken['content'], $this->criticalSecurityFunctions) ||
                 $this->isWpdbWriteMethod($phpcsFile, $i))
            ) {
                $openParen = $phpcsFile->findNext(T_WHITESPACE, $i + 1, null, true);
                if ($openParen !== false && $tokens[$openParen]['code'] === T_OPEN_PARENTHESIS) {
                    $closeParen = $tokens[$openParen]['parenthesis_closer'];
                    for ($k = $openParen + 1; $k < $closeParen; $k++) {
                        if ($tokens[$k]['code'] === T_VARIABLE && in_array($tokens[$k]['content'], $variablesToCheck)) {
                            return false;
                        }
                    }
                }
            }

            if ($currentToken['code'] === T_EQUAL) {
                $assignedVarPtr = $phpcsFile->findPrevious(T_VARIABLE, $i - 1, $scopeStart, false, null, true);
                $valueStartPtr = $phpcsFile->findNext(T_WHITESPACE, $i + 1, null, true);

                if ($assignedVarPtr !== false && $valueStartPtr !== false) {
                    $valueEndPtr = $phpcsFile->findNext(T_SEMICOLON, $valueStartPtr, null, false, null, true);
                    if ($valueEndPtr === false) $valueEndPtr = $scopeEnd;

                    $valueContainsTrackedVar = false;
                    for ($k = $valueStartPtr; $k < $valueEndPtr; $k++) {
                        if ($tokens[$k]['code'] === T_VARIABLE && in_array($tokens[$k]['content'], $variablesToCheck)) {
                            $valueContainsTrackedVar = true;
                            break;
                        }
                    }
                    if ($valueContainsTrackedVar) {
                        if (!in_array($tokens[$assignedVarPtr]['content'], $variablesToCheck)) {
                            $variablesToCheck[] = $tokens[$assignedVarPtr]['content'];
                        }
                    }
                }
            }
        }

        $allUsagesSafe = true;
        for ($i = $superglobalPtr; $i < $scopeEnd; $i++) {
            if ($tokens[$i]['code'] === T_VARIABLE && in_array($tokens[$i]['content'], $variablesToCheck)) {
                $prevTokenPtr = $phpcsFile->findPrevious(T_WHITESPACE, $i - 1, null, true);
                $nextTokenPtr = $phpcsFile->findNext(T_WHITESPACE, $i + 1, null, true);

                if ($nextTokenPtr !== false && $tokens[$nextTokenPtr]['code'] === T_OPEN_PARENTHESIS) {
                    // Function call, not variable usage.
                } elseif ($prevTokenPtr !== false && $tokens[$prevTokenPtr]['code'] === T_STRING) {
                    $functionName = $tokens[$prevTokenPtr]['content'];
                    if (!in_array($functionName, $this->readOnlyOrSafeFunctions) &&
                        !in_array($functionName, $this->nonceVerificationFunctions) &&
                        !in_array($functionName, $this->safeContexts)
                        ) {
                        if (in_array($functionName, $this->dataModificationFunctions) ||
                            in_array($functionName, $this->criticalSecurityFunctions) ||
                            $this->isWpdbWriteMethod($phpcsFile, $prevTokenPtr)
                            ) {
                            return false;
                        }
                        $allUsagesSafe = false;
                        break; 
                    }
                } elseif ($prevTokenPtr !== false && $tokens[$prevTokenPtr]['code'] === T_OBJECT_OPERATOR && $tokens[$i]['content'] === '$wpdb') {
                    if ($nextTokenPtr !== false && $tokens[$nextTokenPtr]['code'] === T_STRING) {
                        $wpdbMethod = $tokens[$nextTokenPtr]['content'];
                        if (!in_array('wpdb::'.$wpdbMethod, $this->readOnlyOrSafeFunctions)) {
                             if ($this->isWpdbWriteMethod($phpcsFile, $nextTokenPtr)) {
                                return false;
                             }
                             $allUsagesSafe = false;
                             break;
                        }
                    }
                } else if ($prevTokenPtr !== false && in_array($tokens[$prevTokenPtr]['code'], [T_ECHO, T_PRINT])) {
                    continue;
                } else {
                    if ($nextTokenPtr !== false && $tokens[$nextTokenPtr]['code'] === T_EQUAL) {
                        // Assignment TO variable.
                    } elseif ($prevTokenPtr !== false && $tokens[$prevTokenPtr]['code'] === T_EQUAL) {
                        continue;
                    }
                }
            }
        }
        
        return $allUsagesSafe;
    }
    
    protected function findFunctionDefinition(File $phpcsFile, $name) {
        $tokens = $phpcsFile->getTokens();
        $ptr = 0;
        while (($ptr = $phpcsFile->findNext(T_FUNCTION, $ptr + 1)) !== false) {
            $funcNamePtr = $phpcsFile->findNext(T_STRING, $ptr + 1, null, false, $name, true);
            if ($funcNamePtr !== false) {
                if (empty($tokens[$ptr]['conditions']) || !isset($tokens[$ptr]['conditions'][T_CLASS])) {
                    return $ptr;
                }
            }
        }
        return false;
    }
    
    protected function findMethodDefinition(File $phpcsFile, $name, $className = null) {
        $tokens = $phpcsFile->getTokens();
        $ptr = 0;
        while (($ptr = $phpcsFile->findNext(T_FUNCTION, $ptr + 1)) !== false) {
            $methodNamePtr = $phpcsFile->findNext(T_STRING, $ptr + 1, null, false, $name, true);
            if ($methodNamePtr !== false) {
                $classCondition = $phpcsFile->getCondition($ptr, T_CLASS);
                if ($classCondition !== false) {
                    if ($className === null) return $ptr;
                    
                    $foundClassNamePtr = $phpcsFile->findNext(T_STRING, $classCondition + 1);
                    if ($foundClassNamePtr !== false && $tokens[$foundClassNamePtr]['content'] === $className) {
                        return $methodNamePtr;
                    }
                }
            }
        }
        return false;
    }
    
    protected function hasPermissionCallback(File $phpcsFile, $arrayStartPtr, $arrayEndPtr) {
        $tokens = $phpcsFile->getTokens();
        for ($i = ($arrayStartPtr + 1); $i < $arrayEndPtr; $i++) {
            if ($tokens[$i]['code'] === T_CONSTANT_ENCAPSED_STRING || $tokens[$i]['code'] === T_STRING) {
                $keyName = trim($tokens[$i]['content'], "'\"");
                if ($keyName === 'permission_callback') {
                    $arrow = $phpcsFile->findNext(T_DOUBLE_ARROW, $i + 1, $arrayEndPtr, false, null, true);
                    if ($arrow) {
                        $valueStart = $phpcsFile->findNext(T_WHITESPACE, $arrow + 1, $arrayEndPtr, true);
                        if ($valueStart !== false && !in_array($tokens[$valueStart]['code'], [T_NULL])) {
                            if ($tokens[$valueStart]['code'] === T_CONSTANT_ENCAPSED_STRING && trim($tokens[$valueStart]['content'], "'\"") === '') {
                                return false;
                            }
                            return true;
                        }
                    }
                    return false;
                }
            }
        }
        return false;
    }

    protected function getFunctionCallArguments(File $phpcsFile, $openParenthesisPtr) {
        $tokens = $phpcsFile->getTokens();
        if (!isset($tokens[$openParenthesisPtr]) || $tokens[$openParenthesisPtr]['code'] !== T_OPEN_PARENTHESIS) return [];
        if (!isset($tokens[$openParenthesisPtr]['parenthesis_closer'])) return []; 
        $closeParenthesisPtr = $tokens[$openParenthesisPtr]['parenthesis_closer'];
        $args = [];
        $currentArgTokens = [];
        $level = 0; 
        for ($i = ($openParenthesisPtr + 1); $i < $closeParenthesisPtr; $i++) {
            $tokenCode = $tokens[$i]['code'];
            if (in_array($tokenCode, [T_OPEN_PARENTHESIS, T_OPEN_SHORT_ARRAY, T_OPEN_CURLY_BRACKET, T_FN])) { 
                $level++;
            } elseif (in_array($tokenCode, [T_CLOSE_PARENTHESIS, T_CLOSE_SHORT_ARRAY, T_CLOSE_CURLY_BRACKET])) {
                if ($level > 0) $level--;
            }
            if ($tokenCode === T_COMMA && $level === 0) {
                if (!empty($currentArgTokens)) {
                    $args[] = $currentArgTokens;
                    $currentArgTokens = [];
                }
            } else {
                if ($tokenCode !== T_WHITESPACE) { 
                     $currentArgTokens[] = ['code' => $tokenCode, 'content' => $tokens[$i]['content'], 'ptr' => $i];
                }
            }
        }
        if (!empty($currentArgTokens)) {
            $args[] = $currentArgTokens;
        }
        return $args;
    }
    
    protected function getCallbackScopeDetails(File $phpcsFile, $callbackTokenPtr, $callbackArgTokens) {
        $tokens = $phpcsFile->getTokens();
        $firstCallbackToken = $tokens[$callbackTokenPtr];
        $callbackName = 'unknown_callback';

        if ($firstCallbackToken['code'] === T_CONSTANT_ENCAPSED_STRING) {
            $callbackName = trim($firstCallbackToken['content'], "'\"");
            $funcDefPtr = $this->findFunctionDefinition($phpcsFile, $callbackName);
            if ($funcDefPtr !== false && isset($tokens[$funcDefPtr]['scope_opener'])) {
                return ['name' => $callbackName, 'start' => $tokens[$funcDefPtr]['scope_opener'], 'end' => $tokens[$funcDefPtr]['scope_closer']];
            }
        } elseif ($firstCallbackToken['code'] === T_CLOSURE || $firstCallbackToken['code'] === T_FN) {
            $callbackName = 'closure/arrow_function';
            if (isset($firstCallbackToken['scope_opener'])) {
                return ['name' => $callbackName, 'start' => $firstCallbackToken['scope_opener'], 'end' => $firstCallbackToken['scope_closer']];
            }
        } elseif ($firstCallbackToken['code'] === T_ARRAY || $firstCallbackToken['code'] === T_OPEN_SHORT_ARRAY) {
            $callbackName = 'array_callback';
            $methodNameStr = '';
            $classNameStr = null;
            $arrayStart = ($firstCallbackToken['code'] === T_ARRAY) ? $phpcsFile->findNext(T_OPEN_PARENTHESIS, $callbackTokenPtr) : $callbackTokenPtr;
            $arrayArgs = $this->getFunctionCallArguments($phpcsFile, $arrayStart);
            
            if (count($arrayArgs) === 2) {
                 $classTokenInfo = $arrayArgs[0][0];
                 $methodTokenInfo = $arrayArgs[1][0];
                 if ($tokens[$methodTokenInfo['ptr']]['code'] === T_CONSTANT_ENCAPSED_STRING) {
                     $methodNameStr = trim($tokens[$methodTokenInfo['ptr']]['content'], "'\"");
                 }
                 if($tokens[$classTokenInfo['ptr']]['code'] === T_VARIABLE && $tokens[$classTokenInfo['ptr']]['content'] === '$this') {
                     $classOwner = $phpcsFile->getCondition($classTokenInfo['ptr'], T_CLASS);
                     if ($classOwner) {
                         $cnPtr = $phpcsFile->findNext(T_STRING, $classOwner + 1);
                         if($cnPtr) $classNameStr = $tokens[$cnPtr]['content'];
                     }
                 } elseif ($tokens[$classTokenInfo['ptr']]['code'] === T_CONSTANT_ENCAPSED_STRING) {
                     $classNameStr = trim($tokens[$classTokenInfo['ptr']]['content'], "'\"");
                 }
                 $callbackName = ($classNameStr ? $classNameStr.'::' : 'array::') . $methodNameStr;
            }
            $methodDefPtr = $this->findMethodDefinition($phpcsFile, $methodNameStr, $classNameStr);
            if ($methodDefPtr !== false && isset($tokens[$methodDefPtr]['scope_opener'])) {
                return ['name' => $callbackName, 'start' => $tokens[$methodDefPtr]['scope_opener'], 'end' => $tokens[$methodDefPtr]['scope_closer']];
            }
        }
        return false;
    }

    protected function isCriticalFunctionContext(File $phpcsFile, $functionTokenPtr, $superglobalInvolved = null) {
        if ($functionTokenPtr === false) {
            return ($superglobalInvolved === '$_POST' || $superglobalInvolved === '$_REQUEST');
        }
        $tokens = $phpcsFile->getTokens();
        $functionName = 'closure/arrow_function';

        if ($tokens[$functionTokenPtr]['code'] === T_FUNCTION) {
            $functionNamePtr = $phpcsFile->findNext(T_STRING, $functionTokenPtr + 1);
            if ($functionNamePtr !== false) {
                $functionName = $tokens[$functionNamePtr]['content'];
            }
        }

        foreach ($this->passwordRelatedFunctions as $passwordFunctionKeyword) {
            if (stripos($functionName, $passwordFunctionKeyword) !== false) {
                return true;
            }
        }
        
        if (isset($tokens[$functionTokenPtr]['scope_opener']) && isset($tokens[$functionTokenPtr]['scope_closer'])) {
            $scopeStart = $tokens[$functionTokenPtr]['scope_opener'];
            $scopeEnd = $tokens[$functionTokenPtr]['scope_closer'];
            for ($i = ($scopeStart + 1); $i < $scopeEnd; $i++) {
                if ($tokens[$i]['code'] === T_STRING && 
                    ($tokens[$i]['content'] === 'wp_set_password' || in_array($tokens[$i]['content'], $this->criticalSecurityFunctions))
                ) {
                    return true;
                }
            }
        }
        return false;
    }
}