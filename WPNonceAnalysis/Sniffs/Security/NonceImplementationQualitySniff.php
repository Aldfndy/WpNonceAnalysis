<?php
/**
 * Enhanced checks for the quality of nonce implementations.
 * * This sniff analyzes nonce action specificity, capability checks pairing,
 * and other quality aspects of nonce implementation.
 */
namespace PHP_CodeSniffer\Standards\WPNonceAnalysis\Sniffs\Security;

use PHP_CodeSniffer\Sniffs\Sniff;
use PHP_CodeSniffer\Files\File;

class NonceImplementationQualitySniff implements Sniff
{
    /**
     * A list of generic nonce action names that should be avoided.
     *
     * @var array
     */
    protected $genericNonceActions = [
        'nonce',
        'wp_nonce',
        'my_nonce',
        'plugin_nonce',
        'theme_nonce',
        'action',
        'security',
        'token',
        'csrf',
        'verify',
        'ajax',
        'ajax_nonce',
        'ic_ajax',
    ];
    
    /**
     * A list of capability check functions.
     *
     * @var array
     */
    protected $capabilityCheckFunctions = [
        'current_user_can',
        'current_user_can_for_blog',
        'author_can',
        'user_can',
        'is_super_admin',
        'is_admin', // Note: is_admin() is a context check, not a true capability check.
        'map_meta_cap',
    ];
    
    /**
     * A list of nonce verification functions.
     *
     * @var array
     */
    protected $nonceVerificationFunctions = [
        'wp_verify_nonce',
        'check_admin_referer',
        'check_ajax_referer',
    ];

    /**
     * A list of function names that indicate password-related operations.
     * These are used to identify sensitive contexts.
     *
     * @var array
     */
    protected $passwordRelatedFunctions = [
        'password_reset',
        'reset_password',
        'change_password',
        'update_password',
        'set_password', // WordPress function wp_set_password is more specific
    ];

    /**
     * Functions that halt execution.
     * @var array
     */
    protected $exitFunctions = [
        'wp_die',
        'wp_send_json_error',
        'wp_send_json_success', // Also halts execution.
        'die',
        'exit',
    ];
    
    /**
     * Returns the token types that this sniff is interested in.
     *
     * @return array
     */
    public function register()
    {
        // We are interested in function calls (T_STRING) and function definitions (T_FUNCTION)
        return [T_STRING, T_FUNCTION];
    }
    
    /**
     * Processes this sniff when one of its tokens is encountered.
     *
     * @param \PHP_CodeSniffer\Files\File $phpcsFile The file being scanned.
     * @param int                         $stackPtr  The position of the current token.
     *
     * @return void
     */
    public function process(File $phpcsFile, $stackPtr)
    {
        $tokens = $phpcsFile->getTokens();
        $currentToken = $tokens[$stackPtr];
        $content = $currentToken['content'];
        
        // Check for password-related function definitions
        if ($currentToken['code'] === T_FUNCTION) {
            $this->checkPasswordRelatedFunction($phpcsFile, $stackPtr);
            // No return here, as a function definition itself isn't a call to check for other issues.
        }
        
        // Only proceed with other checks if it's a T_STRING (likely a function call)
        if ($currentToken['code'] !== T_STRING) {
            return;
        }

        // Ensure it's a function call, not just a string token.
        $nextNonWhitespace = $phpcsFile->findNext(T_WHITESPACE, ($stackPtr + 1), null, true);
        if ($nextNonWhitespace === false || $tokens[$nextNonWhitespace]['code'] !== T_OPEN_PARENTHESIS) {
            return;
        }
        
        // Check nonce generation functions (wp_create_nonce, wp_nonce_url, wp_nonce_field)
        // for action specificity and dynamic data.
        if ($content === 'wp_create_nonce' || $content === 'wp_nonce_url' || $content === 'wp_nonce_field') {
            $this->checkNonceActionSpecificity($phpcsFile, $stackPtr);
            $this->checkNonceActionDynamicData($phpcsFile, $stackPtr);
        }
        
        // Check nonce verification functions (wp_verify_nonce, check_admin_referer, check_ajax_referer)
        if (in_array($content, $this->nonceVerificationFunctions)) {
            $this->checkCapabilityPairing($phpcsFile, $stackPtr);
            $this->checkNonceVerificationErrorHandling($phpcsFile, $stackPtr);
            $this->checkNonceActionSecurity($phpcsFile, $stackPtr); // Checks the *action* argument's quality

            // Specifically check for hardcoded nonce *values* if it's wp_verify_nonce
            if ($content === 'wp_verify_nonce') {
                $this->checkHardcodedNonceValues($phpcsFile, $stackPtr);
            }
        }
    }

    /**
     * Check if a function is related to password operations and has proper security.
     *
     * @param \PHP_CodeSniffer\Files\File $phpcsFile The file being scanned.
     * @param int                         $functionTokenPtr  The position of the T_FUNCTION token.
     *
     * @return void
     */
    protected function checkPasswordRelatedFunction(File $phpcsFile, $functionTokenPtr)
    {
        $tokens = $phpcsFile->getTokens();
        
        // Get function name
        $functionNamePtr = $phpcsFile->findNext(T_STRING, $functionTokenPtr + 1);
        if ($functionNamePtr === false) {
            return;
        }
        
        $functionName = $tokens[$functionNamePtr]['content'];
        
        // Check if this is a password-related function name
        $isPasswordFunctionByName = false;
        foreach ($this->passwordRelatedFunctions as $passwordFunctionKeyword) {
            if (stripos($functionName, $passwordFunctionKeyword) !== false) {
                $isPasswordFunctionByName = true;
                break;
            }
        }
        
        // Get function scope
        if (!isset($tokens[$functionTokenPtr]['scope_opener']) || !isset($tokens[$functionTokenPtr]['scope_closer'])) {
            return;
        }
        
        $functionStart = $tokens[$functionTokenPtr]['scope_opener'];
        $functionEnd = $tokens[$functionTokenPtr]['scope_closer'];
        
        // Check for wp_set_password usage within this function
        $wpSetPasswordUsed = false;
        for ($i = ($functionStart + 1); $i < $functionEnd; $i++) {
            if ($tokens[$i]['code'] === T_STRING && $tokens[$i]['content'] === 'wp_set_password') {
                $wpSetPasswordUsed = true;
                break;
            }
        }
        
        // If it's not a password-related function by name and doesn't use wp_set_password, exit.
        if (!$isPasswordFunctionByName && !$wpSetPasswordUsed) {
            return;
        }
        
        // At this point, it's a security-critical context (password related).
        // Now, check for nonce verification within its scope.
        $nonceVerified = false;
        $nonceVerificationPtr = false; // Pointer to the nonce verification function call
        
        for ($i = ($functionStart + 1); $i < $functionEnd; $i++) {
            if ($tokens[$i]['code'] === T_STRING && in_array($tokens[$i]['content'], $this->nonceVerificationFunctions)) {
                // Ensure it's a function call
                $openParen = $phpcsFile->findNext(T_WHITESPACE, ($i + 1), null, true);
                if ($openParen !== false && $tokens[$openParen]['code'] === T_OPEN_PARENTHESIS) {
                    $nonceVerified = true;
                    $nonceVerificationPtr = $i;
                    break;
                }
            }
        }
        
        if (!$nonceVerified) {
            $phpcsFile->addError(
                'Password-related function "%s" (or function using wp_set_password) lacks nonce verification. This is a critical security issue.',
                $functionTokenPtr,
                'PasswordFunctionWithoutNonceVerification',
                [$functionName]
            );
            return; // Stop further checks if nonce isn't even verified.
        }
        
        // Nonce is verified, now check its quality for this critical context.
        // Check nonce action specificity for the found nonce verification call
        $openParenthesis = $phpcsFile->findNext(T_WHITESPACE, $nonceVerificationPtr + 1, null, true);
        // $openParenthesis is known to be T_OPEN_PARENTHESIS from above check
        
        // The second parameter to nonce verification functions is usually the action.
        $args = $this->getFunctionCallArguments($phpcsFile, $openParenthesis);
        $actionArgIndex = ($tokens[$nonceVerificationPtr]['content'] === 'wp_verify_nonce') ? 1 : 0;

        if (isset($args[$actionArgIndex]) && !empty($args[$actionArgIndex])) {
            $actionToken = $tokens[$args[$actionArgIndex][0]['ptr']]; // First token of the action argument
            if ($actionToken['code'] === T_CONSTANT_ENCAPSED_STRING) {
                $action = trim($actionToken['content'], "'\"");
                if (in_array(strtolower($action), $this->genericNonceActions)) {
                    $phpcsFile->addError(
                        'Password-related function "%s" uses nonce verification with a generic action name "%s". Use specific, unique action names for critical operations.',
                        $nonceVerificationPtr, // Report on the verification call
                        'PasswordFunctionWithGenericNonceAction',
                        [$functionName, $action]
                    );
                }
            } else {
                 $phpcsFile->addError(
                    'Password-related function "%s" uses nonce verification, but the action name could not be determined or is not a string literal. Ensure a specific string action is used.',
                    $nonceVerificationPtr,
                    'PasswordFunctionNonceActionUnclear',
                    [$functionName]
                );
            }
        } else {
             $phpcsFile->addError(
                'Password-related function "%s" uses nonce verification (%s), but its action parameter could not be properly analyzed. Ensure it uses a specific string action.',
                $nonceVerificationPtr,
                'PasswordFunctionNonceActionMissing',
                [$functionName, $tokens[$nonceVerificationPtr]['content']]
            );
        }
        
        // Check for capability checks within the function scope
        $hasProperCapabilityCheck = false;
        for ($i = ($functionStart + 1); $i < $functionEnd; $i++) {
            if ($tokens[$i]['code'] === T_STRING && 
                in_array($tokens[$i]['content'], $this->capabilityCheckFunctions) &&
                $tokens[$i]['content'] !== 'is_admin') { // is_admin is not a sufficient capability check
                $hasProperCapabilityCheck = true;
                break;
            }
        }
        
        if (!$hasProperCapabilityCheck) {
            $phpcsFile->addError(
                'Password-related function "%s" lacks proper capability checks (e.g., current_user_can) alongside nonce verification. This is a critical security issue.',
                $functionTokenPtr,
                'PasswordFunctionWithoutProperCapabilityCheck',
                [$functionName]
            );
        }
    }
    
    /**
     * Check if nonce actions are specific enough.
     * Applies to wp_create_nonce, wp_nonce_url, wp_nonce_field.
     *
     * @param \PHP_CodeSniffer\Files\File $phpcsFile The file being scanned.
     * @param int                         $stackPtr  The position of the T_STRING (nonce generation function name) token.
     *
     * @return void
     */
    protected function checkNonceActionSpecificity(File $phpcsFile, $stackPtr)
    {
        $tokens = $phpcsFile->getTokens();
        
        // Find the opening parenthesis of the function call.
        $openParenthesis = $phpcsFile->findNext(T_WHITESPACE, $stackPtr + 1, null, true);
        // This should have been checked in process(), but being defensive.
        if ($openParenthesis === false || $tokens[$openParenthesis]['code'] !== T_OPEN_PARENTHESIS) {
            return;
        }
        
        // The first parameter to these functions is the action.
        $args = $this->getFunctionCallArguments($phpcsFile, $openParenthesis);
        
        if (!isset($args[0]) || empty($args[0])) {
            $phpcsFile->addWarning(
                'Nonce generation function %s called without a specific action. Using default or empty actions is discouraged.',
                $stackPtr,
                'MissingNonceAction',
                [$tokens[$stackPtr]['content']]
            );
            return;
        }
        
        $actionToken = $tokens[$args[0][0]['ptr']]; // First token of the first argument.

        if ($actionToken['code'] === T_CONSTANT_ENCAPSED_STRING) {
            $action = trim($actionToken['content'], "'\"");
            
            if (empty($action) || $action === '-1') {
                 $phpcsFile->addWarning(
                    'Nonce action for %s is empty or default (-1). Use specific action names for better security.',
                    $stackPtr,
                    'EmptyOrDefaultNonceAction',
                    [$tokens[$stackPtr]['content']]
                );
            } elseif (in_array(strtolower($action), $this->genericNonceActions)) {
                $phpcsFile->addWarning(
                    'Nonce action "%s" for %s is too generic. Use specific action names for better security.',
                    $stackPtr,
                    'GenericNonceAction',
                    [$action, $tokens[$stackPtr]['content']]
                );
            } elseif (!preg_match('/[_-]/', $action) && !preg_match('/[0-9]/', $action) && count(explode(' ', $action)) < 2) {
                // If action is a single word without separators or numbers, it might be too simple.
                $phpcsFile->addWarning(
                    'Nonce action "%s" for %s is simple. Consider using more descriptive actions, possibly including object IDs or user-specific data, separated by underscores or hyphens.',
                    $stackPtr,
                    'SimpleNonceAction',
                    [$action, $tokens[$stackPtr]['content']]
                );
            }
        } elseif ($actionToken['code'] === T_VARIABLE) {
            // Action is a variable. This is potentially good (dynamic).
        } else {
            // Action is not a string literal or a simple variable (e.g., concatenation, function call).
        }
    }
    
    /**
     * Check if nonce actions include dynamic data.
     * Applies to wp_create_nonce, wp_nonce_url, wp_nonce_field.
     *
     * @param \PHP_CodeSniffer\Files\File $phpcsFile The file being scanned.
     * @param int                         $stackPtr  The position of the T_STRING (nonce generation function name) token.
     *
     * @return void
     */
    protected function checkNonceActionDynamicData(File $phpcsFile, $stackPtr)
    {
        $tokens = $phpcsFile->getTokens();
        $openParenthesis = $phpcsFile->findNext(T_WHITESPACE, $stackPtr + 1, null, true);
        if ($openParenthesis === false || $tokens[$openParenthesis]['code'] !== T_OPEN_PARENTHESIS) {
            return;
        }
        
        $args = $this->getFunctionCallArguments($phpcsFile, $openParenthesis);
        if (!isset($args[0]) || empty($args[0])) {
            return; // Already handled by checkNonceActionSpecificity
        }

        $actionArgTokens = $args[0]; // Array of tokens for the first argument
        $hasDynamicPart = false;
        $isSimpleString = true;

        foreach ($actionArgTokens as $tokenInfo) {
            $tokenCode = $tokenInfo['code'];
            if ($tokenCode === T_VARIABLE || 
                $tokenCode === T_STRING_CONCAT ||
                $tokenCode === T_ENCAPSED_AND_WHITESPACE
            ) {
                $hasDynamicPart = true;
                $isSimpleString = false;
                break;
            }
            if ($tokenCode === T_DOUBLE_QUOTED_STRING) {
                $isSimpleString = false; // Assume dynamic if double quoted for simplicity, could refine
                if (preg_match('/(?<!\\)\\\$/', $tokenInfo['content'])) {
                    $hasDynamicPart = true;
                    break;
                }
            }
            if ($tokenCode !== T_CONSTANT_ENCAPSED_STRING) {
                $isSimpleString = false; // If anything other than a single string literal, not simple.
            }
        }
        
        if (!$hasDynamicPart && $isSimpleString && $tokens[$actionArgTokens[0]['ptr']]['code'] === T_CONSTANT_ENCAPSED_STRING) {
            $phpcsFile->addWarning(
                'Nonce action for %s appears to be static. Consider incorporating dynamic data (like post IDs, user IDs, or other contextual identifiers) into nonce actions for enhanced security. This makes nonces more unique to specific operations.',
                $stackPtr,
                'StaticNonceAction',
                [$tokens[$stackPtr]['content']]
            );
        }
    }
    
    /**
     * Check if nonce verification is paired with capability checks.
     * Applies to wp_verify_nonce, check_admin_referer, check_ajax_referer.
     *
     * @param \PHP_CodeSniffer\Files\File $phpcsFile The file being scanned.
     * @param int                         $stackPtr  The position of the T_STRING (nonce verification function name) token.
     *
     * @return void
     */
    protected function checkCapabilityPairing(File $phpcsFile, $stackPtr)
    {
        $tokens = $phpcsFile->getTokens();
        
        $functionTokenPtr = $phpcsFile->getCondition($stackPtr, T_FUNCTION);
        if ($functionTokenPtr === false) {
            return;
        }
        
        if (!isset($tokens[$functionTokenPtr]['scope_opener']) || !isset($tokens[$functionTokenPtr]['scope_closer'])) {
            return;
        }
        
        $scopeStart = $tokens[$functionTokenPtr]['scope_opener'];
        $scopeEnd = $tokens[$functionTokenPtr]['scope_closer'];
        
        $hasProperCapabilityCheck = false;
        $usesIsAdmin = false;
        
        for ($i = ($scopeStart + 1); $i < $scopeEnd; $i++) {
            if ($tokens[$i]['code'] === T_STRING && in_array($tokens[$i]['content'], $this->capabilityCheckFunctions)) {
                 // Ensure it's a function call
                $openParen = $phpcsFile->findNext(T_WHITESPACE, ($i + 1), null, true);
                if ($openParen !== false && $tokens[$openParen]['code'] === T_OPEN_PARENTHESIS) {
                    if ($tokens[$i]['content'] === 'is_admin') {
                        $usesIsAdmin = true;
                    } else {
                        $hasProperCapabilityCheck = true;
                        break; 
                    }
                }
            }
        }
        
        if (!$hasProperCapabilityCheck) {
            $isCriticalContext = $this->isCriticalFunctionContext($phpcsFile, $functionTokenPtr);
            $verificationFuncName = $tokens[$stackPtr]['content'];

            if ($usesIsAdmin) {
                $message = 'Nonce verification (%s) is paired with is_admin(). While is_admin() checks context, it is NOT a substitute for a proper capability check (e.g., current_user_can()) to authorize the action.';
                $errorCode = 'ImproperCapabilityCheckWithIsAdmin';
                if ($isCriticalContext) {
                     $phpcsFile->addError($message . ' This is critical in sensitive operations.', $stackPtr, $errorCode.'Critical', [$verificationFuncName]);
                } else {
                     $phpcsFile->addWarning($message, $stackPtr, $errorCode, [$verificationFuncName]);
                }
            } else {
                $message = 'Nonce verification (%s) found without a corresponding capability check (e.g., current_user_can()) in the same scope. Always authorize actions after verifying nonces.';
                $errorCode = 'NonceWithoutCapabilityCheck';
                 if ($isCriticalContext) {
                     $phpcsFile->addError($message . ' This is critical in sensitive operations.', $stackPtr, $errorCode.'Critical', [$verificationFuncName]);
                } else {
                     $phpcsFile->addWarning($message, $stackPtr, $errorCode, [$verificationFuncName]);
                }
            }
        }
    }
    
    /**
     * Check if nonce verification includes proper error handling if the verification fails.
     * Applies to wp_verify_nonce, check_admin_referer, check_ajax_referer.
     *
     * @param \PHP_CodeSniffer\Files\File $phpcsFile The file being scanned.
     * @param int                         $stackPtr  The position of the T_STRING (nonce verification function name) token.
     *
     * @return void
     */
    protected function checkNonceVerificationErrorHandling(File $phpcsFile, $stackPtr)
    {
        $tokens = $phpcsFile->getTokens();
        $verificationFunctionName = $tokens[$stackPtr]['content'];

        $callOpenParen = $phpcsFile->findNext(T_WHITESPACE, $stackPtr + 1, null, true);
        if ($callOpenParen === false || $tokens[$callOpenParen]['code'] !== T_OPEN_PARENTHESIS) {
            return; // Not a function call.
        }
        $callCloseParen = $tokens[$callOpenParen]['parenthesis_closer'];

        // For check_admin_referer and check_ajax_referer, they die by default.
        // Only need to check error handling if their $die parameter is explicitly false.
        if ($verificationFunctionName === 'check_admin_referer' || $verificationFunctionName === 'check_ajax_referer') {
            $args = $this->getFunctionCallArguments($phpcsFile, $callOpenParen);
            // For check_admin_referer, $die is the 2nd param (index 1).
            // For check_ajax_referer, $die is the 3rd param (index 2).
            $dieParameterIndex = ($verificationFunctionName === 'check_admin_referer') ? 1 : 2;

            if (isset($args[$dieParameterIndex]) && !empty($args[$dieParameterIndex])) {
                $firstTokenOfDieArgPtr = $args[$dieParameterIndex][0]['ptr'];
                if ($tokens[$firstTokenOfDieArgPtr]['code'] === T_FALSE) {
                    // $die is explicitly false, proceed to check handling like wp_verify_nonce.
                } else {
                    // $die is not explicitly false (could be true, a variable, or not set, which defaults to true).
                    // Assume it dies internally.
                    return;
                }
            }
        } else {
            // $die parameter not provided, defaults to true.
            return;
        }

        // --- Logic for wp_verify_nonce or check_*_referer with $die=false ---

        // 1. Check if the call is directly inside a condition that handles failure.
        //    e.g., if ( ! wp_verify_nonce(...) ) { exit_call(); }
        //    e.g., if ( wp_verify_nonce(...) === false ) { exit_call(); }
        $pointerBeforeCall = $phpcsFile->findPrevious(T_WHITESPACE, $stackPtr - 1, null, true);
        $isNegated = ($pointerBeforeCall !== false && $tokens[$pointerBeforeCall]['code'] === T_BOOLEAN_NOT);
        
        $ifConditionPtr = $phpcsFile->getCondition($stackPtr, T_IF); // Also finds elseif
        if ($ifConditionPtr !== false) {
            // Check if the nonce call is the main part of the condition
            $conditionOpen = $tokens[$ifConditionPtr]['parenthesis_opener'];
            $conditionClose = $tokens[$ifConditionPtr]['parenthesis_closer'];
            $mainConditionElementPtr = $phpcsFile->findNext(T_WHITESPACE, $conditionOpen + 1, $conditionClose, true);

            if ($mainConditionElementPtr === $pointerBeforeCall || $mainConditionElementPtr === $stackPtr) {
                 // The nonce call (possibly negated) is the condition.
                if (isset($tokens[$ifConditionPtr]['scope_opener'])) {
                    // If the condition is for failure (e.g. `!wp_verify_nonce` or `wp_verify_nonce(...) == false`),
                    // check for exit inside this `if` block.
                    // If the condition is for success (e.g. `wp_verify_nonce(...)`), check `else` block.
                    // This requires analyzing the condition structure, which can be complex.
                    // For now, a simplified check: does the `if` block itself contain an exit?
                    if ($this->scopeContainsExitCall($phpcsFile, $tokens[$ifConditionPtr]['scope_opener'], $tokens[$ifConditionPtr]['scope_closer'])) {
                        return; // Found exit call in the if block.
                    }
                    // Check for an `else` block if the `if` condition might have been for success.
                    $elsePtr = $phpcsFile->findNext(T_ELSE, $tokens[$ifConditionPtr]['scope_closer'] + 1, null, false, null, true);
                    if ($elsePtr !== false && isset($tokens[$elsePtr]['scope_opener'])) {
                         if ($this->scopeContainsExitCall($phpcsFile, $tokens[$elsePtr]['scope_opener'], $tokens[$elsePtr]['scope_closer'])) {
                            return; // Found exit call in the else block.
                        }
                    }
                     // If we are here, the `if` related to nonce didn't have a clear exit.
                }
            }
        }

        // 2. Check if the result is assigned to a variable, and that variable is then checked.
        //    e.g., $verified = wp_verify_nonce(...); if ( ! $verified ) { exit_call(); }
        $assignmentPtr = $phpcsFile->findPrevious(T_EQUAL, $stackPtr -1, null, false, null, true);
        if ($assignmentPtr !== false) {
            $varPtr = $phpcsFile->findPrevious(T_VARIABLE, $assignmentPtr -1, null, false, null, true);
            // Ensure this assignment is for our nonce call (crude check: $var = wp_verify_nonce)
            $valuePtr = $phpcsFile->findNext(T_WHITESPACE, $assignmentPtr + 1, null, true);
            if ($varPtr !== false && $valuePtr === $stackPtr) {
                $variableName = $tokens[$varPtr]['content'];
                // Search for an `if` statement that uses this variable.
                // This requires iterating forward from $callCloseParen.
                $searchStart = $callCloseParen + 1;
                $semicolonAfterAssignment = $phpcsFile->findNext(T_SEMICOLON, $callCloseParen, null, false, null, true);
                if ($semicolonAfterAssignment !== false) {
                    $searchStart = $semicolonAfterAssignment + 1;
                }


                // Limit search within the current function scope
                $funcEndPtr = $phpcsFile->getCondition($stackPtr, T_FUNCTION);
                $searchEnd = $phpcsFile->numTokens -1;
                if ($funcEndPtr !== false && isset($tokens[$funcEndPtr]['scope_closer'])) {
                    $searchEnd = $tokens[$funcEndPtr]['scope_closer'];
                }


                for ($i = $searchStart; $i < $searchEnd; $i++) {
                    if ($tokens[$i]['code'] === T_IF) {
                        $ifOpen = $tokens[$i]['parenthesis_opener'];
                        $ifClose = $tokens[$i]['parenthesis_closer'];
                        $usesVariable = false;
                        $isFailureCheck = false;

                        for ($j = ($ifOpen + 1); $j < $ifClose; $j++) {
                            if ($tokens[$j]['code'] === T_VARIABLE && $tokens[$j]['content'] === $variableName) {
                                $usesVariable = true;
                                // Check if it's a failure condition like `!$variableName` or `$variableName == false`
                                $tokenBeforeVar = $phpcsFile->findPrevious(T_WHITESPACE, $j - 1, $ifOpen, true);
                                if ($tokenBeforeVar !== false && $tokens[$tokenBeforeVar]['code'] === T_BOOLEAN_NOT) {
                                    $isFailureCheck = true;
                                    break;
                                }
                                $tokenAfterVar = $phpcsFile->findNext(T_WHITESPACE, $j + 1, $ifClose, true);
                                if ($tokenAfterVar !== false && $tokens[$tokenAfterVar]['code'] === T_IS_IDENTICAL) {
                                     $comparedTo = $phpcsFile->findNext(T_WHITESPACE, $tokenAfterVar + 1, $ifClose, true);
                                     if($comparedTo !== false && $tokens[$comparedTo]['code'] === T_FALSE) {
                                         $isFailureCheck = true;
                                         break;
                                     }
                                }
                                 if ($tokenAfterVar !== false && $tokens[$tokenAfterVar]['code'] === T_IS_EQUAL) { // == false
                                     $comparedTo = $phpcsFile->findNext(T_WHITESPACE, $tokenAfterVar + 1, $ifClose, true);
                                     if($comparedTo !== false && $tokens[$comparedTo]['code'] === T_FALSE) {
                                         $isFailureCheck = true;
                                         break;
                                     }
                                }
                                // If it's just `if ($variableName)` it's a success check.
                                if (!$isFailureCheck) { // If it's `if ($variableName)`
                                     // Look for exit in the `else` part of this `if`.
                                    $currentIfScopeCloser = $tokens[$i]['scope_closer'];
                                    $elsePtr = $phpcsFile->findNext(T_ELSE, $currentIfScopeCloser + 1, $searchEnd, false, null, true);
                                    if ($elsePtr !== false && isset($tokens[$elsePtr]['scope_opener'])) {
                                        if ($this->scopeContainsExitCall($phpcsFile, $tokens[$elsePtr]['scope_opener'], $tokens[$elsePtr]['scope_closer'])) {
                                            return; // Handled in else
                                        }
                                    }
                                }
                            }
                        }

                        if ($usesVariable && $isFailureCheck && isset($tokens[$i]['scope_opener'])) {
                            if ($this->scopeContainsExitCall($phpcsFile, $tokens[$i]['scope_opener'], $tokens[$i]['scope_closer'])) {
                                return; // Handled: variable checked and exit call found.
                            }
                        }
                        // Stop searching for `if`s if we go into a nested scope that's not an if related to our var.
                        if ($tokens[$i]['code'] === T_OPEN_CURLY_BRACKET && isset($tokens[$i]['scope_condition']) && $tokens[$i]['scope_condition'] !== $i) {
                            $i = $tokens[$i]['scope_closer'];
                        }
                    }
                }
            }
        }
        
        // If no proper handling is found:
        $isCriticalContext = $this->isCriticalFunctionContext($phpcsFile, $phpcsFile->getCondition($stackPtr, T_FUNCTION));
        $message = 'The result of %s should be checked, and execution should be halted (e.g., using wp_die()) if verification fails. Ensure the failure path is explicitly handled.';
        $errorCode = 'NonceVerificationResultNotHandled';
        if ($isCriticalContext) {
            $phpcsFile->addError($message . ' This is critical in sensitive operations.', $stackPtr, $errorCode.'Critical', [$verificationFunctionName]);
        } else {
            $phpcsFile->addWarning($message, $stackPtr, $errorCode, [$verificationFunctionName]);
        }
    }

    /**
     * Checks if a given scope contains an exit call (wp_die, exit, return etc.).
     *
     * @param \PHP_CodeSniffer\Files\File $phpcsFile The file being scanned.
     * @param int                         $scopeOpener Ptr to the scope opener token.
     * @param int                         $scopeCloser Ptr to the scope closer token.
     * @return bool
     */
    protected function scopeContainsExitCall(File $phpcsFile, $scopeOpener, $scopeCloser) {
        $tokens = $phpcsFile->getTokens();
        for ($i = ($scopeOpener + 1); $i < $scopeCloser; $i++) {
            if ($tokens[$i]['code'] === T_STRING && in_array($tokens[$i]['content'], $this->exitFunctions)) {
                return true; // Found a direct exit function call.
            }
            if ($tokens[$i]['code'] === T_RETURN) {
                // A return statement also effectively halts the current function's path.
                return true;
            }
            // Could also check for function calls that are known to wrap exit calls, but that's more complex.
        }
        return false;
    }
    
    /**
     * Check for hardcoded nonce values when wp_verify_nonce is used.
     *
     * @param \PHP_CodeSniffer\Files\File $phpcsFile The file being scanned.
     * @param int                         $stackPtr  The position of the T_STRING ('wp_verify_nonce') token.
     *
     * @return void
     */
    protected function checkHardcodedNonceValues(File $phpcsFile, $stackPtr)
    {
        $tokens = $phpcsFile->getTokens();
        
        $openParenthesis = $phpcsFile->findNext(T_WHITESPACE, $stackPtr + 1, null, true);
        if ($openParenthesis === false || $tokens[$openParenthesis]['code'] !== T_OPEN_PARENTHESIS) {
            return; 
        }
        
        $args = $this->getFunctionCallArguments($phpcsFile, $openParenthesis);
        if (!isset($args[0]) || empty($args[0])) {
            return; // No first parameter.
        }
        
        $firstParamTokenPtr = $args[0][0]['ptr']; // Pointer to the first token of the first argument.
        
        if ($tokens[$firstParamTokenPtr]['code'] === T_CONSTANT_ENCAPSED_STRING) {
            $phpcsFile->addError(
                'Hardcoded nonce value detected in wp_verify_nonce. The first argument (the nonce value to verify) must be dynamic (e.g., from user input like $_REQUEST[\'_wpnonce\']), not a fixed string.',
                $firstParamTokenPtr, 
                'HardcodedNonceValue'
            );
        }
    }

    /**
     * Check if nonce action (for verification functions) is secure enough for the context.
     * This primarily checks if generic actions are used in critical contexts.
     *
     * @param \PHP_CodeSniffer\Files\File $phpcsFile The file being scanned.
     * @param int                         $stackPtr  The position of the T_STRING (nonce verification function name) token.
     *
     * @return void
     */
    protected function checkNonceActionSecurity(File $phpcsFile, $stackPtr)
    {
        $tokens = $phpcsFile->getTokens();
        $verificationFunctionName = $tokens[$stackPtr]['content'];

        $openParenthesis = $phpcsFile->findNext(T_WHITESPACE, $stackPtr + 1, null, true);
        if ($openParenthesis === false || $tokens[$openParenthesis]['code'] !== T_OPEN_PARENTHESIS) {
            return;
        }
        
        $actionArgIndex = 0; 
        if ($verificationFunctionName === 'wp_verify_nonce') {
            $actionArgIndex = 1;
        }

        $args = $this->getFunctionCallArguments($phpcsFile, $openParenthesis);

        if (!isset($args[$actionArgIndex]) || empty($args[$actionArgIndex])) {
            return;
        }

        $firstTokenOfActionArgPtr = $args[$actionArgIndex][0]['ptr']; 
        
        if ($tokens[$firstTokenOfActionArgPtr]['code'] === T_CONSTANT_ENCAPSED_STRING) {
            $action = trim($tokens[$firstTokenOfActionArgPtr]['content'], "'\"");
            
            $functionContextTokenPtr = $phpcsFile->getCondition($stackPtr, T_FUNCTION);
            $isCriticalContext = $this->isCriticalFunctionContext($phpcsFile, $functionContextTokenPtr);

            if (in_array(strtolower($action), $this->genericNonceActions)) {
                if ($isCriticalContext) {
                    $phpcsFile->addError(
                        'Generic nonce action "%s" used with %s in a security-critical context (e.g., password change, user modification). Use specific, unique action names for such operations.',
                        $firstTokenOfActionArgPtr, 
                        'GenericNonceActionInCriticalContext',
                        [$action, $verificationFunctionName]
                    );
                }
            }
        }
    }
    
    /**
     * Helper to determine if the current function context is critical (e.g., password-related).
     */
    protected function isCriticalFunctionContext(File $phpcsFile, $functionTokenPtr) {
        if ($functionTokenPtr === false) {
            return false;
        }
        $tokens = $phpcsFile->getTokens();
        $functionNamePtr = $phpcsFile->findNext(T_STRING, $functionTokenPtr + 1);
        if ($functionNamePtr === false) {
            // Could be an anonymous function/closure
            return false; // Or decide if all closures in certain hooks are critical.
        }
        $functionName = $tokens[$functionNamePtr]['content'];

        foreach ($this->passwordRelatedFunctions as $passwordFunctionKeyword) {
            if (stripos($functionName, $passwordFunctionKeyword) !== false) {
                return true;
            }
        }
        
        if (isset($tokens[$functionTokenPtr]['scope_opener']) && isset($tokens[$functionTokenPtr]['scope_closer'])) {
            $scopeStart = $tokens[$functionTokenPtr]['scope_opener'];
            $scopeEnd = $tokens[$functionTokenPtr]['scope_closer'];
            for ($i = ($scopeStart + 1); $i < $scopeEnd; $i++) {
                if ($tokens[$i]['code'] === T_STRING && $tokens[$i]['content'] === 'wp_set_password') {
                    return true;
                }
            }
        }
        return false;
    }

    /**
     * Find where a variable is defined (simple local scope check).
     *
     * @param \PHP_CodeSniffer\Files\File $phpcsFile The file being scanned.
     * @param int                         $usageStackPtr  The position of the variable usage.
     * @param string                      $variableName The variable name (e.g., '$foo').
     *
     * @return int|false Pointer to the T_VARIABLE token at definition, or false.
     */
    protected function findVariableDefinition(File $phpcsFile, $usageStackPtr, $variableName)
    {
        $tokens = $phpcsFile->getTokens();
        
        $functionTokenPtr = $phpcsFile->getCondition($usageStackPtr, T_FUNCTION);
        $scopeStart = 0;
        if ($functionTokenPtr !== false && isset($tokens[$functionTokenPtr]['scope_opener'])) {
            $scopeStart = $tokens[$functionTokenPtr]['scope_opener'];
        }
        
        for ($i = ($usageStackPtr - 1); $i > $scopeStart; $i--) {
            if ($tokens[$i]['code'] === T_VARIABLE && $tokens[$i]['content'] === $variableName) {
                $nextToken = $phpcsFile->findNext(T_WHITESPACE, $i + 1, null, true);
                if ($nextToken !== false && $tokens[$nextToken]['code'] === T_EQUAL) {
                    return $i;
                }
            }
        }
        return false;
    }

    /**
     * Get arguments of a function call.
     * Each argument is an array of its constituent token details.
     * @param \PHP_CodeSniffer\Files\File $phpcsFile The file being scanned.
     * @param int                         $openParenthesisPtr Pointer to the T_OPEN_PARENTHESIS of the call.
     * @return array<int, array<int, array{code:int, content:string, ptr:int}>>
     */
    protected function getFunctionCallArguments(File $phpcsFile, $openParenthesisPtr) {
        $tokens = $phpcsFile->getTokens();
        if (!isset($tokens[$openParenthesisPtr]) || $tokens[$openParenthesisPtr]['code'] !== T_OPEN_PARENTHESIS) {
            return [];
        }
        if (!isset($tokens[$openParenthesisPtr]['parenthesis_closer'])) {
            return []; // Malformed or not a simple function call.
        }
        $closeParenthesisPtr = $tokens[$openParenthesisPtr]['parenthesis_closer'];
        $args = [];
        $currentArgTokens = [];
        $level = 0; 

        for ($i = ($openParenthesisPtr + 1); $i < $closeParenthesisPtr; $i++) {
            $tokenCode = $tokens[$i]['code'];
            // Handle nesting for arrays, closures, nested function calls.
            if (in_array($tokenCode, [T_OPEN_PARENTHESIS, T_OPEN_SHORT_ARRAY, T_OPEN_CURLY_BRACKET, T_FN])) { // T_FN for arrow functions
                $level++;
            } elseif (in_array($tokenCode, [T_CLOSE_PARENTHESIS, T_CLOSE_SHORT_ARRAY, T_CLOSE_CURLY_BRACKET])) {
                if ($level > 0) { // Only decrement if we are inside a nested structure for the current argument
                    $level--;
                }
            }

            if ($tokenCode === T_COMMA && $level === 0) {
                if (!empty($currentArgTokens)) {
                    $args[] = $currentArgTokens;
                    $currentArgTokens = [];
                }
            } else {
                if ($tokenCode !== T_WHITESPACE) { // Collect non-whitespace tokens.
                     $currentArgTokens[] = ['code' => $tokenCode, 'content' => $tokens[$i]['content'], 'ptr' => $i];
                }
            }
        }
        if (!empty($currentArgTokens)) {
            $args[] = $currentArgTokens;
        }
        return $args;
    }
}