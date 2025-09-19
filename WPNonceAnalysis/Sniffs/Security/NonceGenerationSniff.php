<?php
/**
 * Checks for proper nonce generation in forms and AJAX requests.
 * * This enhanced sniff detects missing nonce generation in various WordPress contexts
 * including forms, AJAX handlers, and REST API endpoints.
 */
namespace PHP_CodeSniffer\Standards\WPNonceAnalysis\Sniffs\Security;

use PHP_CodeSniffer\Sniffs\Sniff;
use PHP_CodeSniffer\Files\File;

class NonceGenerationSniff implements Sniff
{
    /**
     * A list of form-related functions that should include nonce generation in their callbacks.
     * @var array
     */
    private $formFunctions = [
        'add_meta_box', 'add_settings_field', 'add_settings_section',
        'add_options_page', 'add_menu_page', 'add_submenu_page',
    ];
    
    /**
     * A list of AJAX/Admin Post action prefixes.
     * @var array
     */
    private $ajaxActionPrefixes = ['wp_ajax_', 'wp_ajax_nopriv_', 'admin_post_', 'admin_post_nopriv_'];
    
    /**
     * A list of REST API-related functions.
     * @var array
     */
    private $restApiFunctions = ['register_rest_route'];
    
    /**
     * A list of nonce generation functions.
     * @var array
     */
    private $nonceGenerationFunctions = ['wp_nonce_field', 'wp_create_nonce', 'wp_nonce_url'];
    
    /**
     * Functions that may contain nonce data in their arguments.
     * @var array
     */
    private $functionsThatMayContainNonceInArgs = ['wp_localize_script', 'wp_add_inline_script'];
    
    /**
     * Returns the token types that this sniff is interested in.
     * @return array
     */
    public function register()
    {
        return [T_STRING];
    }
    
    /**
     * Processes this sniff when one of its tokens is encountered.
     * @param \PHP_CodeSniffer\Files\File $phpcsFile The file being scanned.
     * @param int                         $stackPtr  The position of the current token.
     * @return void
     */
    public function process(File $phpcsFile, $stackPtr)
    {
        $tokens = $phpcsFile->getTokens();
        $content = $tokens[$stackPtr]['content'];
        
        $nextNonWhitespace = $phpcsFile->findNext(T_WHITESPACE, ($stackPtr + 1), null, true);
        if ($nextNonWhitespace === false || $tokens[$nextNonWhitespace]['code'] !== T_OPEN_PARENTHESIS) {
            return;
        }

        if (in_array($content, $this->formFunctions)) {
            $this->checkCallbackForNonceGeneration($phpcsFile, $stackPtr, 'Form-related callback for %s');
            return;
        }
        
        if ($content === 'add_action') {
            $this->checkAjaxOrAdminPostActionCallback($phpcsFile, $stackPtr);
            return;
        }
        
        if (in_array($content, $this->restApiFunctions)) {
            $this->checkRestApiRouteCallback($phpcsFile, $stackPtr);
            return;
        }
        
        if (in_array($content, $this->functionsThatMayContainNonceInArgs)) {
            $this->checkFunctionArgumentsForNonceData($phpcsFile, $stackPtr);
            return;
        }
    }

    protected function checkCallbackForNonceGeneration(File $phpcsFile, $stackPtr, $message)
    {
        $tokens = $phpcsFile->getTokens();
        $functionName = $tokens[$stackPtr]['content'];
        
        $openParenthesis = $phpcsFile->findNext(T_WHITESPACE, ($stackPtr + 1), null, true);
        if ($openParenthesis === false) return;
        $closeParenthesis = $tokens[$openParenthesis]['parenthesis_closer'];

        $callbackTokenPtr = $this->findCallableParameter($phpcsFile, $openParenthesis + 1, $closeParenthesis);

        if ($callbackTokenPtr === false) {
            $potentialClosurePtr = $phpcsFile->findNext(T_CLOSURE, ($closeParenthesis + 1), null, false, null, true);
            if ($potentialClosurePtr !== false && isset($tokens[$potentialClosurePtr]['scope_opener'])) {
                $callbackTokenPtr = $potentialClosurePtr;
            } else {
                return;
            }
        }
        
        $callbackScope = $this->getCallbackScope($phpcsFile, $callbackTokenPtr);

        if ($callbackScope && !$this->checkForNonceGeneration($phpcsFile, $callbackScope['start'], $callbackScope['end'])) {
            $phpcsFile->addWarning(
                sprintf($message, $functionName),
                $stackPtr,
                'MissingNonceGenerationInCallback'
            );
        }
    }
    
    protected function checkAjaxOrAdminPostActionCallback(File $phpcsFile, $stackPtr)
    {
        $tokens = $phpcsFile->getTokens();
        
        $openParenthesis = $phpcsFile->findNext(T_WHITESPACE, ($stackPtr + 1), null, true);
        if ($openParenthesis === false) return;
        
        $args = $this->getFunctionCallArguments($phpcsFile, $openParenthesis);
        if (!isset($args[0]) || empty($args[0]) || $tokens[$args[0][0]['ptr']]['code'] !== T_CONSTANT_ENCAPSED_STRING) return;
        
        $hookName = trim($tokens[$args[0][0]['ptr']]['content'], "'\"");
        
        $isRelevantAction = false;
        foreach ($this->ajaxActionPrefixes as $prefix) {
            if (strpos($hookName, $prefix) === 0) {
                $isRelevantAction = true;
                break;
            }
        }
        
        if (!$isRelevantAction) return;
        if (!isset($args[1]) || empty($args[1])) return;

        $callbackTokenPtr = $args[1][0]['ptr'];
        
        $callbackScope = $this->getCallbackScope($phpcsFile, $callbackTokenPtr);
        
        if ($callbackScope) {
            // REFINEMENT: Only warn if the scope appears to output HTML but doesn't generate a nonce.
            $outputsHtml = $this->scopeOutputsHtml($phpcsFile, $callbackScope['start'], $callbackScope['end']);
            $generatesNonce = $this->checkForNonceGeneration($phpcsFile, $callbackScope['start'], $callbackScope['end']);

            if ($outputsHtml && !$generatesNonce) {
                $phpcsFile->addWarning(
                    'The callback for AJAX/admin_post action %s appears to output HTML but does not generate a nonce. If this HTML contains forms or action links, they may be vulnerable to CSRF.',
                    $stackPtr,
                    'MissingNonceGenerationInAjaxHtmlOutput',
                    [$hookName]
                );
            }
        }
    }
    
    protected function checkRestApiRouteCallback(File $phpcsFile, $stackPtr)
    {
        $tokens = $phpcsFile->getTokens();
        $openParenthesis = $phpcsFile->findNext(T_WHITESPACE, ($stackPtr + 1), null, true);
        if ($openParenthesis === false) return;
        
        $args = $this->getFunctionCallArguments($phpcsFile, $openParenthesis);
        if (!isset($args[2]) || empty($args[2])) return;

        $routeArgsTokenPtr = $args[2][0]['ptr'];
        if (!in_array($tokens[$routeArgsTokenPtr]['code'], [T_ARRAY, T_OPEN_SHORT_ARRAY, T_VARIABLE])) return;
        if ($tokens[$routeArgsTokenPtr]['code'] === T_VARIABLE) return;

        $arrayStartPtr = ($tokens[$routeArgsTokenPtr]['code'] === T_ARRAY) ? $phpcsFile->findNext(T_OPEN_PARENTHESIS, $routeArgsTokenPtr + 1, null, true) : $routeArgsTokenPtr;
        $arrayEndPtr = $tokens[$arrayStartPtr]['parenthesis_closer'] ?? $tokens[$arrayStartPtr]['bracket_closer'] ?? null;
        if ($arrayStartPtr === false || $arrayEndPtr === null) return;

        $actualCallbackPtr = false;
        $keyPtr = $arrayStartPtr;
        while (($keyPtr = $phpcsFile->findNext(T_CONSTANT_ENCAPSED_STRING, ($keyPtr + 1), $arrayEndPtr)) !== false) {
            if (trim($tokens[$keyPtr]['content'], "'\"") === 'callback') {
                $arrowPtr = $phpcsFile->findNext(T_DOUBLE_ARROW, ($keyPtr + 1), $arrayEndPtr);
                if ($arrowPtr !== false) {
                    $actualCallbackPtr = $phpcsFile->findNext(T_WHITESPACE, $arrowPtr + 1, null, true);
                    break;
                }
            }
        }
        
        if ($actualCallbackPtr === false) return;

        $callbackScope = $this->getCallbackScope($phpcsFile, $actualCallbackPtr);
        
        if ($callbackScope) {
            $outputsHtml = $this->scopeOutputsHtml($phpcsFile, $callbackScope['start'], $callbackScope['end']);
            $generatesNonce = $this->checkForNonceGeneration($phpcsFile, $callbackScope['start'], $callbackScope['end']);

            if ($outputsHtml && !$generatesNonce) {
                $phpcsFile->addWarning(
                    'The callback for this REST API route appears to output HTML but does not generate a nonce. If this HTML requires CSRF protection for subsequent actions, a nonce should be included.',
                    $stackPtr,
                    'MissingNonceGenerationInRestApiHtmlOutput'
                );
            }
        }
    }
    
    protected function checkFunctionArgumentsForNonceData(File $phpcsFile, $stackPtr)
    {
        $tokens = $phpcsFile->getTokens();
        $functionName = $tokens[$stackPtr]['content'];

        $openParenthesis = $phpcsFile->findNext(T_WHITESPACE, ($stackPtr + 1), null, true);
        if ($openParenthesis === false) return;
        
        $args = $this->getFunctionCallArguments($phpcsFile, $openParenthesis);

        if ($functionName === 'wp_localize_script') {
            if (!isset($args[2])) return;

            $dataArrayTokens = $args[2];
            $dataArrayPtrStart = $dataArrayTokens[0]['ptr'];
            $dataArrayEnd = $tokens[$dataArrayPtrStart]['parenthesis_closer'] ?? $tokens[$dataArrayPtrStart]['bracket_closer'] ?? end($dataArrayTokens)['ptr'];

            $containsAjaxUrlOrAction = false;
            $nonceDataFound = false;

            for ($i = $dataArrayPtrStart; $i <= $dataArrayEnd; $i++) {
                if ($tokens[$i]['code'] === T_CONSTANT_ENCAPSED_STRING) {
                    $keyOrValue = strtolower(trim($tokens[$i]['content'], "'\""));
                    if (strpos($keyOrValue, 'ajax') !== false || strpos($keyOrValue, 'url') !== false || strpos($keyOrValue, 'action') !== false) {
                        $containsAjaxUrlOrAction = true;
                    }
                }
                if ($tokens[$i]['code'] === T_STRING && $tokens[$i]['content'] === 'wp_create_nonce') {
                    $nonceDataFound = true;
                }
            }
            
            if ($containsAjaxUrlOrAction && !$nonceDataFound) {
                $phpcsFile->addWarning(
                    'Script localization via %s contains AJAX URLs or actions but does not appear to include a nonce generated by wp_create_nonce.',
                    $stackPtr, 'ScriptLocalizationPotentiallyMissingNonce', [$functionName]
                );
            }
        }
    }

    protected function findCallableParameter(File $phpcsFile, $startPtr, $endPtr) {
        $tokens = $phpcsFile->getTokens();
        $searchTokens = [T_CONSTANT_ENCAPSED_STRING, T_ARRAY, T_OPEN_SHORT_ARRAY, T_CLOSURE, T_VARIABLE];
        
        for ($i = $startPtr; $i < $endPtr; $i++) {
            if (in_array($tokens[$i]['code'], $searchTokens)) {
                return $i;
            }
        }
        return false;
    }
    
    protected function getCallbackScope(File $phpcsFile, $callbackTokenPtr)
    {
        $tokens = $phpcsFile->getTokens();
        $callbackToken = $tokens[$callbackTokenPtr];

        if ($callbackToken['code'] === T_CONSTANT_ENCAPSED_STRING) {
            $callbackName = trim($callbackToken['content'], "'\"");
            $functionDefPtr = $this->findFunctionDefinition($phpcsFile, $callbackName);
            if ($functionDefPtr !== false && isset($tokens[$functionDefPtr]['scope_opener'])) {
                return ['start' => $tokens[$functionDefPtr]['scope_opener'], 'end' => $tokens[$functionDefPtr]['scope_closer']];
            }
        } elseif ($callbackToken['code'] === T_ARRAY || $callbackToken['code'] === T_OPEN_SHORT_ARRAY) {
            $arrayStart = ($callbackToken['code'] === T_ARRAY) ? $phpcsFile->findNext(T_OPEN_PARENTHESIS, $callbackTokenPtr + 1) : $callbackTokenPtr;
            $arrayEnd = $tokens[$arrayStart]['parenthesis_closer'] ?? $tokens[$arrayStart]['bracket_closer'] ?? null;
            if ($arrayEnd === null) return false;
            
            $args = $this->getFunctionCallArguments($phpcsFile, $arrayStart);
            if (count($args) !== 2) return false;

            $classToken = $args[0][0];
            $methodToken = $args[1][0];

            if ($tokens[$methodToken['ptr']]['code'] !== T_CONSTANT_ENCAPSED_STRING) return false;
            $methodName = trim($tokens[$methodToken['ptr']]['content'], "'\"");

            $className = null;
            if ($tokens[$classToken['ptr']]['code'] === T_VARIABLE && $tokens[$classToken['ptr']]['content'] === '$this') {
                $classOwner = $phpcsFile->getCondition($callbackTokenPtr, T_CLASS);
                if ($classOwner !== false) {
                     $classNamePtr = $phpcsFile->findNext(T_STRING, $classOwner + 1);
                     if ($classNamePtr !== false) $className = $tokens[$classNamePtr]['content'];
                }
            } elseif ($tokens[$classToken['ptr']]['code'] === T_CONSTANT_ENCAPSED_STRING) {
                $className = trim($tokens[$classToken['ptr']]['content'], "'\"");
            }
            
            if ($className !== null && $methodName !== '') {
                $methodDefPtr = $this->findMethodDefinition($phpcsFile, $methodName, $className);
                if ($methodDefPtr !== false && isset($tokens[$methodDefPtr]['scope_opener'])) {
                    return ['start' => $tokens[$methodDefPtr]['scope_opener'], 'end' => $tokens[$methodDefPtr]['scope_closer']];
                }
            }
        } elseif ($callbackToken['code'] === T_CLOSURE) {
            if (isset($callbackToken['scope_opener'])) {
                return ['start' => $callbackToken['scope_opener'], 'end' => $callbackToken['scope_closer']];
            }
        }
        return false;
    }
    
    protected function findFunctionDefinition(File $phpcsFile, $functionName)
    {
        $tokens = $phpcsFile->getTokens();
        $functionPtr = 0;
        
        while (($functionPtr = $phpcsFile->findNext(T_FUNCTION, ($functionPtr + 1))) !== false) {
            $namePtr = $phpcsFile->findNext(T_STRING, ($functionPtr + 1));
            if ($namePtr !== false && $tokens[$namePtr]['content'] === $functionName) {
                if (empty($tokens[$functionPtr]['conditions']) || !in_array(T_CLASS, $tokens[$functionPtr]['conditions'])) {
                    return $functionPtr;
                }
            }
        }
        return false;
    }
    
    protected function findMethodDefinition(File $phpcsFile, $methodName, $className = null)
    {
        $tokens = $phpcsFile->getTokens();
        $methodPtr = 0;
        
        while (($methodPtr = $phpcsFile->findNext(T_FUNCTION, ($methodPtr + 1))) !== false) {
            $namePtr = $phpcsFile->findNext(T_STRING, ($methodPtr + 1));
            if ($namePtr !== false && $tokens[$namePtr]['content'] === $methodName) {
                $classContextPtr = $phpcsFile->getCondition($methodPtr, T_CLASS);
                if ($classContextPtr !== false) {
                    if ($className === null) return $methodPtr;
                    
                    $foundClassNamePtr = $phpcsFile->findNext(T_STRING, ($classContextPtr + 1));
                    if ($foundClassNamePtr !== false && $tokens[$foundClassNamePtr]['content'] === $className) {
                        return $methodPtr;
                    }
                }
            }
        }
        return false;
    }
    
    protected function checkForNonceGeneration(File $phpcsFile, $startPtr, $endPtr)
    {
        $tokens = $phpcsFile->getTokens();
        for ($i = ($startPtr + 1); $i < $endPtr; $i++) {
            if ($tokens[$i]['code'] === T_STRING && in_array($tokens[$i]['content'], $this->nonceGenerationFunctions)) {
                return true;
            }
        }
        return false;
    }

    /**
     * Checks if a given scope appears to output HTML.
     * @param \PHP_CodeSniffer\Files\File $phpcsFile The file being scanned.
     * @param int                         $startPtr  The position to start looking from (scope opener).
     * @param int                         $endPtr    The position to stop looking at (scope closer).
     * @return bool
     */
    protected function scopeOutputsHtml(File $phpcsFile, $startPtr, $endPtr)
    {
        $tokens = $phpcsFile->getTokens();
        for ($i = ($startPtr + 1); $i < $endPtr; $i++) {
            if (in_array($tokens[$i]['code'], [T_ECHO, T_PRINT, T_EXIT])) {
                return true; // Simple heuristic: any output might be HTML.
            }
            if ($tokens[$i]['code'] === T_CONSTANT_ENCAPSED_STRING) {
                // More complex heuristic: check if the string contains HTML tags.
                if (preg_match('/<[a-z][\s\S]*>/i', $tokens[$i]['content'])) {
                    return true;
                }
            }
            if ($tokens[$i]['code'] === T_INLINE_HTML) {
                return true;
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
}
