<?php
/**
 * 请求场景识别器（通用性设计）
 *
 * 核心思想：WAF 不应该"认识"每个具体框架（WordPress/Laravel/ThinkPHP），
 * 而应识别请求的"语义场景"（登录/支付/搜索/上传/回调），并据此调整检测策略。
 *
 * 场景分三类：
 *   1. 高可信场景（HARD_SKIP）：POST 表单本身就是业务核心，任何特征拦截都会误伤
 *      → 登录、注册、找回密码、支付回调、表单提交
 *      → 跳过：CSRF、Bot、所有注入特征检测、参数污染、Content-Type 校验
 *      → 保留：速率限制、IP 封禁、Session 防护、文件上传、请求方法白名单
 *
 *   2. 敏感输入场景（SOFT_SKIP）：含富文本/HTML/代码，特征检测容易误判但不应完全跳过
 *      → 评论、搜索、富文本编辑、联系表单
 *      → 跳过：基于黑名单的关键字检测（SQLi/XSS 正则）
 *      → 保留：CSRF、Bot、结构化检测（JSON/XML 格式）、文件上传、速率限制
 *
 *   3. 普通场景（FULL_CHECK）：走完整 WAF 检测链
 *      → 静态资源、API、后台路径等
 *
 * 配置文件可覆盖：
 *   WAF_TRUSTED_PATHS    = ['/custom-login', '/api/payment/callback']
 *   WAF_SOFTSKIP_PATHS   = ['/forum/post', '/comment']
 *
 * 这是"白名单优先 + 场景化检测"的通用方案，适用于任意 PHP 应用。
 */
defined('ABSPATH') || exit;

class RequestContext
{
    /** 高可信场景：跳过所有特征检测，仅保留基础防护 */
    const SCENE_HARD_SKIP = 'hard_skip';
    /** 敏感输入场景：跳过黑名单关键字检测，保留结构化检测 */
    const SCENE_SOFT_SKIP = 'soft_skip';
    /** 普通场景：完整 WAF 检测 */
    const SCENE_FULL_CHECK = 'full_check';

    /** @var string|null 缓存当前请求场景 */
    private static $scene = null;

    /** @var array 高可信场景路径关键字（通用，不绑定具体框架） */
    private static $hardSkipPaths = [
        // 登录/注册/找回密码
        'login', 'signin', 'sign-in', 'sign_up', 'signup', 'sign-up',
        'register', 'registration', 'auth', 'my-account', 'account',
        'lostpassword', 'lost-password', 'resetpassword', 'reset-password',
        'wp-login.php', 'user-login', 'member-login', 'customer-login',
        // 支付回调（电商/订阅通用）
        'payment', 'pay', 'checkout', 'callback', 'notify', 'return_url',
        'alipay', 'wechat', 'wechatpay', 'wxpay', 'paypal', 'stripe',
        'notify_url', 'callback_url', 'ipn', 'webhook',
        // WooCommerce 特有
        'wc-api', 'wc-ajax', 'wc_order', 'order-pay', 'order-received',
        'add_payment_method', 'add-payment-method', 'payment-method', 'cart',
        // 易支付/码支付/虎皮椒等第三方支付
        'epay', 'payjs', 'payapi', 'payepay', 'hupijiao',
        // OAuth/SSO 回调
        'oauth', 'oauth2', 'oauth2callback', 'sso', 'saml',
        // 表单提交
        'contact', 'feedback', 'subscribe', 'newsletter',
        // 常见API端点（支付/登录相关）
        'api/pay', 'api/order', 'api/callback', 'api/notify',
        'api/login', 'api/auth',
    ];

    /** @var array 敏感输入场景路径关键字 */
    private static $softSkipPaths = [
        'comment', 'comments', 'review', 'reviews',
        'search', 's', 'q', 'keyword',
        'forum', 'post', 'thread', 'reply',
        'edit', 'draft', 'publish',
        'message', 'chat', 'mail',
    ];

    /**
     * 获取当前请求场景（带缓存）
     */
    public static function detect()
    {
        if (self::$scene !== null) {
            return self::$scene;
        }

        $uri    = $_SERVER['REQUEST_URI'] ?? '/';
        $path   = parse_url($uri, PHP_URL_PATH) ?: '/';
        $method = $_SERVER['REQUEST_METHOD'] ?? 'GET';
        $lower  = strtolower($path);

        // 允许通过 config.php 自定义高可信路径
        $customHardSkip = (defined('WAF_TRUSTED_PATHS') && is_array(WAF_TRUSTED_PATHS))
            ? array_map('strtolower', WAF_TRUSTED_PATHS) : [];
        $customSoftSkip = (defined('WAF_SOFTSKIP_PATHS') && is_array(WAF_SOFTSKIP_PATHS))
            ? array_map('strtolower', WAF_SOFTSKIP_PATHS) : [];

        // 精确匹配优先（/login, /login/ 都算，但 /loginabc 不算）
        $isHard = self::matchAny($lower, array_merge(self::$hardSkipPaths, $customHardSkip));
        $isSoft = self::matchAny($lower, array_merge(self::$softSkipPaths, $customSoftSkip));

        // 查询参数兜底：
        //   ?action=login, ?view=checkout 等参数关键字匹配 → hard_skip
        //   ?s=keyword, ?q=keyword, ?search=xxx 等搜索参数 → soft_skip
        if (!$isHard && !$isSoft) {
            $query = strtolower($_SERVER['QUERY_STRING'] ?? '');
            if ($query !== '') {
                // 解析查询参数名
                parse_str($query, $queryParams);
                $paramNames = array_map('strtolower', array_keys($queryParams));
                // 搜索参数名：s/q/search/keyword/kw（短到长，避免误判）
                $searchParams = ['s', 'q', 'search', 'keyword', 'kw', 'query'];
                foreach ($searchParams as $sp) {
                    if (in_array($sp, $paramNames, true)) {
                        $isSoft = true;
                        break;
                    }
                }
                // 仍未命中，再用关键字包含匹配 hard_skip
                if (!$isSoft) {
                    foreach (self::$hardSkipPaths as $kw) {
                        if (strpos($query, $kw) !== false) {
                            $isHard = true;
                            break;
                        }
                    }
                }
            }
        }

        // 高可信场景：
        //   POST/PUT/PATCH → hard_skip（跳过所有特征检测）
        //   GET/HEAD/OPTIONS → soft_skip（仅跳过关键字黑名单检测，保留CSRF/Bot等）
        // 为什么GET也soft_skip？因为登录/支付页面可能带 redirect_to 等参数，
        // 容易被 OpenRedirect/特征检测误判，且这些页面本身没有敏感数据
        if ($isHard) {
            if (in_array($method, ['POST', 'PUT', 'PATCH'])) {
                self::$scene = self::SCENE_HARD_SKIP;
            } else {
                self::$scene = self::SCENE_SOFT_SKIP;
            }
        } elseif ($isSoft) {
            self::$scene = self::SCENE_SOFT_SKIP;
        } else {
            self::$scene = self::SCENE_FULL_CHECK;
        }

        return self::$scene;
    }

    /**
     * 路径匹配：支持子路径出现关键字（/user/login/）、.php 文件名、查询参数搜索
     * 匹配规则：
     *   - /login 精确匹配
     *   - /user/login/ 路径任意一段匹配关键字
     *   - /wp-login.php /wp-comments-post.php 处理 .php 后缀
     *   - 不误匹配：/loginabc 不算（需边界）
     *   - 路径穿越防护：先规范化 .. / // / ./ 等，防止 /login/../wp-admin 绕过
     */
    private static function matchAny($path, $keywords)
    {
        // 去掉 query string，保留 path
        $path = parse_url($path, PHP_URL_PATH) ?: $path;
        $lower = strtolower($path);

        // 路径穿越规范化：防止 /login/../wp-admin 之类绕过
        // 反复处理直到稳定（防止 /a/../../b 多层穿越）
        $prev = '';
        while ($prev !== $lower) {
            $prev = $lower;
            $lower = preg_replace('#(?:^|/)\.(?:/|$)#', '/', $lower);   // /./ → /
            $lower = preg_replace('#(?:^|/)[^/]+/\.\.(?:/|$)#', '/', $lower); // /foo/.. → /
            $lower = preg_replace('#/{2,}#', '/', $lower);               // // → /
        }
        $lower = '/' . ltrim($lower, '/');

        foreach ($keywords as $kw) {
            $kw = trim($kw, '/');
            if ($kw === '') continue;

            // 1. 精确匹配整段路径 /login 或 /login/
            if ($lower === '/' . $kw || $lower === '/' . $kw . '/') {
                return true;
            }
            // 2. 前缀匹配 /login/xxx
            if (strpos($lower, '/' . $kw . '/') === 0) {
                return true;
            }
            // 3. .php 文件名匹配 /wp-login.php /wp-comments-post.php
            //    关键字可能带连字符前缀：comments → wp-comments-post.php
            if (substr($lower, -4) === '.php') {
                $basename = basename($lower);
                // 移除 .php 后缀
                $stem = substr($basename, 0, -4);
                // 按连字符/点拆分 stem
                $parts = preg_split('/[-_.]/', $stem);
                foreach ($parts as $p) {
                    if ($p === $kw) return true;
                }
            }
            // 4. 子路径任意一段匹配 /user/login/xxx
            //    按斜杠拆分路径，检查任意一段是否等于关键字
            $segments = explode('/', trim($lower, '/'));
            foreach ($segments as $seg) {
                if ($seg === $kw) return true;
            }
        }
        return false;
    }

    /** 是否为高可信场景（跳过特征检测） */
    public static function isHardSkip()
    {
        return self::detect() === self::SCENE_HARD_SKIP;
    }

    /**
     * 是否为登录页面路径（无论 GET 还是 POST）
     * 用于攻击评分时记录但不拦截的场景判断
     * 与 isHardSkip() 的区别：isHardSkip 只在 POST 时返回 true，
     * isLoginPagePath 在 GET/POST 都返回 true（GET 登录页也需要记录但容忍）
     */
    public static function isLoginPagePath()
    {
        $uri  = $_SERVER['REQUEST_URI'] ?? '/';
        $path = parse_url($uri, PHP_URL_PATH) ?: '/';
        $lower = strtolower($path);
        // 登录相关关键字（hardSkipPaths 中的登录类子集）
        $loginKeywords = [
            'login', 'signin', 'sign-in', 'sign_up', 'signup', 'sign-up',
            'register', 'registration', 'auth', 'my-account', 'account',
            'lostpassword', 'lost-password', 'resetpassword', 'reset-password',
            'wp-login.php',
        ];
        return self::matchAny($lower, $loginKeywords);
    }

    /** 是否为敏感输入场景（跳过黑名单检测） */
    public static function isSoftSkip()
    {
        return self::detect() === self::SCENE_SOFT_SKIP;
    }

    /** 是否需要跳过特征检测（hard_skip 或 soft_skip） */
    public static function shouldSkipSignature()
    {
        $scene = self::detect();
        return $scene !== self::SCENE_FULL_CHECK;
    }

    /**
     * 调试用：返回当前场景和匹配到的关键字
     */
    public static function debug()
    {
        return [
            'scene'      => self::detect(),
            'uri'        => $_SERVER['REQUEST_URI'] ?? '',
            'method'     => $_SERVER['REQUEST_METHOD'] ?? '',
            'hard_paths' => self::$hardSkipPaths,
            'soft_paths' => self::$softSkipPaths,
        ];
    }
}
