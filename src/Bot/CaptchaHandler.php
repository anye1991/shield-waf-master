<?php
/**
 * 盾甲 WAF 验证码处理模块 (bot/CaptchaHandler.php)
 *
 * 功能：
 *  1. 发起验证挑战 challenge()
 *  2. 验证挑战结果 verify()
 *  3. 支持滑块(slider)、点击(click)、行为验证(behavior)三种类型
 *  4. 简单实现，不依赖真实验证码图片生成
 */
defined('ABSPATH') || exit;

class CaptchaHandler {
    const TYPE_SLIDER   = 'slider';
    const TYPE_CLICK    = 'click';
    const TYPE_BEHAVIOR = 'behavior';

    const CHALLENGE_TTL = 300; // 挑战有效期（秒）

    private static $store_dir = null;

    /**
     * 发起验证挑战
     * @param string $type 验证类型 slider|click|behavior
     * @return array ['type'=>string, 'session_id'=>string, 'html'=>string]
     */
    public static function challenge(string $type = 'slider'): array {
        self::initDir();
        $type       = self::normalizeType($type);
        $session_id = self::generateSessionId();
        $challenge  = self::buildChallenge($type);

        // 存储会话（含服务端答案）
        $record = [
            'session_id' => $session_id,
            'type'       => $type,
            'answer'     => $challenge['answer'],
            'created_at' => time(),
            'attempts'   => 0,
            'verified'   => false,
            'ip'         => self::getClientIp(),
        ];
        self::saveSession($session_id, $record);

        $html = self::renderHtml($type, $session_id, $challenge);

        return [
            'type'       => $type,
            'session_id' => $session_id,
            'html'       => $html,
        ];
    }

    /**
     * 验证挑战结果
     * @param string $token 客户端提交的 token，格式 session_id:payload(base64)
     * @param string $type  验证类型
     * @return bool
     */
    public static function verify(string $token, string $type): bool {
        self::initDir();
        $type = self::normalizeType($type);

        // token 格式：session_id:payload
        $parts = explode(':', $token, 2);
        if (count($parts) !== 2) return false;
        list($session_id, $payload) = $parts;

        $record = self::loadSession($session_id);
        if ($record === null) return false;

        // 类型必须匹配
        if (($record['type'] ?? '') !== $type) return false;

        // 过期检查
        if (time() - $record['created_at'] > self::CHALLENGE_TTL) {
            self::deleteSession($session_id);
            return false;
        }

        // 尝试次数限制
        $record['attempts'] = ($record['attempts'] ?? 0) + 1;
        if ($record['attempts'] > 5) {
            self::deleteSession($session_id);
            return false;
        }

        // 校验答案
        $ok = self::checkAnswer($type, $record['answer'] ?? [], $payload);

        if ($ok) {
            $record['verified'] = true;
            self::saveSession($session_id, $record);
            return true;
        }

        self::saveSession($session_id, $record);
        return false;
    }

    /**
     * 检查会话是否已通过验证（用于放行二次请求）
     */
    public static function isVerified(string $session_id): bool {
        $record = self::loadSession($session_id);
        if ($record === null) return false;
        if (!empty($record['verified'])) {
            // 验证成功后，在原始 TTL 内有效
            if (time() - $record['created_at'] <= self::CHALLENGE_TTL) {
                return true;
            }
        }
        return false;
    }

    // ====================== 内部实现 ======================

    private static function normalizeType(string $type): string {
        $valid = [self::TYPE_SLIDER, self::TYPE_CLICK, self::TYPE_BEHAVIOR];
        return in_array($type, $valid, true) ? $type : self::TYPE_SLIDER;
    }

    private static function generateSessionId(): string {
        return bin2hex(random_bytes(16));
    }

    /**
     * 构建挑战题目与答案
     */
    private static function buildChallenge(string $type): array {
        switch ($type) {
            case self::TYPE_SLIDER:
                // 滑块需对齐红色标记位置（百分比），容差 ±5%
                $target = random_int(30, 75);
                return [
                    'answer' => ['target' => $target, 'tolerance' => 5],
                    'data'   => ['target' => $target],
                ];
            case self::TYPE_CLICK:
                // 点击验证：按顺序点击指定字符
                $pool = ['A', 'B', 'C', 'D', 'E', 'F', '7', '9'];
                shuffle($pool);
                $sequence = implode('', array_slice($pool, 0, 3));
                return [
                    'answer' => ['sequence' => $sequence],
                    'data'   => ['sequence' => $sequence],
                ];
            case self::TYPE_BEHAVIOR:
            default:
                // 行为验证：nonce + 期望耗时 + 轨迹点数
                $nonce        = bin2hex(random_bytes(8));
                $min_duration = random_int(800, 1500); // 期望耗时（毫秒）
                return [
                    'answer' => ['nonce' => $nonce, 'min_duration' => $min_duration],
                    'data'   => ['nonce' => $nonce],
                ];
        }
    }

    /**
     * 校验答案
     */
    private static function checkAnswer(string $type, array $answer, string $payload): bool {
        $data = json_decode(base64_decode($payload), true);
        if (!is_array($data)) return false;

        switch ($type) {
            case self::TYPE_SLIDER:
                $pos    = (int)($data['position'] ?? -1);
                $target = (int)($answer['target'] ?? 0);
                $tol    = (int)($answer['tolerance'] ?? 5);
                return abs($pos - $target) <= $tol;
            case self::TYPE_CLICK:
                $seq = (string)($data['sequence'] ?? '');
                return hash_equals((string)($answer['sequence'] ?? ''), $seq);
            case self::TYPE_BEHAVIOR:
                $nonce    = (string)($data['nonce'] ?? '');
                $duration = (int)($data['duration'] ?? 0);
                $points   = (int)($data['points'] ?? 0);
                if (!hash_equals((string)($answer['nonce'] ?? ''), $nonce)) return false;
                if ($duration < (int)($answer['min_duration'] ?? 800)) return false;
                if ($points < 10) return false;
                return true;
        }
        return false;
    }

    /**
     * 渲染挑战 HTML（简易实现，纯前端交互）
     */
    private static function renderHtml(string $type, string $session_id, array $challenge): string {
        $sid_json = json_encode($session_id);
        $head = '<!DOCTYPE html><html lang="zh-CN"><head><meta charset="utf-8">'
              . '<meta name="viewport" content="width=device-width,initial-scale=1">'
              . '<title>安全验证</title><style>'
              . 'body{margin:0;background:#f5f7fa;font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,sans-serif;display:flex;align-items:center;justify-content:center;min-height:100vh}'
              . '.box{background:#fff;border-radius:12px;padding:30px;box-shadow:0 4px 20px rgba(0,0,0,.08);width:360px;max-width:90vw}'
              . 'h3{margin:0 0 16px;color:#222;font-size:18px}.tip{color:#888;font-size:13px;margin-bottom:16px}'
              . '.slider-track{position:relative;height:40px;background:#eee;border-radius:20px;overflow:hidden;margin:10px 0}'
              . '.slider-fill{position:absolute;left:0;top:0;height:100%;background:linear-gradient(90deg,#4a90e2,#357abd);width:0}'
              . '.slider-marker{position:absolute;top:-2px;height:44px;width:3px;background:#e74c3c;border-radius:2px}'
              . '.slider-btn{position:absolute;top:2px;left:0;width:36px;height:36px;background:#fff;border-radius:50%;box-shadow:0 2px 6px rgba(0,0,0,.2);cursor:pointer;user-select:none;display:flex;align-items:center;justify-content:center;font-size:16px}'
              . '.click-area{display:grid;grid-template-columns:repeat(2,1fr);gap:10px;margin:10px 0}'
              . '.click-cell{height:50px;background:#eef;border-radius:8px;display:flex;align-items:center;justify-content:center;font-size:20px;font-weight:bold;color:#357abd;cursor:pointer;user-select:none}.click-cell:hover{background:#e0e8f5}.click-cell.done{background:#357abd;color:#fff}'
              . 'button{width:100%;padding:10px;background:#357abd;color:#fff;border:none;border-radius:8px;font-size:14px;cursor:pointer;margin-top:12px}button:disabled{background:#aaa}'
              . '</style></head><body><div class="box">';

        if ($type === self::TYPE_SLIDER) {
            $target = (int)($challenge['data']['target'] ?? 50);
            return $head
                . '<h3>滑块验证</h3><div class="tip">请拖动滑块对齐红色标记完成验证</div>'
                . '<div class="slider-track" id="track">'
                . '<div class="slider-marker" id="marker" style="left:' . $target . '%"></div>'
                . '<div class="slider-fill" id="fill"></div>'
                . '<div class="slider-btn" id="btn">→</div></div>'
                . '<button id="submit" disabled>提交验证</button>'
                . '<script>'
                . 'var SID=' . $sid_json . ';'
                . 'var btn=document.getElementById("btn"),track=document.getElementById("track"),fill=document.getElementById("fill"),sub=document.getElementById("submit");'
                . 'var dragging=false,startX=0,btnLeft=0;'
                . 'btn.addEventListener("mousedown",function(e){dragging=true;startX=e.clientX;btnLeft=btn.offsetLeft;e.preventDefault();});'
                . 'document.addEventListener("mousemove",function(e){if(!dragging)return;var x=btnLeft+(e.clientX-startX);var max=track.offsetWidth-btn.offsetWidth;x=Math.max(0,Math.min(max,x));btn.style.left=x+"px";fill.style.width=(x+btn.offsetWidth)+"px";});'
                . 'document.addEventListener("mouseup",function(){if(!dragging)return;dragging=false;var pct=Math.round((btn.offsetLeft/(track.offsetWidth-btn.offsetWidth))*100);sub.disabled=false;sub.dataset.pct=pct;});'
                . 'sub.addEventListener("click",function(){var p=btoa(JSON.stringify({position:parseInt(sub.dataset.pct||0,10)}));var token=SID+":"+p;location.href="?captcha_verify=1&type=slider&token="+encodeURIComponent(token);});'
                . '</script></div></body></html>';
        }

        if ($type === self::TYPE_CLICK) {
            $seq    = $challenge['data']['sequence'] ?? 'ABC';
            $chars  = str_split($seq);
            $distractors = ['X', 'Y', 'Z', '1', '2', '3'];
            $cells  = array_merge($chars, array_slice($distractors, 0, 4));
            shuffle($cells);
            $cells_html = '';
            foreach ($cells as $c) {
                $ce = htmlspecialchars($c, ENT_QUOTES);
                $cells_html .= '<div class="click-cell" data-c="' . $ce . '">' . $ce . '</div>';
            }
            return $head
                . '<h3>点击验证</h3><div class="tip">请依次点击字符: <b>' . htmlspecialchars($seq) . '</b></div>'
                . '<div class="click-area" id="area">' . $cells_html . '</div>'
                . '<button id="submit" disabled>提交验证</button>'
                . '<script>'
                . 'var SID=' . $sid_json . ',target=' . json_encode($seq) . ',clicked="",sub=document.getElementById("submit");'
                . 'document.querySelectorAll(".click-cell").forEach(function(c){c.addEventListener("click",function(){clicked+=this.dataset.c;this.classList.add("done");if(clicked.length>=target.length)sub.disabled=false;});});'
                . 'sub.addEventListener("click",function(){var p=btoa(JSON.stringify({sequence:clicked}));var token=SID+":"+p;location.href="?captcha_verify=1&type=click&token="+encodeURIComponent(token);});'
                . '</script></div></body></html>';
        }

        // behavior
        $nonce = $challenge['data']['nonce'] ?? '';
        return $head
            . '<h3>行为验证</h3><div class="tip">请在此区域随意移动鼠标完成验证</div>'
            . '<div id="area" style="height:120px;background:#eef;border-radius:8px;display:flex;align-items:center;justify-content:center;color:#888">在此移动鼠标</div>'
            . '<button id="submit" disabled>提交验证</button>'
            . '<input type="hidden" id="nonce" value="' . htmlspecialchars($nonce, ENT_QUOTES) . '">'
            . '<script>'
            . 'var SID=' . $sid_json . ';'
            . 'var area=document.getElementById("area"),sub=document.getElementById("submit"),start=0,points=0;'
            . 'area.addEventListener("mouseenter",function(){start=Date.now();});'
            . 'area.addEventListener("mousemove",function(){points++;if(points>15)sub.disabled=false;});'
            . 'sub.addEventListener("click",function(){var dur=Date.now()-start;var p=btoa(JSON.stringify({nonce:document.getElementById("nonce").value,duration:dur,points:points}));var token=SID+":"+p;location.href="?captcha_verify=1&type=behavior&token="+encodeURIComponent(token);});'
            . '</script></div></body></html>';
    }

    // ====================== 会话存储 ======================

    private static function initDir() {
        if (self::$store_dir !== null) return;
        $base = defined('WAF_LOG_PATH') ? WAF_LOG_PATH : (sys_get_temp_dir() . '/shield_waf_');
        $dir  = $base . '/captcha/';
        if (!is_dir($dir)) @mkdir($dir, 0700, true);
        self::$store_dir = $dir;
    }

    private static function sessionFile(string $session_id): string {
        $safe = preg_replace('/[^a-f0-9]/', '', $session_id);
        return self::$store_dir . 'sess_' . $safe . '.json';
    }

    private static function saveSession(string $session_id, array $record) {
        @file_put_contents(self::sessionFile($session_id), json_encode($record), LOCK_EX);
    }

    private static function loadSession(string $session_id): ?array {
        $file = self::sessionFile($session_id);
        if (!is_file($file)) return null;
        $raw  = @file_get_contents($file);
        if (!$raw) return null;
        $data = json_decode($raw, true);
        return is_array($data) ? $data : null;
    }

    private static function deleteSession(string $session_id) {
        $file = self::sessionFile($session_id);
        if (is_file($file)) @unlink($file);
    }

    private static function getClientIp(): string {
        if (function_exists('waf_get_real_ip')) return waf_get_real_ip();
        return $_SERVER['REMOTE_ADDR'] ?? '0.0.0.0';
    }
}
