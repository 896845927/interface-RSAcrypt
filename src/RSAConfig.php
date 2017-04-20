<?php
/**
 * Created by PhpStorm.
 * User: yaozhen
 * Date: 2017/4/20
 * Time: 下午11:40
 */

namespace mrmiao\script;

use Composer\Script\Event;

class RSAConfig
{
    public static function postPackageInstall(Event $event)
    {
        $installedPackage = $event->getOperation()->getPackage();
        $path_name = 'rsa_config.php';
        if (!file_exists($path_name)){
            $config = array('private_key_bits' => 1024);
            $res = openssl_pkey_new($config);
            openssl_pkey_export($res, $request_privKey);
            $request_pubKey = openssl_pkey_get_details($res);
            $request_pubKey = $request_pubKey["key"];

            $res = openssl_pkey_new($config);
            openssl_pkey_export($res, $response_privKey);
            $response_pubKey = openssl_pkey_get_details($res);
            $response_pubKey = $response_pubKey["key"];


            $content = <<<EOT
<?php
//配置文件
return [
    'debug'=>true,
    'request_privKey'=>'{$request_privKey}',
    'request_pubKey'=>'{$request_pubKey}',
    'response_privKey'=>'{$response_privKey}',
    'response_pubKey'=>'{$response_pubKey}',
];
EOT;

            file_put_contents($path_name,$content);
        }
    }
}