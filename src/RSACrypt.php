<?php

namespace mrmiao\crypt;

class RSACrypt
{
    const rsa_config_path = __DIR__.DIRECTORY_SEPARATOR.'rsa_config.php';
    protected $rsa_config;
    //默认设置返回密文
    protected $response_crypt = 1;

    /**
     * 使用魔术方法统一请求和返回入口,作为前置钩子hook
     * @param $name
     * @param $arguments
     * @return mixed
     * @throws \Exception
     */
    public function __call($name, $arguments){
        if (!file_exists(self::rsa_config_path))
            throw new \Exception('RSA Config Missing');

        $this->rsa_config = include self::rsa_config_path;
        return call_user_func_array([__CLASS__,$name],$arguments);
    }


    //获取请求参数,必须使用param字段
    protected function request(){
        $param = $_REQUEST['param'];
//        $param = request()->param('param');

        //请求开关开启,可以接受明文请求,尝试json解析
        if ($this->rsa_config['debug']){
            $request_param = json_decode($param,true);
        }
        //求布尔值,未开启开关,强制密文;是否通过 json 解析出了$request_param
        $bool = $this->rsa_config['debug'] && isset($request_param) && (boolean)$request_param;

        //解析
        $request_param = $bool ? $request_param : self::request_decrypt($param,$this->rsa_config['request_privKey']);
        if ($request_param === null)
            throw new \Exception('Request Param Abnormal');

        //更新返回是否使用密文
        $this->response_crypt = isset($request_param['hamburger_coke']) ? $request_param['hamburger_coke']:0;

        if (isset($request_param['hamburger_coke']))
            unset($request_param['hamburger_coke']);

        return $request_param;
    }

    //处理返回数字,根据加密请求的参数hamburger_coke来确定返回 密文或明文
    protected function response($response_arr){
        $bool = (boolean)$this->response_crypt==0;
        return $bool ? json_encode($response_arr): self::response_encrypt($response_arr,$this->rsa_config['response_pubKey']);
    }

    //请求私钥解密
    protected function request_decrypt($param,$request_privKey){
        $decrypted = $this->ssl_decrypt(base64_decode($param),'private',$request_privKey);
        return json_decode($decrypted,true);
    }
    //返回公钥加密
    protected function response_encrypt($response_arr,$response_pubKey){
        //公钥加密
        $encrypted = $this->ssl_encrypt(json_encode($response_arr),'public',$response_pubKey);
        return base64_encode($encrypted);
    }

    //分段加密方法
    protected function ssl_encrypt($source,$type,$key){
    //Assumes 1024 bit key and encrypts in chunks.

        $maxlength=117;
        $output='';
        while($source){
            $input= substr($source,0,$maxlength);
            $source=substr($source,$maxlength);
            if($type=='private'){
                $ok= openssl_private_encrypt($input,$encrypted,$key);
            }else{
                $ok= openssl_public_encrypt($input,$encrypted,$key);
            }

            $output.=$encrypted;
        }
        return $output;
    }

    //分段解密方法
    protected function ssl_decrypt($source,$type,$key){
    // The raw PHP decryption functions appear to work
    // on 128 Byte chunks. So this decrypts long text
    // encrypted with ssl_encrypt().

        $maxlength=128;
        $output='';
        while($source){
            $input= substr($source,0,$maxlength);
            $source=substr($source,$maxlength);
            if($type=='private'){
                $ok= openssl_private_decrypt($input,$out,$key);
            }else{
                $ok= openssl_public_decrypt($input,$out,$key);
            }

            $output.=$out;
        }
        return $output;

    }
}