class Cloudhubapi{    
    /**
     * 云之家openapi OAuth签名协议服务器
     */
    private $yzj_openapi_oauth_host = "https://www.yunzhijia.com";  //轻应用开发
    /**
     * 云之家openapi OAuth签名协议的应用ID（开发者应用ID-轻应用开发）
     */
    private $yzj_openapi_oauth_app_id = "10323";
    /**
     * 云之家openapi OAuth签名协议的应用secret（开发者应用密钥-轻应用开发）
     */
    private $yzj_openapi_oauth_app_secret = "xxxxxxxxxxxxxxxx";   


     /**
     * [云之家轻应用接口-openapi oauth签名协议]个人信息
     * @param $data
     * @return mixed
     */
    public function yzj_openapi_oauth_getperson($data){
        //接口url
        $yzj_url = $this->yzj_openapi_oauth_host."/openapi/third/v1/opendata-control/data/getperson";

        //生成Http的Header请求头中的Authorization键值
        $authorization = $this->_yzj_openapi_oauth_authorization($yzj_url,$data);

        //http的头信息
        $headers = array("Content-Type: application/x-www-form-urlencoded;charset=utf-8","Authorization: ".$authorization);

        //调用接口
        $yzj_josn = _kis_http_restfull_curl($yzj_url,"POST",$data,$headers);

        //json转换为对象
        $yzjobj = json_decode($yzj_josn);
        
        //返回
        return $yzjobj;
    }

    /**
     * 云之家openapi oauth签名协议生成http的header中的Authorization键值
     * @param $url
     * @param $post_data
     * @return string
     */
    private function _yzj_openapi_oauth_authorization($url,$post_data){
        $timestamp = time();             //时间戳
        $nonce = time().rand(10,1000);   //随机数
        //签名参数
        $params = array();
        $params["oauth_version"]          = "1.0";
        $params["oauth_signature_method"] = "HMAC-SHA1";
        $params["oauth_timestamp"]        = $timestamp;
        $params["oauth_nonce"]            = $nonce;
        $params["oauth_consumer_key"]     = $this->yzj_openapi_oauth_app_id;       
        
        //把客户端输入参数加入签名参数
        foreach($post_data as $k=>$v){
            $params[$k] = urlencode($v);
        }

        //组合生成签名字符串
        $sigstr = "POST"."&".urlencode($url)."&";
        //对参数按照字母升序做序列化
        $normalized_str = $this->_get_yzj_openapi_oauth_normalized_string($params);
        $sigstr        .= urlencode($normalized_str);

        //密钥
        $key = $this->yzj_openapi_oauth_app_secret."&";

        //生成oauth_signature签名值。这里需要确保PHP版本支持hash_hmac函数
        $signature = urlencode($this->_get_yzj_openapi_oauth_signature($sigstr, $key));

        //生成Http的Header请求头中的Authorization键值
        $authorization = sprintf('OAuth oauth_consumer_key="%s",oauth_signature_method="HMAC-SHA1",oauth_timestamp="%s",oauth_nonce="%s",oauth_version="1.0",oauth_signature="%s"',$this->yzj_openapi_oauth_app_id,$timestamp,$nonce,$signature);

        //返回Authorization值
        return $authorization;
    }

    /**
     * 云之家openapi oauth签名协议参数升序排序
     * @param $params
     * @return string
     */
    private function _get_yzj_openapi_oauth_normalized_string($params)
    {
        //按字母升序排列
        ksort($params);
        $normalized = array();
        foreach($params as $key => $val)
        {
            $normalized[] = $key."=".$val;
        }
        //
        return implode("&", $normalized);
    }

    /**
     * 云之家openapi oauth签名协议HMAC-SHA1加密
     * @param $str
     * @param $key
     * @return string
     */
    private function _get_yzj_openapi_oauth_signature($str, $key)
    {
        $signature = "";
        if (function_exists('hash_hmac')){
            $signature = base64_encode(hash_hmac("sha1", $str, $key, true));
        }
        else{
            $blocksize	= 64;
            $hashfunc	= 'sha1';
            if (strlen($key) > $blocksize)
            {
                $key = pack('H*', $hashfunc($key));
            }
            $key	= str_pad($key,$blocksize,chr(0x00));
            $ipad	= str_repeat(chr(0x36),$blocksize);
            $opad	= str_repeat(chr(0x5c),$blocksize);
            $hmac 	= pack(
                'H*',$hashfunc(
                    ($key^$opad).pack(
                        'H*',$hashfunc(
                            ($key^$ipad).$str
                        )
                    )
                )
            );
            $signature = base64_encode($hmac);
        }
        //
        return $signature;
    }


    /**
    * 通过curl模拟http提交数据（支持POST,GET,PUT,DELETE）
    * @param $URL  //请求资源url
    * @param $type  //请求资源类型（支持POST,GET,PUT,DELETE）
    * @param $data  //参数数据
    * @param $headers //http头信息(数组)
    * @return mixed
    */
    private function _kis_http_restfull_curl($URL,$type,$data,$headers=""){
    //如果$data是字符串
    if(is_string($data)){
        $params = $data;
    }
    else{
        //$data是数组
        $values = array();
        foreach ($data as $key=>$val){
            $values[]="$key=".urlencode($val);
        }
        //
        $params = implode("&",$values);
    }

    //开始curl操作
    $ch = curl_init();
   
    //资源地址
    curl_setopt ($ch, CURLOPT_URL, $URL);
    //https请求不验证证书处理
    if(strpos(strtolower($URL),"https://") !== false)
    {
        //https请求 不验证证书和hosts
        curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, false);
        curl_setopt($ch, CURLOPT_SSL_VERIFYHOST, false);
    }
    //http头文件类型处理
    if($headers == ""){
        curl_setopt ($ch, CURLOPT_HTTPHEADER, false); //CURLOPT_HEADER值为false或零(默认x-www-from-urlencod方式提交数据)
    }
    else {
        curl_setopt ($ch, CURLOPT_HTTPHEADER, $headers);
    }
    curl_setopt ($ch, CURLOPT_RETURNTRANSFER, true);
   
    //请求类型处理
    $type = strtoupper($type); //转换为大写
    if($type == "GET"){
        curl_setopt($ch, CURLOPT_HTTPGET, true);
    }
    elseif($type == "POST"){
        curl_setopt($ch, CURLOPT_POST,true);
        curl_setopt($ch, CURLOPT_POSTFIELDS,$params);
    }
    elseif($type == "PUT"){
        curl_setopt ($ch, CURLOPT_CUSTOMREQUEST, "PUT");
        curl_setopt($ch, CURLOPT_POSTFIELDS,$params);
    }
    elseif($type == "DELETE"){
        curl_setopt ($ch, CURLOPT_CUSTOMREQUEST, "DELETE");
        curl_setopt($ch, CURLOPT_POSTFIELDS,$params);
    }
    //
     $ret_contents = curl_exec($ch); //获得返回值
     curl_close($ch);
     return $ret_contents;
   }
}


//调用Demo(以获取云之家个人信息接口为例)

//输入参数
$post_data["eid"] = "7687143";
$post_data["openId"] = "5775e284e4b0bb1fc15dd513";
//接口调用
$cloudhub = new Cloudhubapi();
$yzj_obj = $cloudhub->yzj_openapi_oauth_getperson($post_data);

print_r($yzj_obj);