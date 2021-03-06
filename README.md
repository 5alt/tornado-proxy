# tornado-proxy

tornado-proxy 是基于 tornado 实现的 HTTP/HTTPS 代理服务器，支持 python2 和 python3。

本程序在 owtf-proxy 的基础上修改而成，整合了 owtf-proxy 和 tornado-proxy 对 HTTPS 的两种不同方式的支持，参考 proxy2 中对请求和响应的拦截与处理方式。

## 特性

* 支持对 HTTPS 请求的透明代理和动态伪造证书拦截流量两种方式
* 高性能
* 自定义对请求和响应的处理
* 可配置此代理服务器的代理服务器

## 依赖

* pyopenssl
* tornado
* pycurl

`pip install -r requirements.txt`

pycurl 安装参考 https://wfuzz.readthedocs.io/en/latest/user/installation.html

mac os 下

```
brew install openssl
brew install curl-openssl
export PATH="/usr/local/opt/curl-openssl/bin:$PATH"
PYCURL_SSL_LIBRARY=openssl LDFLAGS="-L/usr/local/opt/openssl/lib" CPPFLAGS="-I/usr/local/opt/openssl/include" pip install --no-cache-dir pycurl
```

ubuntu 下需先安装 `libssl-dev` 和 `libcurl4-openssl-dev`

## 开启 HTTPS 拦截

拦截 HTTPS 流量需要先生成私钥和CA证书。将生成的CA证书添加到浏览器的信任区域中。

`$ ./setup_https_intercept.sh`

删除产生的证书以及私钥文件即不拦截 HTTPS 流量。

## 自定义功能

在 `ProxyHandler` 中有三个方法可以用来修改或者保存请求和响应信息。

* request_handler: 在代理服务器向web服务器发送请求之前调用
* response_handler: 在代理服务器向客户端返回响应之前调用
* save_handler: 在客户端获取响应之后调用


## 参考资料

https://github.com/tunnelshade/owtf-proxy

https://github.com/senko/tornado-proxy

https://github.com/inaz2/proxy2
