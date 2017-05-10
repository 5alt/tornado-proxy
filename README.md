# tornado-proxy

tornado-proxy 是基于 tornado 实现的 HTTP/HTTPS 代理服务器。

本程序在 owtf-proxy 的基础上修改而成，整合了 owtf-proxy 和 tornado-proxy 对 HTTPS 的两种不同方式的支持，参考 proxy2 中对请求和响应的拦截与处理方式。

## 特性

* 支持对 HTTPS 请求的透明代理和动态伪造证书拦截流量两种方式
* 高性能
* 自定义对请求和响应的处理

## 依赖

* OpenSSL
* tornado
* pycurl

在 osx 下 pip 安装 pycurl 报编译错误，加上环境变量 `archflags -arch x86_64` 即可。

`sudo env ARCHFLAGS="-arch x86_64" pip install pycurl`

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
