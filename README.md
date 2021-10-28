# proxy-crawler

http://cachefly.cachefly.net/speedtest/?ref=driverlayer.com/web

```python
#%%
os.environ['http_proxy'] = 'http://127.0.0.1:1087'
os.environ['https_proxy'] = 'http://127.0.0.1:1087'
print(os.environ.get('http_proxy'))
print(os.environ.get('https_proxy'))
s = speedtest.Speedtest()
s.get_best_server()
s.download()
s.results
#%%
os.environ['http_proxy'] = 'http://127.0.0.1:1087'
os.environ['https_proxy'] = 'http://127.0.0.1:1087'
print(os.environ.get('http_proxy'))
print(os.environ.get('https_proxy'))
s = speedtest.Speedtest()
s.get_best_server()
s.download()
s.results
```

http://www.ruanyifeng.com/blog/2018/03/systemd-timer.html

爬取代理
逐个写测试 JSON、启动 v2ray、测试速度
按速度排序，取前 5/10 个
然后写正式 JSON
重启 systemctl
