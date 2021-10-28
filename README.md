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
