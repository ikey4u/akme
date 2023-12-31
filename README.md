## Introduction

akme is an ACME client which help you issue/renew certificate from certificate
authority, it does only two things

- Issue HTTPS certificate
- Automatically renew HTTPS certificate (in daemonize)

And then you can integrate the certificate into your favorite web server.

## Usage

You must run akme in administrator/root priviledge, and its usage is given as
below

    akme --domain <domain> --ssldir </path/to/ssldir>

`<domain>` is your website domain such as `example.com` without any prefix
like `https` or `http`.

`<path/to/ssldir>` is any existed directory (both `.` and `..` are accepted) you
want to store the generated files which named `<domain>.crt` and `<domain>.key`
respectively.

Assume your `domain` is `exampmle.com` and your `ssldir` is `/stc/akme`, here is
an example configuration in nginx

    server {
        listen 443 ssl;
        server_name example.com;

        ssl_protocols TLSv1 TLSv1.1 TLSv1.2 TLSv1.3;
        ssl_prefer_server_ciphers on;
        ssl_certificate /etc/akme/example.com.crt
        ssl_certificate_key /etc/akme/example.com.key;
    }
